// Command client is the official-SDK modern e2e client fixture.
// Exactly one result JSON object on stdout; diagnostics on stderr.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"time"
)

const (
	sdkName = "github.com/modelcontextprotocol/go-sdk"

	// modernProtocol is the negotiated version for every session (direct and
	// jack alike); direct mode defaults to it via Connect(ctx, tr, nil).
	modernProtocol = "2026-07-28"

	// Driver-observed deterministic echo value (tools/mcp-e2e-modern/run.mjs ECHO_VALUE).
	echoValue = "modern-e2e-deterministic"
)

// sdkVer resolves from the build's module graph; CI builds from the lock, so
// it resolves to the pinned version. "unknown" is reported otherwise.
var sdkVer = "unknown"

func sdkVersionFromBuild() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == sdkName && d.Version != "" {
				return d.Version
			}
		}
	}
	return ""
}

const usage = "usage: client --scenario <1..8> --server <go|ts> (--direct --url <address> | --bridge-bin <path> --bridge-config <path> --era <modern|auto>) [--config <path>]"

type config struct {
	scenario     int
	server       string
	direct       bool
	url          string
	urlSeen      int
	bridgeBin    string
	bridgeConfig string
	era          string
	probeConfig  string
}

func parseFlags() (*config, []string) {
	cfg := &config{}
	scenario := flag.Int("scenario", 0, "scenario number 1..8")
	server := flag.String("server", "", "server SDK identity label (go|ts)")
	direct := flag.Bool("direct", false, "direct modern HTTP mode")
	url := urlFlag{} // counts --url occurrences
	flag.Var(&url, "url", "direct mode server address")
	bridgeBin := flag.String("bridge-bin", "", "jack binary (jack mode)")
	bridgeConfig := flag.String("bridge-config", "", "driver-written bridge config path (jack mode)")
	era := flag.String("era", "", "bridge era: modern|auto (jack mode)")
	probeConfig := flag.String("config", "", "scenario 5 direct-mode config path")
	flag.Parse()
	var errs []string
	if *scenario < 1 || *scenario > 8 {
		errs = append(errs, "--scenario must be 1..8")
	}
	cfg.scenario = *scenario
	cfg.server = *server
	if cfg.server != "go" && cfg.server != "ts" {
		errs = append(errs, "--server must be go or ts")
	}
	cfg.direct = *direct
	cfg.url = url.value
	cfg.urlSeen = url.count
	if *bridgeBin != "" {
		cfg.bridgeBin = *bridgeBin
	}
	if *bridgeConfig != "" {
		cfg.bridgeConfig = *bridgeConfig
	}
	if *era != "" {
		cfg.era = *era
	}
	if *probeConfig != "" {
		cfg.probeConfig = *probeConfig
	}
	return cfg, errs
}

// validate enforces the CONTRACT.md mode exclusivity rules.
func (c *config) validate() []string {
	var errs []string
	jack := c.bridgeBin != "" || c.bridgeConfig != "" || c.era != ""
	if c.direct == jack {
		errs = append(errs, "exactly one of --direct or jack mode (--bridge-bin --bridge-config --era) is required")
	}
	if c.direct {
		if c.url == "" {
			errs = append(errs, "--url is required in direct mode")
		}
		if c.urlSeen != 1 {
			errs = append(errs, "exactly one --url flag must appear in direct mode")
		}
		if c.bridgeBin != "" || c.bridgeConfig != "" || c.era != "" {
			errs = append(errs, "--bridge-* flags are not allowed in direct mode")
		}
		if c.probeConfig != "" && c.scenario != 5 {
			errs = append(errs, "--config is only allowed for scenario 5 direct mode")
		}
	} else {
		if c.bridgeBin == "" || c.bridgeConfig == "" || c.era == "" {
			errs = append(errs, "--bridge-bin, --bridge-config and --era are required in jack mode")
		}
		if c.era != "" && c.era != "modern" && c.era != "auto" {
			errs = append(errs, "--era must be modern or auto")
		}
		if c.url != "" {
			errs = append(errs, "--url is not allowed in jack mode")
		}
	}
	return errs
}

// urlFlag records how many times --url appeared and its last value.
type urlFlag struct {
	value string
	count int
}

func (f *urlFlag) String() string { return f.value }

func (f *urlFlag) Set(s string) error {
	f.count++
	f.value = s
	return nil
}

type elapsed struct{ start time.Time }

func (e elapsed) ms() int64 { return time.Since(e.start).Milliseconds() }

func main() {
	cfg, errs := parseFlags()
	errs = append(errs, cfg.validate()...)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "%s\n", usage)
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "client: %s\n", e)
		}
		os.Exit(2)
	}
	clock := elapsed{start: time.Now()}
	if v := sdkVersionFromBuild(); v != "" {
		sdkVer = v
	}
	res := run(cfg, clock, os.Stdin)
	data, err := marshalResult(*res)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client: marshal result: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

const unsupportedAuthEvidence = "github.com/modelcontextprotocol/go-sdk v1.8.0 provides no Jack auth hook: " +
	"mcp.StreamableClientTransport (mcp/streamable.go:1966) exposes only Endpoint, HTTPClient and OAuthHandler " +
	"(auth.OAuthHandler); there is no API to set signed Jack-Auth or Jack-Accept: s1 headers, and no Jack signing " +
	"implementation exists within the pinned module set (go.mod allows only the go-sdk module and the standard library)"

// run executes the scenario and assembles the result record. The pointer
// return lets the deferred cleanup mutate the record the caller marshals.
func run(cfg *config, clock elapsed, stdin io.Reader) *result {
	res := &result{
		Scenario:    cfg.scenario,
		SDK:         sdkID{Name: sdkName, Version: sdkVer},
		Bridge:      noBridge(),
		Progress:    []progressObs{},
		RequestMeta: nil,
	}
	res.Timings.StartedMs = 0
	rec := newRecorder(clock.ms)
	var (
		s        *session
		connectE error
		bridge   *bridgeProc
	)
	defer func() {
		if s != nil {
			s.close()
		} else if bridge != nil {
			bridge.stop()
		}
		if bridge != nil {
			res.Bridge = bridge.info()
		}
		prog, firstMs := rec.snapshot()
		res.Progress = prog
		res.Timings.FirstEventMs = firstMs
	}()

	var out runOut
	ctx := context.Background()
	switch cfg.scenario {
	case 5:
		res.Outcome = "unsupported"
		ev := unsupportedAuthEvidence
		res.CapabilityEvidence = &ev
		return res
	case 1, 2, 3, 8:
		if cfg.direct {
			s, connectE = connectDirect(ctx, cfg.url, rec)
		} else {
			bridge, connectE = startBridge(cfg.bridgeBin, cfg.bridgeConfig)
			if connectE == nil {
				s, connectE = connectBridge(ctx, bridge, rec)
			}
		}
	default: // 4, 6, 7
		if cfg.direct {
			s, connectE = connectDirect(ctx, cfg.url, rec)
		} else {
			bridge, connectE = startBridge(cfg.bridgeBin, cfg.bridgeConfig)
			if connectE == nil {
				s, connectE = connectBridge(ctx, bridge, rec)
			}
		}
	}
	if connectE != nil {
		res.Outcome = "fail"
		res.SDKError = strPtr(fmt.Sprintf("connect: %v", connectE))
		if cfg.scenario == 3 {
			// The driver requires non-null request_meta on every result path,
			// including connect failure; build it without a session.
			res.RequestMeta = requestMetaFor(modernProtocol)
		}
		return res
	}

	now := clock.ms
	switch cfg.scenario {
	case 1:
		out = scenario1(ctx, s, now)
	case 3:
		out = scenario3(ctx, s, now)
	case 4:
		out = scenario4(ctx, s, now)
	case 6:
		out = scenario6(ctx, s, scanLines(stdin), now)
	case 7:
		out = scenario7(ctx, s, now, cfg.server)
	default:
		out = scenario8(ctx, s, now)
	}
	res.Outcome = out.outcome
	res.ToolResult = out.toolResult
	res.SDKError = strPtr(out.sdkErr)
	if out.capabilityEvidence != "" {
		res.CapabilityEvidence = &out.capabilityEvidence
	}
	res.RequestMeta = out.meta
	res.Timings.CompletedMs = out.completedMs
	res.Timings.CancelledMs = out.cancelledMs
	return res
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
