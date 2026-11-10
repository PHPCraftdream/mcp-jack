package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"time"
)

const maxBody = 1 << 20
const protocolVersion = "2025-11-25"

const usage = `jack keygen server|user --secret FILE --public FILE
jack bootstrap --state FILE --invite-file FILE
jack enroll --config FILE --invite-file FILE --name NAME
jack gateway --config FILE
jack bridge --config FILE
jack nonce-init-unused --config FILE --confirm-unused-deployment ID
jack nonce-inspect --config FILE

nonce-init-unused: только deployment, никогда не принимавший запросы.
Не использовать для восстановления утраченной истории nonce или миграции volatile state.
nonce-inspect не снимает dirty/unsafe и не разрешает запуск сервера.
`

var errConfig = errors.New("invalid configuration or private storage")
var errProtocol = errors.New("unsupported or invalid protocol message")
var errRemote = errors.New("remote call failed; no retry performed")

type verifiedStatusError struct {
	status int
}

func (e *verifiedStatusError) Error() string {
	return "authenticated HTTP " + strconv.Itoa(e.status) + "; no retry performed"
}

func (e *verifiedStatusError) Unwrap() error { return errRemote }

// IO transfers ownership of In and Out to Run for bridge operation. Close must
// unblock concurrent Read/Write; use pipes or files, not arbitrary blocking wrappers.
type IO struct {
	In  io.ReadCloser
	Out io.WriteCloser
	Err io.Writer
}

// Run returns an exit status. Diagnostics never include supplied values or SDK errors.
func Run(ctx context.Context, args []string, streams IO) int {
	if streams.Err == nil {
		streams.Err = io.Discard
	}
	err := run(ctx, args, streams)
	if err == nil {
		return 0
	}
	message := "operation failed"
	var verified *verifiedStatusError
	switch {
	case errors.As(err, &verified):
		message = verified.Error()
	case errors.Is(err, errConfig):
		message = errConfig.Error()
	case errors.Is(err, errProtocol):
		message = errProtocol.Error()
	case errors.Is(err, errRemote):
		message = errRemote.Error()
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		message = "operation cancelled or deadline exceeded"
	}
	_, _ = fmt.Fprintln(streams.Err, "jack: "+message)
	return 1
}

func flags(name string, args []string, names ...string) (map[string]string, error) {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	values := make(map[string]*string)
	for _, name := range names {
		values[name] = f.String(name, "", "")
	}
	if f.Parse(args) != nil || f.NArg() != 0 {
		return nil, errConfig
	}
	out := make(map[string]string)
	for name, value := range values {
		if *value == "" {
			return nil, errConfig
		}
		out[name] = *value
	}
	return out, nil
}

func run(ctx context.Context, args []string, streams IO) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help") {
		_, err := io.WriteString(streams.Err, usage)
		return err
	}
	if len(args) < 2 {
		return errConfig
	}
	switch args[0] {
	case "keygen":
		if len(args) < 3 {
			return errConfig
		}
		f, err := flags("keygen", args[2:], "secret", "public")
		if err != nil {
			return err
		}
		return keygen(args[1], f["secret"], f["public"])
	case "bootstrap":
		f, err := flags("bootstrap", args[1:], "state", "invite-file")
		if err != nil {
			return err
		}
		return bootstrap(f["state"], f["invite-file"])
	case "nonce-init-unused":
		f, err := flags(args[0], args[1:], "config", "confirm-unused-deployment")
		if err != nil {
			return err
		}
		return nonceInitializeUnused(f["config"], f["confirm-unused-deployment"])
	case "nonce-inspect":
		f, err := flags(args[0], args[1:], "config")
		if err != nil {
			return err
		}
		return nonceInspect(f["config"], streams.Out)
	case "enroll":
		f, err := flags("enroll", args[1:], "config", "invite-file", "name")
		if err != nil {
			return err
		}
		return enroll(ctx, f["config"], f["invite-file"], f["name"])
	case "gateway", "bridge":
		f, err := flags(args[0], args[1:], "config")
		if err != nil {
			return err
		}
		if args[0] == "gateway" {
			return gateway(ctx, f["config"])
		}
		return bridge(ctx, f["config"], streams)
	}
	return errConfig
}

func callDuration(ms int) (time.Duration, error) {
	if ms < 100 || ms > 30000 {
		return 0, errConfig
	}
	return time.Duration(ms) * time.Millisecond, nil
}
