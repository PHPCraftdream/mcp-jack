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
jack nonce-reconcile-terminal --config FILE --expected-hash HASH --receipt-file FILE --confirm-no-redelivery INTENT_ID
jack server-key-init-unused --config FILE --confirm-unused-endpoint URL --confirm-unused-aud AUD
jack server-key-status --config FILE
jack server-key-announce --config FILE --reference HANDLE --kid KID
jack user-set-admin --config FILE --kid KID --admin true|false
jack user-create --config FILE --public FILE --name NAME --admin true|false [--not-before TS] [--not-after TS]
jack user-list --config FILE
jack user-get --config FILE --kid KID
jack user-revoke --config FILE --kid KID
jack invite-create --config FILE --invite-file FILE --admin true|false [--ttl-seconds N] [--key-ttl-seconds N]
jack invite-list --config FILE
jack invite-revoke --config FILE --invite-id ID

nonce-init-unused: only for a deployment that has never accepted requests.
Do not use it to recover lost nonce history or to migrate volatile state.
nonce-inspect does not clear dirty/unsafe and does not permit the server to start.
nonce-reconcile-terminal only turns an exact receipt into a no-redelivery tombstone; dirty/unsafe stay.
server-key-init-unused: only for a binding that never used a server rotation store; not a recovery or reset.
server-key-status works offline without signer seeds, does not clear dirty/unsafe and does not permit serving.
server-key-announce needs the store owner stopped; stdout contains only the public record after the ACK.
An error after publication does not roll the commit back: do not retry automatically, check status and evidence.
invite-create stores the code only in a new private file; stdout contains only invite_id and expires_at.
After an invite-create error the reservation file is kept: do not delete it to retry automatically.
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
	var enrollAuth *enrollUnauthorizedError
	switch {
	case errors.As(err, &verified):
		message = verified.Error()
	case errors.As(err, &enrollAuth):
		// Must precede the errRemote fallback: a 401 from enroll carries the
		// invite-specific diagnostic even though it unwraps to errRemote.
		message = enrollAuth.Error()
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

// run resolves the top-level command and dispatches to a per-command handler.
// Usage output, unknown-command rejection, and error values are unchanged.
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
		return runKeygen(args)
	case "bootstrap":
		return runBootstrap(args)
	case "server-key-init-unused", "server-key-announce", "server-key-status":
		return runServerKeyCommand(ctx, args, streams)
	case "nonce-init-unused", "nonce-reconcile-terminal", "nonce-inspect":
		return runNonceCommand(ctx, args, streams)
	case "invite-create", "invite-list", "invite-revoke":
		return runInviteCommand(ctx, args, streams)
	case "user-create", "user-list", "user-get", "user-revoke", "user-set-admin":
		return runUserCommand(ctx, args, streams)
	case "enroll":
		return runEnroll(ctx, args)
	case "gateway", "bridge":
		return runGatewayOrBridge(ctx, args, streams)
	}
	return errConfig
}

// runKeygen handles "jack keygen server|user --secret FILE --public FILE".
func runKeygen(args []string) error {
	if len(args) < 3 {
		return errConfig
	}
	f, err := flags("keygen", args[2:], "secret", "public")
	if err != nil {
		return err
	}
	return keygen(args[1], f["secret"], f["public"])
}

// runBootstrap handles "jack bootstrap --state FILE --invite-file FILE".
func runBootstrap(args []string) error {
	f, err := flags("bootstrap", args[1:], "state", "invite-file")
	if err != nil {
		return err
	}
	return bootstrap(f["state"], f["invite-file"])
}

// runServerKeyCommand dispatches the server-key-* subcommands.
func runServerKeyCommand(_ context.Context, args []string, streams IO) error {
	switch args[0] {
	case "server-key-init-unused":
		f, err := flags(args[0], args[1:], "config", "confirm-unused-endpoint", "confirm-unused-aud")
		if err != nil {
			return err
		}
		return serverKeyInitializeUnused(f["config"], f["confirm-unused-endpoint"], f["confirm-unused-aud"])
	case "server-key-announce":
		f, err := flags(args[0], args[1:], "config", "reference", "kid")
		if err != nil {
			return err
		}
		return serverKeyAnnounce(f["config"], f["reference"], f["kid"], streams.Out)
	default:
		f, err := flags(args[0], args[1:], "config")
		if err != nil {
			return err
		}
		return serverKeyStatus(f["config"], streams.Out)
	}
}

// runNonceCommand dispatches the nonce-* subcommands.
func runNonceCommand(_ context.Context, args []string, streams IO) error {
	switch args[0] {
	case "nonce-init-unused":
		f, err := flags(args[0], args[1:], "config", "confirm-unused-deployment")
		if err != nil {
			return err
		}
		return nonceInitializeUnused(f["config"], f["confirm-unused-deployment"])
	case "nonce-reconcile-terminal":
		f, err := flags(args[0], args[1:], "config", "expected-hash", "receipt-file", "confirm-no-redelivery")
		if err != nil {
			return err
		}
		return nonceReconcileTerminal(f["config"], f["expected-hash"], f["receipt-file"], f["confirm-no-redelivery"])
	default:
		f, err := flags(args[0], args[1:], "config")
		if err != nil {
			return err
		}
		return nonceInspect(f["config"], streams.Out)
	}
}

// runInviteCommand dispatches the invite-* subcommands.
func runInviteCommand(ctx context.Context, args []string, streams IO) error {
	if args[0] == "invite-create" {
		return inviteCreate(ctx, args[1:], streams.Out)
	}
	names := []string{"config"}
	if args[0] == "invite-revoke" {
		names = append(names, "invite-id")
	}
	f, err := flags(args[0], args[1:], names...)
	if err != nil {
		return err
	}
	return inviteCommand(ctx, args[0], f["config"], f["invite-id"], streams.Out)
}

// runUserCommand dispatches the user-* subcommands.
func runUserCommand(ctx context.Context, args []string, streams IO) error {
	if args[0] == "user-create" {
		return userCreate(ctx, args[1:], streams.Out)
	}
	if args[0] == "user-set-admin" {
		f, err := flags(args[0], args[1:], "config", "kid", "admin")
		if err != nil {
			return err
		}
		return userSetAdmin(ctx, f["config"], f["kid"], f["admin"], streams.Out)
	}
	names := []string{"config"}
	if args[0] != "user-list" {
		names = append(names, "kid")
	}
	f, err := flags(args[0], args[1:], names...)
	if err != nil {
		return err
	}
	return userCommand(ctx, args[0], f["config"], f["kid"], streams.Out)
}

// runEnroll handles "jack enroll --config FILE --invite-file FILE --name NAME".
func runEnroll(ctx context.Context, args []string) error {
	f, err := flags("enroll", args[1:], "config", "invite-file", "name")
	if err != nil {
		return err
	}
	return enroll(ctx, f["config"], f["invite-file"], f["name"])
}

// runGatewayOrBridge handles "jack gateway" and "jack bridge".
func runGatewayOrBridge(ctx context.Context, args []string, streams IO) error {
	f, err := flags(args[0], args[1:], "config")
	if err != nil {
		return err
	}
	if args[0] == "gateway" {
		return gateway(ctx, f["config"], streams.Err)
	}
	return bridge(ctx, f["config"], streams)
}

func callDuration(ms int) (time.Duration, error) {
	if ms < 100 || ms > 30000 {
		return 0, errConfig
	}
	return time.Duration(ms) * time.Millisecond, nil
}
