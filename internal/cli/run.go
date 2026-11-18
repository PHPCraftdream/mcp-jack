package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/admin"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/bridge"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gateway"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/keys"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/nonce"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/serverkey"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/stdio"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
)

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
	var verified *transport.VerifiedStatusError
	var enrollAuth *keys.EnrollUnauthorizedError
	switch {
	case errors.As(err, &verified):
		message = verified.Error()
	case errors.As(err, &enrollAuth):
		// Must precede the errRemote fallback: a 401 from enroll carries the
		// invite-specific diagnostic even though it unwraps to errRemote.
		message = enrollAuth.Error()
	case errors.Is(err, command.ErrConfig):
		message = command.ErrConfig.Error()
	case errors.Is(err, command.ErrProtocol):
		message = command.ErrProtocol.Error()
	case errors.Is(err, command.ErrRemote):
		message = command.ErrRemote.Error()
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		message = "operation cancelled or deadline exceeded"
	}
	_, _ = fmt.Fprintln(streams.Err, "jack: "+message)
	return 1
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
		return command.ErrConfig
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
	return command.ErrConfig
}

// runKeygen handles "jack keygen server|user --secret FILE --public FILE".
func runKeygen(args []string) error {
	if len(args) < 3 {
		return command.ErrConfig
	}
	f, err := command.Flags("keygen", args[2:], "secret", "public")
	if err != nil {
		return err
	}
	return keys.Keygen(args[1], f["secret"], f["public"])
}

// runBootstrap handles "jack bootstrap --state FILE --invite-file FILE".
func runBootstrap(args []string) error {
	f, err := command.Flags("bootstrap", args[1:], "state", "invite-file")
	if err != nil {
		return err
	}
	return keys.Bootstrap(f["state"], f["invite-file"])
}

// runServerKeyCommand dispatches the server-key-* subcommands.
func runServerKeyCommand(_ context.Context, args []string, streams IO) error {
	switch args[0] {
	case "server-key-init-unused":
		f, err := command.Flags(args[0], args[1:], "config", "confirm-unused-endpoint", "confirm-unused-aud")
		if err != nil {
			return err
		}
		return serverkey.ServerKeyInitializeUnused(f["config"], f["confirm-unused-endpoint"], f["confirm-unused-aud"])
	case "server-key-announce":
		f, err := command.Flags(args[0], args[1:], "config", "reference", "kid")
		if err != nil {
			return err
		}
		return serverkey.ServerKeyAnnounce(f["config"], f["reference"], f["kid"], streams.Out)
	default:
		f, err := command.Flags(args[0], args[1:], "config")
		if err != nil {
			return err
		}
		return serverkey.ServerKeyStatus(f["config"], streams.Out)
	}
}

// runNonceCommand dispatches the nonce-* subcommands.
func runNonceCommand(_ context.Context, args []string, streams IO) error {
	switch args[0] {
	case "nonce-init-unused":
		f, err := command.Flags(args[0], args[1:], "config", "confirm-unused-deployment")
		if err != nil {
			return err
		}
		return nonce.NonceInitializeUnused(f["config"], f["confirm-unused-deployment"])
	case "nonce-reconcile-terminal":
		f, err := command.Flags(args[0], args[1:], "config", "expected-hash", "receipt-file", "confirm-no-redelivery")
		if err != nil {
			return err
		}
		return nonce.NonceReconcileTerminal(f["config"], f["expected-hash"], f["receipt-file"], f["confirm-no-redelivery"])
	default:
		f, err := command.Flags(args[0], args[1:], "config")
		if err != nil {
			return err
		}
		return nonce.NonceInspect(f["config"], streams.Out)
	}
}

// runInviteCommand dispatches the invite-* subcommands.
func runInviteCommand(ctx context.Context, args []string, streams IO) error {
	if args[0] == "invite-create" {
		return admin.InviteCreate(ctx, args[1:], streams.Out)
	}
	names := []string{"config"}
	if args[0] == "invite-revoke" {
		names = append(names, "invite-id")
	}
	f, err := command.Flags(args[0], args[1:], names...)
	if err != nil {
		return err
	}
	return admin.InviteCommand(ctx, args[0], f["config"], f["invite-id"], streams.Out)
}

// runUserCommand dispatches the user-* subcommands.
func runUserCommand(ctx context.Context, args []string, streams IO) error {
	if args[0] == "user-create" {
		return admin.UserCreate(ctx, args[1:], streams.Out)
	}
	if args[0] == "user-set-admin" {
		f, err := command.Flags(args[0], args[1:], "config", "kid", "admin")
		if err != nil {
			return err
		}
		return admin.UserSetAdmin(ctx, f["config"], f["kid"], f["admin"], streams.Out)
	}
	names := []string{"config"}
	if args[0] != "user-list" {
		names = append(names, "kid")
	}
	f, err := command.Flags(args[0], args[1:], names...)
	if err != nil {
		return err
	}
	return admin.UserCommand(ctx, args[0], f["config"], f["kid"], streams.Out)
}

// runEnroll handles "jack enroll --config FILE --invite-file FILE --name NAME".
func runEnroll(ctx context.Context, args []string) error {
	f, err := command.Flags("enroll", args[1:], "config", "invite-file", "name")
	if err != nil {
		return err
	}
	return keys.Enroll(ctx, f["config"], f["invite-file"], f["name"])
}

// runGatewayOrBridge handles "jack gateway" and "jack bridge".
func runGatewayOrBridge(ctx context.Context, args []string, streams IO) error {
	f, err := command.Flags(args[0], args[1:], "config")
	if err != nil {
		return err
	}
	if args[0] == "gateway" {
		return gateway.Run(ctx, f["config"], streams.Err)
	}
	return bridge.Run(ctx, f["config"], stdio.IO{In: streams.In, Out: streams.Out, Err: streams.Err})
}
