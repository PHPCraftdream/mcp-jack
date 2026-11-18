package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/stdio"
)

// ProcessIO prepares owned, interruptible stdio only for the bridge command.
// Bridge pipes must be exclusively used by this process after preparation.
func ProcessIO(args []string) (IO, error) {
	if len(args) != 0 && args[0] == "bridge" {
		sio, err := stdio.PrepareProcessIO(os.Stdin, os.Stdout)
		if err != nil {
			return IO{}, err
		}
		return IO{In: sio.In, Out: sio.Out, Err: sio.Err}, nil
	}
	return IO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}, nil
}

// RunProcess is the shared executable and child-test entry into Run.
func RunProcess(ctx context.Context, args []string) int {
	streams, err := ProcessIO(args)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "jack: interruptible bridge stdio unavailable")
		return 1
	}
	if len(args) != 0 && args[0] == "bridge" {
		defer streams.In.Close()
		defer streams.Out.Close()
	}
	return Run(ctx, args, streams)
}
