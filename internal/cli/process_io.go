package cli

import (
	"context"
	"fmt"
	"os"
)

// ProcessIO prepares owned, interruptible stdio only for the bridge command.
// Bridge pipes must be exclusively used by this process after preparation.
func ProcessIO(args []string) (IO, error) {
	if len(args) != 0 && args[0] == "bridge" {
		return prepareProcessIO(os.Stdin, os.Stdout)
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
