package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/PHPCraftdream/mcp-jack/internal/cli"
)

func main() {
	signal.Ignore(syscall.SIGPIPE)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.RunProcess(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
