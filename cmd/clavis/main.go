package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/heurema/clavis/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args, os.Stdout)
	stop()
	os.Exit(code)
}
