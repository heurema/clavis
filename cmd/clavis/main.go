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
	code := cli.RunWithIO(ctx, os.Args, cli.IO{
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
	})
	stop()
	os.Exit(code)
}
