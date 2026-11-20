// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"fpp/internal/site"
)

// caddySite prints the Caddy site block implementing the header contract.
func caddySite(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("caddy-site", flag.ContinueOnError)
	fs.SetOutput(stderr)
	host := fs.String("host", "", "public hostname (e.g. code.example.com)")
	root := fs.String("root", "", "directory Caddy serves (the live release, e.g. /srv/sites/code/current)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return exitUsage
	}
	out, err := site.CaddySite(*host, *root)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	fmt.Fprint(stdout, out)
	return exitOK
}

// checkContract verifies a running server against the header contract.
func checkContract(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check-contract", flag.ContinueOnError)
	fs.SetOutput(stderr)
	base := fs.String("base", "", "server URL, e.g. http://127.0.0.1:8080")
	host := fs.String("host", "", "Host header to send (the site's hostname)")
	dir := fs.String("site", "", "a local copy of the site being served (samples are picked from it)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *base == "" || *dir == "" {
		fmt.Fprintln(stderr, "usage: fpp check-contract -base URL [-host H] -site DIR")
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	probs, err := site.CheckContract(ctx, *base, *host, *dir)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitInvalid
	}
	for _, p := range probs {
		fmt.Fprintln(stdout, p)
	}
	if len(probs) > 0 {
		fmt.Fprintf(stdout, "header contract: FAILED (%d problems)\n", len(probs))
		return exitInvalid
	}
	fmt.Fprintln(stdout, "header contract: OK")
	return exitOK
}
