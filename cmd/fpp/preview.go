// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"fpp/internal/config"
	"fpp/internal/site"
)

func preview(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("preview", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfig, "config file")
	state := fs.String("state", defaultStateDir(), "state directory (git cache, published manifest)")
	out := fs.String("out", "", "output directory (default <state>/preview); replaced on every build")
	addr := fs.String("addr", "127.0.0.1:8080", "listen address (loopback only)")
	siteDir := fs.String("site", "", "serve an already built site instead of building")
	buildOnly := fs.Bool("build-only", false, "build the site and exit without serving")
	ignoreGates := fs.Bool("ignore-gates", false, "build and serve even if the gates or the output lint fail (local inspection only)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "preview: unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return exitUsage
	}
	if err := site.CheckLoopback(*addr); err != nil && !*buildOnly {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dir := *siteDir
	if dir == "" {
		var err error
		if *state, err = filepath.Abs(*state); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitUsage
		}
		if *out == "" {
			*out = filepath.Join(*state, "preview")
		}
		cfg, warnings, err := config.Load(*cfgPath)
		for _, w := range warnings {
			fmt.Fprintf(stderr, "warning: %s\n", w)
		}
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitInvalid
		}
		if code := buildPreview(ctx, cfg, *state, *out, *ignoreGates, stdout, stderr); code != exitOK {
			return code
		}
		dir = *out
	}
	if *buildOnly {
		return exitOK
	}
	if err := serve(ctx, dir, *addr, stdout); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitInvalid
	}
	return exitOK
}

// buildPreview runs the pipeline up to the output lint. Gate or lint
// failures stop it unless ignore is set.
func buildPreview(ctx context.Context, cfg *config.Config, state, out string, ignore bool, stdout, stderr io.Writer) int {
	p, err := prepare(ctx, cfg, state, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitInvalid
	}
	if printGates(stdout, p.gates, false) {
		if !ignore {
			fmt.Fprintln(stderr, "preview: blocked by the gates (-ignore-gates to build anyway, locally)")
			return exitInvalid
		}
		fmt.Fprintln(stderr, "warning: building despite blocking gate findings (-ignore-gates)")
	}
	probs, err := stage(ctx, cfg, p, state, out, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitInvalid
	}
	if len(probs) > 0 {
		printProblems(stdout, probs)
		if !ignore {
			fmt.Fprintln(stderr, "preview: output lint failed (-ignore-gates to serve anyway, locally)")
			return exitInvalid
		}
	}
	return exitOK
}

// clearOutput removes out only if it is a previous fpp build.
func clearOutput(out string) error {
	if _, err := os.Lstat(out); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if fi, err := os.Lstat(filepath.Join(out, site.MarkerFile)); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("%s exists and is not an fpp build (no %s); refusing to replace it", out, site.MarkerFile)
	}
	return os.RemoveAll(out)
}

func serve(ctx context.Context, dir, addr string, stdout io.Writer) error {
	h, err := site.Handler(dir)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: site.LoopbackOnly(h), ReadHeaderTimeout: 10 * time.Second}
	fmt.Fprintf(stdout, "serving %s on http://%s/ (Ctrl-C to stop)\n", dir, ln.Addr())
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
