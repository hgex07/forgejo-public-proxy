// SPDX-License-Identifier: AGPL-3.0-or-later

// Command fpp builds the static public mirror of selected Forgejo repos.
// See README.md and docs/SETUP.md for the pipeline and the commands.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"fpp/internal/config"
)

const defaultConfig = "/etc/fpp/config.yaml"

// Exit codes.
const (
	exitOK      = 0
	exitInvalid = 1 // config or gate failure
	exitUsage   = 2
)

func main() {
	// Everything fpp writes (git cache, manifests, staging) is private.
	syscall.Umask(0o077)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	stdout, stderr = termSafe(stdout), termSafe(stderr)
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch cmd, rest := args[0], args[1:]; cmd {
	case "check-config":
		return checkConfig(rest, stdout, stderr)
	case "plan":
		return plan(rest, stdout, stderr)
	case "preview":
		return preview(rest, stdout, stderr)
	case "apply":
		return apply(rest, stdout, stderr)
	case "unpublish":
		return unpublish(rest, stdout, stderr)
	case "caddy-site":
		return caddySite(rest, stdout, stderr)
	case "check-contract":
		return checkContract(rest, stdout, stderr)
	case "-h", "-help", "--help", "help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "fpp: unknown command %q\n", cmd)
		usage(stderr)
		return exitUsage
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: fpp <command> [flags]

commands:
  check-config   strictly validate the config (no network access)
  plan           access checks + fetch + policy + gates; print the
                 exposure report, the diff against the published
                 manifest and the gate findings (exit 1 if blocked)
  apply          plan + render + output lint + deploy; fails closed.
                 -auto refuses new repos; -no-deploy stops after the lint
  preview        plan + render + lint into a local directory and serve
                 it on 127.0.0.1 with the production header contract
  unpublish      apply without one repo (emergency removal)
  caddy-site     print the Caddy site block implementing the header contract
  check-contract check a running server against the header contract

Run "fpp <command> -h" for command flags.
`)
}

func checkConfig(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check-config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", defaultConfig, "config file")
	show := fs.Bool("print", false, "print the effective per-repo exposure policy")
	strict := fs.Bool("strict", false, "treat warnings as errors")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "check-config: unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return exitUsage
	}
	cfg, warnings, err := config.Load(*path)
	for _, w := range warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	if err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			fmt.Fprintf(stderr, "error: %s\n", line)
		}
		return exitInvalid
	}
	if *show {
		printEffective(stdout, cfg)
	}
	if *strict && len(warnings) > 0 {
		fmt.Fprintf(stderr, "%s: %d warning(s) with -strict\n", *path, len(warnings))
		return exitInvalid
	}
	fmt.Fprintf(stdout, "%s: OK (%d repos, %d warnings)\n", *path, len(cfg.Publish.Repos), len(warnings))
	return exitOK
}

func printEffective(w io.Writer, cfg *config.Config) {
	for i := range cfg.Publish.Repos {
		e := cfg.Effective(i)
		var refs []string
		for _, b := range e.Branches {
			if b.As != "" {
				refs = append(refs, b.Name+"→"+b.As)
			} else {
				refs = append(refs, b.Name)
			}
		}
		tags := "none"
		if len(e.TagInclude) > 0 {
			tags = fmt.Sprintf("%s (latest %d)", strings.Join(e.TagInclude, ","), e.TagLatest)
		}
		fmt.Fprintf(w, "%s → /%s/\n", e.Source, e.Slug)
		fmt.Fprintf(w, "  branches:  %s\n", strings.Join(refs, ", "))
		fmt.Fprintf(w, "  tags:      %s\n", tags)
		fmt.Fprintf(w, "  history:   last %d commits\n", e.MaxCommits)
		fmt.Fprintf(w, "  diffs=%t releases=%t assets=%t prereleases=%t archives=%t\n",
			e.Diffs, e.Releases, e.Assets, e.Prereleases, e.Archives)
		fmt.Fprintf(w, "  authors=%s dates=%s\n", e.Authors, e.Dates)
		fmt.Fprintf(w, "  exclude:   %s\n", strings.Join(e.Exclude, " "))
	}
}
