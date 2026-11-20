// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"fpp/internal/config"
	"fpp/internal/manifest"
	"fpp/internal/policy"
)

// defaultStateDir follows systemd's StateDirectory= when set.
func defaultStateDir() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return strings.Split(d, ":")[0]
	}
	return "/var/lib/fpp"
}

// publishedManifest is where `fpp apply` records what is live.
func publishedManifest(state string) string {
	return filepath.Join(state, "published", "manifest.json")
}

func plan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfig, "config file")
	state := fs.String("state", defaultStateDir(), "state directory (git cache, published manifest)")
	out := fs.String("manifest-out", "", "also write the planned manifest to this file")
	verbose := fs.Bool("v", false, "list every path and skipped item instead of a summary")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "plan: unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return exitUsage
	}
	if !filepath.IsAbs(*state) {
		abs, err := filepath.Abs(*state)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitUsage
		}
		*state = abs
	}
	cfg, warnings, err := config.Load(*cfgPath)
	for _, w := range warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitInvalid
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	p, err := prepare(ctx, cfg, *state, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitInvalid
	}
	cur := manifest.FromSet(p.set)
	old, err := manifest.Read(publishedManifest(*state))
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitInvalid
	}
	printExposure(stdout, p.set, *verbose)
	printDiff(stdout, old, manifest.Compare(old, cur), *verbose)
	blocked := printGates(stdout, p.gates, *verbose)
	if *out != "" {
		if err := manifest.Write(*out, cur); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitInvalid
		}
		fmt.Fprintf(stdout, "\nmanifest written to %s\n", *out)
	}
	if blocked {
		fmt.Fprintln(stderr, "plan: publishing would be BLOCKED by the gates")
		return exitInvalid
	}
	return exitOK
}

const summaryLimit = 20

func printExposure(w io.Writer, set *policy.Set, verbose bool) {
	fmt.Fprintln(w, "\n== Exposure")
	for _, r := range set.Repos {
		fmt.Fprintf(w, "%s → /%s/\n", r.Source, r.Slug)
		if r.Meta.Description != "" {
			fmt.Fprintf(w, "  description: %s\n", r.Meta.Description)
		}
		for _, ref := range r.Refs {
			var bytes int64
			for _, f := range ref.Files {
				if f.Size > 0 {
					bytes += f.Size
				}
			}
			name := ref.Public
			if ref.Name != ref.Public {
				name = fmt.Sprintf("%s (%s)", ref.Public, ref.Name)
			}
			fmt.Fprintf(w, "  %-6s %s @ %.10s: %d files (%s), %d commits\n",
				ref.Kind, name, ref.Commit, len(ref.Files), humanBytes(bytes), len(ref.Window))
			if verbose {
				for _, f := range ref.Files {
					fmt.Fprintf(w, "           %s %s (%d)\n", f.Kind, f.Path, f.Size)
				}
			}
		}
		if len(r.Releases) > 0 {
			var tags []string
			for _, rel := range r.Releases {
				tags = append(tags, rel.Tag)
			}
			fmt.Fprintf(w, "  releases: %s\n", strings.Join(tags, ", "))
		}
		hidden, unknown := 0, 0
		for _, c := range r.Commits {
			hidden += c.HiddenChanges
			if !c.ChangesKnown {
				unknown++
			}
		}
		fmt.Fprintf(w, "  commits: %d published", len(r.Commits))
		if unknown > 0 {
			fmt.Fprintf(w, ", %d without a file list (parent outside the window)", unknown)
		}
		if hidden > 0 {
			fmt.Fprintf(w, ", %d changed paths hidden by excludes", hidden)
		}
		fmt.Fprintln(w)
		printSkips(w, r.Skipped, verbose)
	}
}

func printSkips(w io.Writer, skips []policy.Skip, verbose bool) {
	if len(skips) == 0 {
		return
	}
	byReason := map[string][]policy.Skip{}
	var reasons []string
	for _, s := range skips {
		if byReason[s.Reason] == nil {
			reasons = append(reasons, s.Reason)
		}
		byReason[s.Reason] = append(byReason[s.Reason], s)
	}
	sort.Strings(reasons)
	fmt.Fprintln(w, "  not published:")
	for _, reason := range reasons {
		items := byReason[reason]
		fmt.Fprintf(w, "    %s (%d)\n", reason, len(items))
		for i, s := range items {
			if !verbose && i == summaryLimit {
				fmt.Fprintf(w, "      … %d more (-v to list all)\n", len(items)-i)
				break
			}
			switch {
			case s.Ref != "" && s.Path != "":
				fmt.Fprintf(w, "      %s: %s\n", s.Ref, s.Path)
			case s.Path != "":
				fmt.Fprintf(w, "      %s\n", s.Path)
			case s.Ref != "":
				fmt.Fprintf(w, "      %s\n", s.Ref)
			}
		}
	}
}

func printDiff(w io.Writer, old *manifest.Manifest, d manifest.Diff, verbose bool) {
	if old == nil {
		fmt.Fprintln(w, "\n== Changes (nothing published yet)")
	} else {
		fmt.Fprintln(w, "\n== Changes vs the published manifest")
	}
	if d.Empty() {
		fmt.Fprintln(w, "no changes")
		return
	}
	for _, r := range d.Repos {
		switch {
		case r.New:
			fmt.Fprintf(w, "+ %s  NEW: first publish needs a manual `fpp apply` (I8)\n", r.Slug)
		case r.Removed:
			fmt.Fprintf(w, "- %s  unpublished\n", r.Slug)
		default:
			fmt.Fprintf(w, "~ %s\n", r.Slug)
		}
		list(w, "+ ref", r.RefsAdded, verbose)
		list(w, "- ref", r.RefsRemoved, verbose)
		list(w, "~ ref moved", r.RefsMoved, verbose)
		list(w, "+ becomes public", r.PathsAdded, verbose)
		list(w, "~ content changes", r.PathsChanged, verbose)
		list(w, "- no longer public", r.PathsRemoved, verbose)
		if r.CommitsAdded > 0 {
			fmt.Fprintf(w, "    + %d commits\n", r.CommitsAdded)
		}
	}
}

func list(w io.Writer, label string, items []string, verbose bool) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "    %s (%d)\n", label, len(items))
	for i, it := range items {
		if !verbose && i == summaryLimit {
			fmt.Fprintf(w, "        … %d more (-v to list all)\n", len(items)-i)
			return
		}
		fmt.Fprintf(w, "        %s\n", it)
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
