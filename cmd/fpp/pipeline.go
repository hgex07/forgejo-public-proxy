// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"fpp/internal/config"
	"fpp/internal/credential"
	"fpp/internal/forgejo"
	"fpp/internal/gates"
	"fpp/internal/lint"
	"fpp/internal/policy"
	"fpp/internal/site"
)

// prepared is the outcome of discover → fetch → policy → gates.
type prepared struct {
	set     *policy.Set // redacted by the gates
	gates   *gates.Report
	matcher *gates.Matcher
}

// prepare runs discover → fetch → policy → gates. The token never leaves
// this function except inside the matcher (to find it in output).
func prepare(ctx context.Context, cfg *config.Config, state string, stdout, stderr io.Writer) (*prepared, error) {
	token, err := credential.Token(cfg.Forgejo.Token.Credential)
	if err != nil {
		return nil, err
	}
	api, err := forgejo.New(cfg.Forgejo.APIURL, cfg.Forgejo.User, token)
	if err != nil {
		return nil, err
	}
	baseline, err := gates.LoadBaseline(cfg.Gates.SecretScan.Baseline)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		return nil, err
	}
	b := &policy.Builder{Config: cfg, API: api, StateDir: state}
	d, err := b.Discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("access check failed, aborting: %w", err)
	}
	fmt.Fprintf(stdout, "access checks: OK (%d canaries hidden via API and git; push denied on %d repos; bot sees %d repos)\n",
		len(cfg.Forgejo.CanaryRepos), len(cfg.Publish.Repos), len(d.Visible))
	for _, w := range d.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	set, err := b.Build(ctx)
	if err != nil {
		return nil, err
	}
	rep, err := gates.Run(ctx, set, gates.Options{Config: cfg, Token: token, Baseline: baseline})
	if err != nil {
		return nil, err
	}
	m, err := gates.NewMatcher(cfg, token)
	if err != nil {
		return nil, err
	}
	return &prepared{set: set, gates: rep, matcher: m}, nil
}

// stage renders the site into out (replacing a previous fpp build there,
// never anything else) and runs the output lint over it.
func stage(ctx context.Context, cfg *config.Config, p *prepared, state, out string, stdout io.Writer) ([]lint.Problem, error) {
	if err := clearOutput(out); err != nil {
		return nil, err
	}
	start := time.Now()
	res, err := site.Generate(ctx, site.Options{Config: cfg, Set: p.set, Out: out,
		CloneWork: filepath.Join(state, "clone")})
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(stdout, "site: %d pages, %d files, %s in %s (%s)\n",
		res.Pages, res.Files, humanBytes(res.Bytes), out, time.Since(start).Round(time.Millisecond))
	for _, n := range res.Notes {
		fmt.Fprintf(stdout, "  note: %s\n", n)
	}
	work := filepath.Join(state, "lint")
	if err := os.MkdirAll(work, 0o700); err != nil {
		return nil, err
	}
	l := cfg.EffectiveLimits()
	start = time.Now()
	probs, err := lint.Site(ctx, lint.Options{Dir: out, Matcher: p.matcher, Written: res.Written, Set: p.set,
		MaxBytes: l.MaxSiteBytes, MaxFileBytes: l.RawMaxBytes, Work: work})
	if err != nil {
		return nil, err
	}
	if len(probs) == 0 {
		fmt.Fprintf(stdout, "output lint: OK (%d files, %s)\n", len(res.Written), time.Since(start).Round(time.Millisecond))
	}
	return probs, nil
}

// printGates prints the gate report and reports whether it blocks.
func printGates(w io.Writer, rep *gates.Report, verbose bool) bool {
	scan := "secret scan OFF"
	if rep.SecretScan {
		scan = "secret scan on"
	}
	fmt.Fprintf(w, "\n== Gates (%s; %d files, %s scanned; %d email addresses redacted)\n",
		scan, rep.Blobs, humanBytes(rep.Bytes), rep.Redacted)
	shown := map[gates.Action]int{}
	for _, f := range rep.Findings {
		shown[f.Action]++
		if !verbose && shown[f.Action] > summaryLimit {
			continue
		}
		label := "BLOCK"
		if f.Action == gates.Warn {
			label = "warn "
		}
		fmt.Fprintf(w, "%s %s  %s  %s  %s", label, f.Repo, f.Rule, f.Where, f.Excerpt)
		if f.Fingerprint != "" {
			fmt.Fprintf(w, "  [fingerprint %s]", f.Fingerprint)
		}
		if f.Baselined != "" {
			fmt.Fprintf(w, "  (baseline: %s)", f.Baselined)
		}
		fmt.Fprintln(w)
	}
	for _, a := range []gates.Action{gates.Block, gates.Warn} {
		if !verbose && shown[a] > summaryLimit {
			fmt.Fprintf(w, "… %d more %s findings (-v to list all)\n", shown[a]-summaryLimit, a)
		}
	}
	warned := shown[gates.Warn]
	blocked := shown[gates.Block]
	if blocked > 0 {
		fmt.Fprintf(w, "result: BLOCKED (%d findings). Fix the content, exclude the path, or (secret-scan false\n"+
			"positives only) add the fingerprint with a reason to gates.secret_scan.baseline.\n", blocked)
		return true
	}
	fmt.Fprintf(w, "result: OK (%d warnings)\n", warned)
	return false
}

func printProblems(w io.Writer, probs []lint.Problem) {
	fmt.Fprintf(w, "output lint: FAILED (%d problems)\n", len(probs))
	for _, p := range probs {
		fmt.Fprintf(w, "  %s\n", p)
	}
}
