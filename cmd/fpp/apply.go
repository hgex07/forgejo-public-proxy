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
	"strings"
	"syscall"

	"fpp/internal/config"
	"fpp/internal/credential"
	"fpp/internal/deploy"
	"fpp/internal/manifest"
	"fpp/internal/site"
)

func apply(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfig, "config file")
	state := fs.String("state", defaultStateDir(), "state directory")
	auto := fs.Bool("auto", false, "timer mode: refuse to publish a repo that was never published (I8)")
	noDeploy := fs.Bool("no-deploy", false, "stop after staging and the output lint")
	verbose := fs.Bool("v", false, "list everything instead of a summary")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "apply: unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return exitUsage
	}
	cfg, code := loadForRun(*cfgPath, stderr)
	if cfg == nil {
		return code
	}
	return runApply(cfg, *state, applyOpts{auto: *auto, noDeploy: *noDeploy, verbose: *verbose}, stdout, stderr)
}

// unpublish rebuilds the site without one repo.
func unpublish(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("unpublish", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfig, "config file")
	state := fs.String("state", defaultStateDir(), "state directory")
	noDeploy := fs.Bool("no-deploy", false, "stop after staging and the output lint")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: fpp unpublish [flags] <owner/repo>  (the public slug)")
		return exitUsage
	}
	slug := fs.Arg(0)
	cfg, code := loadForRun(*cfgPath, stderr)
	if cfg == nil {
		return code
	}
	kept := cfg.Publish.Repos[:0:0]
	found := false
	for i, r := range cfg.Publish.Repos {
		if strings.EqualFold(cfg.Effective(i).Slug, slug) {
			found = true
			continue
		}
		kept = append(kept, r)
	}
	if !found {
		fmt.Fprintf(stderr, "unpublish: %q is not a published slug in %s\n", slug, *cfgPath)
		return exitUsage
	}
	cfg.Publish.Repos = kept
	code = runApply(cfg, *state, applyOpts{noDeploy: *noDeploy}, stdout, stderr)
	base := strings.TrimRight(cfg.Site.BaseURL, "/")
	fmt.Fprintf(stdout, "\nNext: remove %s from %s (or the next apply publishes it again), purge the\n"+
		"CDN cache if any, rotate anything it exposed, and confirm it is gone: %s/%s must show\n"+
		"the build above and %s/%s/ must return 404 (docs/RUNBOOK.md).\n",
		slug, *cfgPath, base, site.BuildFile, base, slug)
	return code
}

type applyOpts struct {
	auto, noDeploy, verbose bool
}

func loadForRun(path string, stderr io.Writer) (*config.Config, int) {
	cfg, warnings, err := config.Load(path)
	for _, w := range warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return nil, exitInvalid
	}
	return cfg, exitOK
}

// runApply is plan → gates → I8 → render → output lint → deploy. Every
// failure stops it before anything is published (I7); the published
// manifest only changes after a successful deploy.
func runApply(cfg *config.Config, state string, o applyOpts, stdout, stderr io.Writer) int {
	state, err := filepath.Abs(state)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := os.MkdirAll(state, 0o700); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitInvalid
	}
	// One apply at a time per state directory (timer vs. a manual run).
	lock, err := os.OpenFile(filepath.Join(state, ".apply.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitInvalid
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		fmt.Fprintln(stderr, "apply: another apply is running on this state directory; nothing was published")
		return exitInvalid
	}
	fail := func(format string, args ...any) int {
		fmt.Fprintf(stderr, "apply: "+format+"; nothing was published\n", args...)
		return exitInvalid
	}
	if !o.noDeploy && !cfg.HasDeploy() {
		return fail("the config has no deploy section; run with -no-deploy and serve %s yourself",
			filepath.Join(state, "staging", "site"))
	}

	p, err := prepare(ctx, cfg, state, stdout, stderr)
	if err != nil {
		return fail("%v", err)
	}
	old, err := manifest.Read(publishedManifest(state))
	if err != nil {
		return fail("%v", err)
	}
	diff := manifest.Compare(old, manifest.FromSet(p.set))
	printExposure(stdout, p.set, o.verbose)
	printDiff(stdout, old, diff, o.verbose)
	if printGates(stdout, p.gates, o.verbose) {
		return fail("BLOCKED by the gates")
	}
	if o.auto {
		var added []string
		for _, r := range diff.Repos {
			if r.New {
				added = append(added, r.Slug)
			}
		}
		if len(added) > 0 {
			return fail("-auto refuses to publish new repos (I8): %s; run `fpp apply` by hand after reviewing `fpp plan`",
				strings.Join(added, ", "))
		}
	}
	out := filepath.Join(state, "staging", "site")
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return fail("%v", err)
	}
	fmt.Fprintln(stdout)
	probs, err := stage(ctx, cfg, p, state, out, stdout)
	if err != nil {
		return fail("%v", err)
	}
	if len(probs) > 0 {
		printProblems(stdout, probs)
		return fail("output lint failed")
	}
	if o.noDeploy {
		fmt.Fprintf(stdout, "staged and verified in %s; not deployed (-no-deploy)\n", out)
		return exitOK
	}
	digest, err := deploy.Digest(out)
	if err != nil {
		return fail("%v", err)
	}
	build, err := site.ReadBuildID(out)
	if err != nil {
		return fail("%v", err)
	}
	digestFile := filepath.Join(state, "published", "site.digest")
	if prev, err := os.ReadFile(digestFile); err == nil && strings.TrimSpace(string(prev)) == digest && old != nil && diff.Empty() {
		fmt.Fprintf(stdout, "site unchanged since the last deploy; nothing to upload (live build should be %s)\n", build)
		return exitOK
	}
	if err := push(ctx, cfg, state, out, stdout); err != nil {
		return fail("%v", err)
	}
	// Recorded only after a complete upload: the next plan diffs against it
	// and -auto treats its repos as already published.
	if err := os.MkdirAll(filepath.Dir(publishedManifest(state)), 0o700); err != nil {
		fmt.Fprintf(stderr, "apply: deployed, but recording the manifest failed: %v\n", err)
		return exitInvalid
	}
	if err := manifest.Write(publishedManifest(state), manifest.FromSet(p.set)); err != nil {
		fmt.Fprintf(stderr, "apply: deployed, but recording the manifest failed: %v\n", err)
		return exitInvalid
	}
	if err := os.WriteFile(digestFile, []byte(digest+"\n"), 0o600); err != nil {
		fmt.Fprintf(stderr, "apply: deployed, but recording the site digest failed: %v\n", err)
		return exitInvalid
	}
	fmt.Fprintf(stdout, "deployed to %s; the host activates it after validating the upload\n", cfg.Deploy.Target)
	fmt.Fprintf(stdout, "build %s: the upload is live once %s/%s shows it (the builder can't check: the\n"+
		"host may reject an upload, and later unchanged runs skip it). See docs/RUNBOOK.md.\n",
		build, strings.TrimRight(cfg.Site.BaseURL, "/"), site.BuildFile)
	return exitOK
}

// push uploads the staged site with the deploy key from the credentials
// directory.
func push(ctx context.Context, cfg *config.Config, state, site string, stdout io.Writer) error {
	key, err := credential.Path(cfg.Deploy.SSHKey.Credential)
	if err != nil {
		return err
	}
	home := filepath.Join(state, "deploy-home")
	if err := os.RemoveAll(home); err != nil {
		return err
	}
	if err := os.Mkdir(home, 0o700); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "deploying to %s (port %d)\n", cfg.Deploy.Target, cfg.DeployPort())
	return deploy.Push(ctx, deploy.Options{Target: cfg.Deploy.Target, Port: cfg.DeployPort(), KeyFile: key,
		KnownHosts: cfg.Deploy.KnownHosts, Home: home}, site, stdout)
}
