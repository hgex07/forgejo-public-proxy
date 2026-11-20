// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fpp/internal/manifest"
)

func (e *e2e) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	if strings.Contains(out.String()+errb.String(), "tok-e2e") {
		t.Fatal("token in output")
	}
	return code, out.String(), errb.String()
}

func TestApplyStagesAndFailsClosed(t *testing.T) {
	e := newE2E(t)
	staged := filepath.Join(e.state, "staging", "site", "me", "proj", "index.html")

	// I8: timer mode never publishes a repo for the first time.
	code, _, errs := e.run(t, "apply", "-config", e.cfg, "-state", e.state, "-auto", "-no-deploy")
	if code != exitInvalid || !strings.Contains(errs, "refuses to publish new repos (I8): me/proj") {
		t.Fatalf("auto first publish: exit %d %s", code, errs)
	}
	if _, err := os.Stat(staged); err == nil {
		t.Fatal("staged despite I8")
	}

	// By hand it stages and verifies.
	code, out, errs := e.run(t, "apply", "-config", e.cfg, "-state", e.state, "-no-deploy")
	if code != exitOK || !strings.Contains(out, "output lint: OK") || !strings.Contains(out, "result: OK") {
		t.Fatalf("manual apply: exit %d\n%s\n%s", code, out, errs)
	}
	if _, err := os.Stat(staged); err != nil {
		t.Fatal(err)
	}

	// Once published, -auto accepts the known repo.
	cfgSet := mustPlanManifest(t, e)
	if err := os.MkdirAll(filepath.Dir(publishedManifest(e.state)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(cfgSet, publishedManifest(e.state)); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := e.run(t, "apply", "-config", e.cfg, "-state", e.state, "-auto", "-no-deploy"); code != exitOK {
		t.Fatalf("auto on a published repo: exit %d\n%s\n%s", code, out, errs)
	}

	// Without -no-deploy it stops at the missing deploy channel and does
	// not record anything as published.
	before, _ := os.ReadFile(publishedManifest(e.state))
	code, _, errs = e.run(t, "apply", "-config", e.cfg, "-state", e.state)
	if code != exitInvalid || !strings.Contains(errs, "nothing was published") {
		t.Fatalf("deploy: exit %d %s", code, errs)
	}
	if after, _ := os.ReadFile(publishedManifest(e.state)); !bytes.Equal(before, after) {
		t.Fatal("published manifest changed without a deploy")
	}
}

func mustPlanManifest(t *testing.T, e *e2e) string {
	t.Helper()
	p := filepath.Join(e.dir, "planned.json")
	if code, _, errs := e.run(t, "plan", "-config", e.cfg, "-state", e.state, "-manifest-out", p); code != exitOK {
		t.Fatalf("plan: %s", errs)
	}
	if m, err := manifest.Read(p); err != nil || m == nil {
		t.Fatalf("manifest: %v", err)
	}
	return p
}

func TestGateBlocksEveryCommand(t *testing.T) {
	e := newE2E(t)
	e.fx.Write("docs/setup.md", "Clone from https://forgejo.lan/me/proj.git\n")
	e.fx.Commit("docs")
	e.fx.Publish(e.gs, "me/proj")

	code, out, _ := e.run(t, "plan", "-config", e.cfg, "-state", e.state)
	if code != exitInvalid || !strings.Contains(out, "BLOCK me/proj  forgejo-host  main:docs/setup.md:1") {
		t.Fatalf("plan: exit %d\n%s", code, out)
	}
	code, _, errs := e.run(t, "apply", "-config", e.cfg, "-state", e.state, "-no-deploy")
	if code != exitInvalid || !strings.Contains(errs, "BLOCKED by the gates; nothing was published") {
		t.Fatalf("apply: exit %d %s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(e.state, "staging", "site")); err == nil {
		t.Fatal("apply staged a blocked site")
	}
	site := filepath.Join(e.dir, "preview")
	if code, _, _ := e.run(t, "preview", "-config", e.cfg, "-state", e.state, "-out", site, "-build-only"); code != exitInvalid {
		t.Fatalf("preview: exit %d", code)
	}
	// -ignore-gates builds locally; the output lint still reports it.
	code, out, errs = e.run(t, "preview", "-config", e.cfg, "-state", e.state, "-out", site, "-build-only", "-ignore-gates")
	if code != exitOK || !strings.Contains(out, "output lint: FAILED") || !strings.Contains(out, "forgejo-host") {
		t.Fatalf("preview -ignore-gates: exit %d\n%s\n%s", code, out, errs)
	}
}

func TestUnpublish(t *testing.T) {
	e := newE2E(t)
	code, out, errs := e.run(t, "unpublish", "-config", e.cfg, "-state", e.state, "-no-deploy", "ME/proj")
	if code != exitOK || !strings.Contains(out, "remove ME/proj from") {
		t.Fatalf("unpublish: exit %d\n%s\n%s", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(e.state, "staging", "site", "me")); err == nil {
		t.Error("unpublished repo still staged")
	}
	if _, err := os.Stat(filepath.Join(e.state, "staging", "site", "index.html")); err != nil {
		t.Error(err)
	}
	if code, _, _ := e.run(t, "unpublish", "-config", e.cfg, "-state", e.state, "nope/x"); code != exitUsage {
		t.Errorf("unknown slug: exit %d", code)
	}
}

// Without a deploy section only -no-deploy runs; apply refuses up front.
func TestApplyWithoutDeploySection(t *testing.T) {
	e := newE2E(t)
	b, err := os.ReadFile(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	doc = doc[:strings.Index(doc, "deploy:")]
	if err := os.WriteFile(e.cfg, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs := e.run(t, "apply", "-config", e.cfg, "-state", e.state)
	if code != exitInvalid || !strings.Contains(errs, "no deploy section") || !strings.Contains(errs, "nothing was published") {
		t.Fatalf("apply without deploy: exit %d %s", code, errs)
	}
	if code, out, errs := e.run(t, "apply", "-config", e.cfg, "-state", e.state, "-no-deploy"); code != exitOK {
		t.Fatalf("apply -no-deploy without deploy: exit %d\n%s\n%s", code, out, errs)
	}
}
