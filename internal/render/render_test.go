// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"math/rand"

	"golang.org/x/net/html"
	"strings"
	"testing"
	"time"
)

type fakeLinks struct{}

func (fakeLinks) Href(d string) (string, bool) {
	switch {
	case d == "docs/ok.md":
		return "/o/r/blob/main/docs/ok.md/", true
	case strings.HasPrefix(d, "https://"):
		return d, true
	case strings.HasPrefix(d, "mailto:"):
		return d, true
	}
	return "", false
}

func (fakeLinks) Src(s string) (string, ImageMode) {
	switch {
	case s == "img/logo.png":
		return "/o/r/media/main/img/logo.png", ImageShow
	case strings.HasPrefix(s, "https://"):
		return s, ImageLink
	}
	return "", ImageDrop
}

func md(t *testing.T, src string) string {
	t.Helper()
	return Markdown{}.Render(src, fakeLinks{}).String()
}

func TestMarkdownXSS(t *testing.T) {
	for _, src := range []string{
		"<script>alert(1)</script>",
		`<img src=x onerror="alert(1)">`,
		`[x](javascript:alert(1))`,
		`<a href="javascript:alert(1)">x</a>`,
		`[x](data:text/html;base64,PHNjcmlwdD4=)`,
		`<svg><script>alert(1)</script></svg>`,
		`<iframe src="https://evil.example"></iframe>`,
		`<form action="https://evil.example"><input name=q></form>`,
		`<p style="background:url(x)">s</p>`,
		`<div onclick="x()">c</div>`,
		`<object data="x"></object>`,
		`<a href="https://ok.example" target="_blank" rel="opener">t</a>`,
		"<math><mi xlink:href=\"javascript:alert(1)\">x</mi></math>",
		"<base href=\"https://evil.example/\">",
		"<meta http-equiv=refresh content=\"0;url=https://evil.example\">",
		"<style>body{display:none}</style>",
	} {
		out := strings.ToLower(md(t, src))
		for _, bad := range []string{"<script", "onerror", "javascript:", "data:", "<iframe", "<form",
			"style=", "onclick", "<object", "opener\"", "target=", "<base", "<meta", "<style", "<svg"} {
			if strings.Contains(out, bad) {
				t.Errorf("%q → %q contains %q", src, out, bad)
			}
		}
	}
}

func TestMarkdownLinks(t *testing.T) {
	out := md(t, "# Title\n\n[ok](docs/ok.md) [gone](secret/x.md) [ext](https://e.example/a) "+
		"[frag](#title)\n\n![logo](img/logo.png) ![ext](https://img.example/x.png) ![missing](nope.png)\n\n"+
		`<a name="anchor">a</a> <div id="main">m</div> <a href="secret/y">raw</a>`)
	for _, want := range []string{
		`<h1 id="user-content-title">Title</h1>`,
		`<a href="/o/r/blob/main/docs/ok.md/">ok</a>`,
		` gone `,
		`<a href="https://e.example/a" rel="nofollow noopener noreferrer">ext</a>`,
		`<a href="#user-content-title">frag</a>`,
		`<img src="/o/r/media/main/img/logo.png" alt="logo">`,
		`<a href="https://img.example/x.png" rel="nofollow noopener noreferrer">ext</a>`,
		`missing`,
		`<a name="user-content-anchor">a</a>`,
		`<div id="user-content-main">m</div>`,
		` raw`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "secret/") || strings.Contains(out, "nope.png") {
		t.Errorf("unpublished target leaked:\n%s", out)
	}
}

func TestMarkdownFeatures(t *testing.T) {
	out := md(t, "- [x] done\n- [ ] todo\n\n| a | b |\n|---|:-:|\n| 1 | 2 |\n\n~~old~~\n\n"+
		"<details><summary>More</summary>hidden</details>\n\n<p align=\"center\">c</p>\n\n```go\nfunc main() {}\n```\n")
	for _, want := range []string{`type="checkbox"`, `disabled`, `<table>`, `<del>old</del>`,
		`<details><summary>More</summary>`, `align="center"`, `<pre class="hl"><code>`, `<span class="hl-kd">func</span>`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestHighlight(t *testing.T) {
	lines, ok := Highlight("main.go", "", "package main\n\nfunc main() { x := \"<b>\" }\n", time.Second)
	if !ok || len(lines) != 3 {
		t.Fatalf("ok=%v lines=%d", ok, len(lines))
	}
	if !strings.Contains(lines[2].String(), "&lt;b&gt;") || !strings.Contains(lines[0].String(), `class="hl-k`) {
		t.Errorf("lines: %v", lines)
	}
	if lines[1].String() != "" {
		t.Errorf("blank line = %q", lines[1])
	}
	plain, ok := Highlight("notes.unknownext", "", "<script>\r\nx", time.Second)
	if ok || len(plain) != 2 || plain[0].String() != "&lt;script&gt;" {
		t.Errorf("plain: %v %v", ok, plain)
	}
	if _, ok := Highlight("", "go\" onload=\"x", "x", time.Second); ok {
		t.Error("bogus fence language matched a lexer")
	}
}

func TestIsText(t *testing.T) {
	if !IsText([]byte("héllo\n")) || IsText([]byte("a\x00b")) || IsText([]byte{0xff, 0xfe}) {
		t.Error("IsText")
	}
}

func apply(lines []DiffLine, a string) string {
	// Rebuild b from a and the hunks.
	x := splitLines(a)
	var out []string
	next := 0
	for _, l := range lines {
		switch l.Kind {
		case ' ':
			for next < l.Old-1 {
				out = append(out, x[next])
				next++
			}
			out = append(out, l.Text)
			next = l.Old
		case '-':
			for next < l.Old-1 {
				out = append(out, x[next])
				next++
			}
			next = l.Old
		case '+':
			out = append(out, l.Text)
		}
	}
	out = append(out, x[next:]...)
	return strings.Join(out, "\n")
}

func TestDiffProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	gen := func() string {
		n := rng.Intn(30)
		ls := make([]string, n)
		for i := range ls {
			ls[i] = string(rune('a' + rng.Intn(4)))
		}
		return strings.Join(ls, "\n")
	}
	for i := 0; i < 2000; i++ {
		a, b := gen(), gen()
		d, ok := Diff(a, b)
		if !ok {
			t.Fatal("diff refused small input")
		}
		if got := apply(d, a); got != b {
			t.Fatalf("diff(%q,%q) does not round-trip: got %q\n%+v", a, b, got, d)
		}
	}
	d, _ := Diff("a\nb\nc\n", "a\nB\nc\n")
	if len(d) != 5 || d[0].Header != "@@ -1,3 +1,3 @@" || d[2].Kind != '-' || d[3].Kind != '+' {
		t.Errorf("%+v", d)
	}
	if d, _ := Diff("", "x\n"); len(d) != 2 || d[0].Header != "@@ -0,0 +1 @@" {
		t.Errorf("%+v", d)
	}
	big := strings.Repeat("x\n", diffMaxLines+1)
	if _, ok := Diff(big, ""); ok {
		t.Error("oversized diff accepted")
	}
}

func TestDetectLicense(t *testing.T) {
	mit := `MIT License

Copyright (c) 2026 Someone

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`
	if id := DetectLicense(mit); id != "MIT" {
		t.Errorf("MIT detected as %q", id)
	}
	if id := DetectLicense("all rights reserved"); id != "" {
		t.Errorf("got %q", id)
	}
	if !IsLicenseFile("LICENSE.md") || !IsLicenseFile("COPYING") || IsLicenseFile("docs/LICENSE") {
		t.Error("IsLicenseFile")
	}
}

func FuzzMarkdown(f *testing.F) {
	f.Add("<a href=\"x\">y</a> [z](#q) ![i](img/logo.png)")
	f.Add("<img src=x onerror=alert(1)>")
	f.Add("0 onerror=")
	f.Fuzz(func(t *testing.T, src string) {
		out := Markdown{HighlightTimeout: 100 * time.Millisecond}.Render(src, fakeLinks{}).String()
		if err := checkHTML(out); err != "" {
			t.Fatalf("%s in output for %q:\n%s", err, src, out)
		}
	})
}

// checkHTML is an independent oracle: structural properties every rendered
// fragment must have, whatever the input.
func checkHTML(s string) string {
	z := html.NewTokenizer(strings.NewReader(s))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return ""
		}
		tok := z.Token()
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		switch tok.Data {
		case "script", "style", "iframe", "object", "embed", "form", "base", "meta", "link", "svg", "math", "frame", "textarea", "button", "select":
			return "forbidden element " + tok.Data
		}
		for _, a := range tok.Attr {
			k, v := strings.ToLower(a.Key), strings.ToLower(strings.TrimSpace(a.Val))
			if strings.HasPrefix(k, "on") || k == "style" || k == "srcset" || k == "formaction" || k == "target" {
				return "forbidden attribute " + k
			}
			if (k == "id" || k == "name") && !strings.HasPrefix(a.Val, ContentPrefix) {
				return "unprefixed " + k
			}
			if k == "href" || k == "src" {
				if strings.HasPrefix(v, "javascript:") || strings.HasPrefix(v, "data:") || strings.HasPrefix(v, "vbscript:") {
					return "dangerous url " + v
				}
				if k == "href" && !strings.HasPrefix(v, "#") && !strings.HasPrefix(v, "/o/r/") && !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "mailto:") {
					return "unresolved href " + v
				}
				if k == "src" && !strings.HasPrefix(v, "/o/r/") {
					return "unresolved src " + v
				}
			}
		}
	}
}
