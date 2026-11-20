// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"bytes"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	gmhtml "github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/util"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// ImageMode says how an image source is rendered.
type ImageMode int

const (
	// ImageDrop renders only the alt text.
	ImageDrop ImageMode = iota
	// ImageShow renders the image from the returned URL.
	ImageShow
	// ImageLink renders a link to the returned URL with the alt text.
	ImageLink
)

// Links resolves link and image targets found in user content. Every URL that
// ends up in rendered markdown comes from a Links implementation.
type Links interface {
	// Href maps a link target. ok=false renders the link as plain text.
	Href(dest string) (href string, ok bool)
	// Src maps an image source.
	Src(src string) (url string, mode ImageMode)
}

// Markdown renders GitHub-flavored markdown with a strict sanitizer.
type Markdown struct {
	// HighlightTimeout bounds lexing of each fenced code block.
	HighlightTimeout time.Duration
}

// Render converts src to sanitized HTML. Links and images are rewritten
// through links; ids get ContentPrefix.
func (m Markdown) Render(src string, links Links) Safe {
	md := goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithParserOptions(parser.WithAutoHeadingID()),
		goldmark.WithRendererOptions(
			// Raw HTML passes through to the sanitizer (same as Forgejo).
			gmhtml.WithUnsafe(),
			renderer.WithNodeRenderers(util.Prioritized(&fenceRenderer{timeout: m.timeout()}, 100)),
		),
	)
	var buf bytes.Buffer
	if err := md.Convert([]byte(src), &buf); err != nil {
		return Safe{}
	}
	return finish(buf.String(), links)
}

func (m Markdown) timeout() time.Duration {
	if m.HighlightTimeout <= 0 {
		return 2 * time.Second
	}
	return m.HighlightTimeout
}

// finish sanitizes, rewrites URLs and ids, then sanitizes again (the
// rewrite must not be able to introduce anything the allowlist rejects).
func finish(raw string, links Links) Safe {
	clean := SanitizeHTML(raw)
	rewritten := rewrite(clean, links)
	return sanitized(SanitizeHTML(rewritten))
}

// rewrite walks sanitized HTML and applies the link policy.
func rewrite(s string, links Links) string {
	z := html.NewTokenizer(strings.NewReader(s))
	var out strings.Builder
	var dropA []bool // per open <a>: was its start tag dropped?
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if z.Err() == io.EOF {
				return out.String()
			}
			return "" // the sanitizer's output should always tokenize
		}
		tok := z.Token()
		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			prefixIDs(&tok)
			switch tok.DataAtom {
			case atom.A:
				ok := rewriteAnchor(&tok, links)
				if tt == html.StartTagToken {
					dropA = append(dropA, !ok)
				}
				if !ok {
					continue
				}
			case atom.Img:
				out.WriteString(rewriteImage(tok, links))
				continue
			}
		case html.EndTagToken:
			if tok.DataAtom == atom.A && len(dropA) > 0 {
				drop := dropA[len(dropA)-1]
				dropA = dropA[:len(dropA)-1]
				if drop {
					continue
				}
			}
		}
		out.WriteString(tok.String())
	}
}

func prefixIDs(tok *html.Token) {
	for i, a := range tok.Attr {
		if (a.Key == "id" || a.Key == "name") && !strings.HasPrefix(a.Val, ContentPrefix) {
			tok.Attr[i].Val = ContentPrefix + a.Val
		}
	}
}

func getAttr(tok html.Token, key string) (string, bool) {
	for _, a := range tok.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

func setAttr(tok *html.Token, key, val string) {
	for i, a := range tok.Attr {
		if a.Key == key {
			tok.Attr[i].Val = val
			return
		}
	}
	tok.Attr = append(tok.Attr, html.Attribute{Key: key, Val: val})
}

func delAttr(tok *html.Token, key string) {
	attrs := tok.Attr[:0]
	for _, a := range tok.Attr {
		if a.Key != key {
			attrs = append(attrs, a)
		}
	}
	tok.Attr = attrs
}

// rewriteAnchor returns false if the link must be reduced to its text.
func rewriteAnchor(tok *html.Token, links Links) bool {
	delAttr(tok, "rel")
	delAttr(tok, "target")
	href, ok := getAttr(*tok, "href")
	if !ok {
		return true // a named anchor
	}
	if strings.HasPrefix(href, "#") {
		frag := href[1:]
		if frag == "" {
			return false
		}
		if !strings.HasPrefix(frag, ContentPrefix) {
			frag = ContentPrefix + frag
		}
		setAttr(tok, "href", "#"+frag)
		return true
	}
	dest, ok := links.Href(href)
	if !ok {
		return false
	}
	setAttr(tok, "href", dest)
	if IsExternal(dest) {
		setAttr(tok, "rel", relExternal)
	}
	return true
}

func rewriteImage(tok html.Token, links Links) string {
	src, _ := getAttr(tok, "src")
	alt, _ := getAttr(tok, "alt")
	mode := ImageDrop
	var dest string
	if src != "" {
		dest, mode = links.Src(src)
	}
	switch mode {
	case ImageShow:
		setAttr(&tok, "src", dest)
		return tok.String()
	case ImageLink:
		label := alt
		if label == "" {
			label = dest
		}
		rel := ""
		if IsExternal(dest) {
			rel = ` rel="` + relExternal + `"`
		}
		return `<a href="` + escape(dest) + `"` + rel + `>` + escape(label) + `</a>`
	default:
		return escape(alt)
	}
}

// IsExternal reports whether u has a scheme or host (leaves the site).
func IsExternal(u string) bool {
	p, err := url.Parse(u)
	return err != nil || p.Scheme != "" || p.Host != ""
}

// fenceRenderer highlights fenced code blocks.
type fenceRenderer struct{ timeout time.Duration }

func (f *fenceRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindFencedCodeBlock, f.render)
}

func (f *fenceRenderer) render(w util.BufWriter, src []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	node := n.(*ast.FencedCodeBlock)
	var code strings.Builder
	for i := 0; i < node.Lines().Len(); i++ {
		seg := node.Lines().At(i)
		code.Write(seg.Value(src))
	}
	lang := ""
	if l := node.Language(src); l != nil {
		lang = string(l)
	}
	lines, _ := Highlight("", lang, code.String(), f.timeout)
	_, _ = w.WriteString(`<pre class="hl"><code>`)
	for i, l := range lines {
		if i > 0 {
			_ = w.WriteByte('\n')
		}
		_, _ = w.WriteString(l.h)
	}
	_, _ = w.WriteString("</code></pre>\n")
	return ast.WalkSkipChildren, nil
}
