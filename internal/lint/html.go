// SPDX-License-Identifier: AGPL-3.0-or-later

package lint

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
)

// forbiddenElements never appear in generated pages: the templates don't
// emit them and the sanitizer strips them from repo content.
var forbiddenElements = map[string]bool{
	"iframe": true, "frame": true, "frameset": true, "object": true, "embed": true, "applet": true,
	"form": true, "input": false, "base": true, "style": true, "link": false, "meta": false,
	"portal": true, "svg": false, "math": true, "template": true, "noscript": true,
}

// urlAttrs hold URLs.
var urlAttrs = map[string]bool{
	"href": true, "src": true, "action": true, "formaction": true, "xlink:href": true, "poster": true,
	"background": true, "cite": true, "data": true, "srcset": true, "longdesc": true, "ping": true,
	"manifest": true, "codebase": true, "lowsrc": true,
}

// checkHTML returns the first structural problem of a generated page, or "".
func checkHTML(data []byte) string {
	z := html.NewTokenizer(bytes.NewReader(data))
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return ""
		case html.StartTagToken, html.SelfClosingTagToken:
		default:
			continue
		}
		tok := z.Token()
		name := strings.ToLower(tok.Data)
		if forbiddenElements[name] {
			return "forbidden element <" + name + ">"
		}
		attrs := map[string]string{}
		for _, a := range tok.Attr {
			k := strings.ToLower(a.Key)
			if a.Namespace != "" {
				k = strings.ToLower(a.Namespace) + ":" + k
			}
			attrs[k] = a.Val
			if strings.HasPrefix(k, "on") {
				return "event handler attribute " + k + " on <" + name + ">"
			}
			if k == "style" {
				return "style attribute on <" + name + ">"
			}
			if urlAttrs[k] || urlAttrs[strings.TrimPrefix(k, "xlink:")] {
				if s := dangerousURL(a.Val); s != "" {
					return "dangerous URL (" + s + ") in " + k + " on <" + name + ">"
				}
			}
		}
		switch name {
		case "script":
			// The site uses no JavaScript at all (the CSP has no
			// script-src, so default-src 'none' applies).
			return "<script> element"
		case "meta":
			if _, ok := attrs["http-equiv"]; ok {
				return "<meta http-equiv>"
			}
		case "link":
			if rel := strings.ToLower(attrs["rel"]); rel != "stylesheet" && rel != "icon" && rel != "canonical" {
				return "<link rel=" + rel + ">"
			}
		case "input":
			if attrs["type"] != "checkbox" {
				return "<input> other than a task-list checkbox"
			}
			if _, ok := attrs["disabled"]; !ok {
				return "enabled <input>"
			}
		}
	}
}

// dangerousURL returns the scheme of a URL that could run code, or "".
func dangerousURL(v string) string {
	// Browsers ignore leading spaces/control characters and tabs/newlines
	// inside the scheme.
	s := strings.Map(func(r rune) rune {
		if r <= 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.ToLower(v))
	for _, scheme := range []string{"javascript:", "vbscript:", "data:", "blob:", "filesystem:"} {
		if strings.HasPrefix(s, scheme) {
			return scheme
		}
	}
	return ""
}
