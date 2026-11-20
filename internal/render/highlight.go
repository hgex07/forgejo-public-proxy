// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/lexers"
)

// maxLexerName bounds markdown fence info strings used for lexer lookup.
const maxLexerName = 40

// Highlight splits src into lines of HTML with syntax classes (hl-*), using
// the lexer for filename or, if empty, for lang (a markdown fence). If no
// lexer matches, lexing panics or exceeds timeout, it returns escaped plain
// lines and false. src must be valid UTF-8 (callers check).
func Highlight(filename, lang string, src string, timeout time.Duration) ([]Safe, bool) {
	lexer := pickLexer(filename, lang)
	if lexer == nil {
		return plainLines(src), false
	}
	lines, ok := tokenize(lexer, src, timeout)
	if !ok {
		return plainLines(src), false
	}
	return lines, true
}

func pickLexer(filename, lang string) chroma.Lexer {
	var l chroma.Lexer
	if filename != "" {
		l = lexers.Match(path.Base(filename))
	} else if lang != "" && len(lang) <= maxLexerName {
		l = lexers.Get(lang)
	}
	if l == nil || l.Config().Name == "plaintext" {
		return nil
	}
	return chroma.Coalesce(l)
}

func tokenize(lexer chroma.Lexer, src string, timeout time.Duration) (lines []Safe, ok bool) {
	defer func() {
		if recover() != nil {
			lines, ok = nil, false
		}
	}()
	it, err := lexer.Tokenise(nil, src)
	if err != nil {
		return nil, false
	}
	deadline := time.Now().Add(timeout)
	var cur strings.Builder
	n := 0
	for tok := it(); tok != chroma.EOF; tok = it() {
		if n++; n%256 == 0 && time.Now().After(deadline) {
			return nil, false
		}
		class := chroma.StandardTypes[tok.Type]
		if class == "w" || !validClass(class) {
			class = ""
		}
		parts := strings.Split(tok.Value, "\n")
		for i, part := range parts {
			if i > 0 {
				lines = append(lines, escaped(cur.String()))
				cur.Reset()
			}
			part = strings.TrimSuffix(part, "\r")
			if part == "" {
				continue
			}
			if class == "" {
				cur.WriteString(escape(part))
			} else {
				cur.WriteString(`<span class="hl-` + class + `">` + escape(part) + `</span>`)
			}
		}
	}
	if cur.Len() > 0 {
		lines = append(lines, escaped(cur.String()))
	}
	return lines, true
}

func validClass(c string) bool {
	if c == "" || len(c) > 4 {
		return false
	}
	for _, r := range c {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func plainLines(src string) []Safe {
	src = strings.TrimSuffix(src, "\n")
	if src == "" {
		return nil
	}
	parts := strings.Split(src, "\n")
	out := make([]Safe, len(parts))
	for i, p := range parts {
		out[i] = escaped(escape(strings.TrimSuffix(p, "\r")))
	}
	return out
}

// IsText reports whether data should be shown as text: valid UTF-8 (a
// truncated final rune is tolerated) and no NUL in the first 8 KiB.
func IsText(data []byte) bool {
	head := data
	if len(head) > 8<<10 {
		head = head[:8<<10]
	}
	for _, b := range head {
		if b == 0 {
			return false
		}
	}
	return utf8.Valid(data)
}

// HasBidi detects Trojan Source characters (bidi overrides and isolates).
func HasBidi(d []byte) bool {
	for _, r := range string(d) {
		switch r {
		case '\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069':
			return true
		}
	}
	return false
}
