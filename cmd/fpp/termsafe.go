// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"io"
	"unicode"
	"unicode/utf8"
)

// termSafe wraps an operator-facing writer so that text taken from Forgejo
// or from repo content (descriptions, paths, ref and release names, git
// and rsync output) cannot drive the terminal: control characters other
// than newline and tab, C1 controls, Unicode format characters (bidi
// overrides) and invalid UTF-8 are written as '?'. Otherwise a repo admin
// could hide or rewrite lines of the exposure report the operator reviews.
func termSafe(w io.Writer) io.Writer { return &safeWriter{w: w} }

type safeWriter struct {
	w       io.Writer
	pending []byte // an incomplete UTF-8 sequence from the previous Write
}

func (s *safeWriter) Write(p []byte) (int, error) {
	data := append(s.pending, p...)
	s.pending = nil
	out := make([]byte, 0, len(data))
	for len(data) > 0 {
		r, n := utf8.DecodeRune(data)
		if r == utf8.RuneError && n <= 1 {
			if !utf8.FullRune(data) {
				s.pending = append([]byte(nil), data...)
				break
			}
			out = append(out, '?')
			data = data[n:]
			continue
		}
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.Is(unicode.Cf, r) {
			out = append(out, '?')
		} else {
			out = append(out, data[:n]...)
		}
		data = data[n:]
	}
	if _, err := s.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}
