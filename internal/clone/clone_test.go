// SPDX-License-Identifier: AGPL-3.0-or-later

package clone

import "testing"

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"a/b.go":       `"a/b.go"`,
		`we"ird\name`:  `"we\"ird\\name"`,
		"\"lead space": `"\"lead space"`,
		"tab\there":    `"tab\011here"`,
		"ñ.txt":        `"ñ.txt"`,
	} {
		if got := quote(in); got != want {
			t.Errorf("quote(%q) = %s, want %s", in, got, want)
		}
	}
	if got := cleanName("Eve <eve@x> \n"); got != "Eve eve@x" {
		t.Errorf("cleanName = %q", got)
	}
}
