// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import "strings"

// DiffLine is one line of a unified diff. Text is plain (templates escape it).
type DiffLine struct {
	Kind   byte // ' ', '+', '-', '@' (hunk header)
	Old    int  // 1-based line number in the old file, 0 if none
	New    int  // 1-based line number in the new file, 0 if none
	Text   string
	Header string // for '@' lines
}

// DiffLimits bound the work Diff does.
const (
	diffContext  = 3
	diffMaxLines = 20000 // per side
	diffMaxEdits = 2000
)

// Diff computes a unified line diff of a and b. ok is false when the inputs
// are too large or too different to diff cheaply.
func Diff(a, b string) (lines []DiffLine, ok bool) {
	x, y := splitLines(a), splitLines(b)
	if len(x) > diffMaxLines || len(y) > diffMaxLines {
		return nil, false
	}
	ops, ok := myers(x, y)
	if !ok {
		return nil, false
	}
	return hunks(ops, x, y), true
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	ls := strings.Split(s, "\n")
	for i, l := range ls {
		ls[i] = strings.TrimSuffix(l, "\r")
	}
	return ls
}

type op struct {
	kind byte // ' ', '+', '-'
	i, j int  // indices into x (for ' ' and '-') and y (for ' ' and '+')
}

// myers is the classic O((N+M)D) greedy algorithm with the edit path
// recovered from saved frontiers. Common prefix/suffix are stripped first.
func myers(x, y []string) ([]op, bool) {
	pre := 0
	for pre < len(x) && pre < len(y) && x[pre] == y[pre] {
		pre++
	}
	suf := 0
	for suf < len(x)-pre && suf < len(y)-pre && x[len(x)-1-suf] == y[len(y)-1-suf] {
		suf++
	}
	a, b := x[pre:len(x)-suf], y[pre:len(y)-suf]
	n, m := len(a), len(b)
	var mid []op
	if n > 0 || m > 0 {
		max := n + m
		if max > 2*diffMaxEdits {
			max = 2 * diffMaxEdits
		}
		off := max + 1
		v := make([]int, 2*max+3)
		var trace [][]int
		found := false
		for d := 0; d <= max && !found; d++ {
			trace = append(trace, append([]int(nil), v...))
			for k := -d; k <= d; k += 2 {
				var i int
				if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
					i = v[off+k+1]
				} else {
					i = v[off+k-1] + 1
				}
				j := i - k
				for i < n && j < m && a[i] == b[j] {
					i++
					j++
				}
				v[off+k] = i
				if i >= n && j >= m {
					found = true
					break
				}
			}
		}
		if !found {
			return nil, false
		}
		// Backtrack.
		i, j := n, m
		for d := len(trace) - 1; d >= 0 && (i > 0 || j > 0); d-- {
			vd := trace[d]
			k := i - j
			var pk int
			if k == -d || (k != d && vd[off+k-1] < vd[off+k+1]) {
				pk = k + 1
			} else {
				pk = k - 1
			}
			pi := vd[off+pk]
			pj := pi - pk
			for i > pi && j > pj {
				i--
				j--
				mid = append(mid, op{' ', i, j})
			}
			if d > 0 {
				if i == pi {
					j--
					mid = append(mid, op{'+', i, j})
				} else {
					i--
					mid = append(mid, op{'-', i, j})
				}
			}
		}
		for l, r := 0, len(mid)-1; l < r; l, r = l+1, r-1 {
			mid[l], mid[r] = mid[r], mid[l]
		}
	}
	ops := make([]op, 0, pre+len(mid)+suf)
	for i := 0; i < pre; i++ {
		ops = append(ops, op{' ', i, i})
	}
	for _, o := range mid {
		ops = append(ops, op{o.kind, o.i + pre, o.j + pre})
	}
	for s := suf; s > 0; s-- {
		ops = append(ops, op{' ', len(x) - s, len(y) - s})
	}
	return ops, true
}

func hunks(ops []op, x, y []string) []DiffLine {
	var out []DiffLine
	n := len(ops)
	i := 0
	for i < n {
		// Find the next change.
		for i < n && ops[i].kind == ' ' {
			i++
		}
		if i >= n {
			break
		}
		start := max(i-diffContext, 0)
		// Extend while changes are within 2*context of each other.
		end := i
		for end < n {
			if ops[end].kind != ' ' {
				end++
				continue
			}
			run := end
			for run < n && ops[run].kind == ' ' {
				run++
			}
			if run == n || run-end > 2*diffContext {
				end = min(end+diffContext, n)
				break
			}
			end = run
		}
		oldStart, newStart, oldLen, newLen := 0, 0, 0, 0
		var body []DiffLine
		for _, o := range ops[start:end] {
			switch o.kind {
			case ' ':
				body = append(body, DiffLine{Kind: ' ', Old: o.i + 1, New: o.j + 1, Text: x[o.i]})
				oldLen++
				newLen++
			case '-':
				body = append(body, DiffLine{Kind: '-', Old: o.i + 1, Text: x[o.i]})
				oldLen++
			case '+':
				body = append(body, DiffLine{Kind: '+', New: o.j + 1, Text: y[o.j]})
				newLen++
			}
			if oldStart == 0 && o.kind != '+' {
				oldStart = o.i + 1
			}
			if newStart == 0 && o.kind != '-' {
				newStart = o.j + 1
			}
		}
		if oldStart == 0 {
			oldStart = ops[start].i
		}
		if newStart == 0 {
			newStart = ops[start].j
		}
		out = append(out, DiffLine{Kind: '@', Header: hunkHeader(oldStart, oldLen, newStart, newLen)})
		out = append(out, body...)
		i = end
	}
	return out
}

func hunkHeader(os, ol, ns, nl int) string {
	return "@@ -" + rng(os, ol) + " +" + rng(ns, nl) + " @@"
}

func rng(s, l int) string {
	if l == 1 {
		return itoa(s)
	}
	return itoa(s) + "," + itoa(l)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
