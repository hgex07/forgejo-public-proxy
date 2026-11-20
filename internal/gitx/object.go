// SPDX-License-Identifier: AGPL-3.0-or-later

package gitx

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Signature is an author, committer or tagger. The email is parsed only to
// be discarded: it never leaves this package (invariant I5).
type Signature struct {
	Name string
	When time.Time // UTC
}

// Commit is a parsed commit object.
type Commit struct {
	Tree      string
	Parents   []string
	Author    Signature
	Committer Signature
	Encoding  string
	Message   []byte
}

// Tag is a parsed annotated tag object.
type Tag struct {
	Object  string
	Type    string
	Name    string
	Tagger  Signature // zero if absent
	Message []byte    // without any trailing PGP/SSH signature
}

var errMalformed = errors.New("gitx: malformed object")

// headers splits an object into header fields and the message. Continuation
// lines (leading space, e.g. gpgsig) are folded into the previous field.
func headers(data []byte) ([][2]string, []byte, error) {
	var hs [][2]string
	for len(data) > 0 {
		nl := bytes.IndexByte(data, '\n')
		if nl < 0 {
			return nil, nil, errMalformed
		}
		line := data[:nl]
		data = data[nl+1:]
		if len(line) == 0 {
			return hs, data, nil
		}
		if line[0] == ' ' {
			if len(hs) == 0 {
				return nil, nil, errMalformed
			}
			hs[len(hs)-1][1] += "\n" + string(line[1:])
			continue
		}
		k, v, _ := strings.Cut(string(line), " ")
		hs = append(hs, [2]string{k, v})
	}
	return hs, nil, nil
}

// ParseCommit parses a raw commit object.
func ParseCommit(data []byte) (*Commit, error) {
	hs, msg, err := headers(data)
	if err != nil {
		return nil, err
	}
	c := &Commit{Message: msg}
	var haveAuthor, haveCommitter bool
	for _, h := range hs {
		switch h[0] {
		case "tree":
			if c.Tree != "" || !ValidOID(h[1]) {
				return nil, errMalformed
			}
			c.Tree = h[1]
		case "parent":
			if !ValidOID(h[1]) {
				return nil, errMalformed
			}
			c.Parents = append(c.Parents, h[1])
		case "author":
			if c.Author, err = parseSignature(h[1]); err != nil {
				return nil, err
			}
			haveAuthor = true
		case "committer":
			if c.Committer, err = parseSignature(h[1]); err != nil {
				return nil, err
			}
			haveCommitter = true
		case "encoding":
			c.Encoding = h[1]
		}
	}
	if c.Tree == "" || !haveAuthor || !haveCommitter {
		return nil, errMalformed
	}
	return c, nil
}

// ParseTag parses a raw annotated tag object.
func ParseTag(data []byte) (*Tag, error) {
	hs, msg, err := headers(data)
	if err != nil {
		return nil, err
	}
	t := &Tag{Message: stripSignature(msg)}
	for _, h := range hs {
		switch h[0] {
		case "object":
			if !ValidOID(h[1]) {
				return nil, errMalformed
			}
			t.Object = h[1]
		case "type":
			t.Type = h[1]
		case "tag":
			t.Name = h[1]
		case "tagger":
			if t.Tagger, err = parseSignature(h[1]); err != nil {
				return nil, err
			}
		}
	}
	if t.Object == "" || t.Type == "" {
		return nil, errMalformed
	}
	return t, nil
}

func stripSignature(msg []byte) []byte {
	for _, marker := range []string{"-----BEGIN PGP SIGNATURE-----", "-----BEGIN SSH SIGNATURE-----", "-----BEGIN SIGNED MESSAGE-----"} {
		if i := bytes.Index(msg, []byte(marker)); i >= 0 && (i == 0 || msg[i-1] == '\n') {
			msg = msg[:i]
		}
	}
	return msg
}

// parseSignature parses "Name <email> 1700000000 +0100", discarding the
// email and the timezone (dates are published in UTC).
func parseSignature(s string) (Signature, error) {
	lt := strings.IndexByte(s, '<')
	gt := strings.LastIndexByte(s, '>')
	if lt < 0 || gt < lt {
		return Signature{}, errMalformed
	}
	name := strings.TrimSpace(s[:lt])
	f := strings.Fields(s[gt+1:])
	if len(f) < 1 {
		return Signature{}, errMalformed
	}
	ts, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return Signature{}, errMalformed
	}
	return Signature{Name: name, When: time.Unix(ts, 0).UTC()}, nil
}
