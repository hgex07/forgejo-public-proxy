// SPDX-License-Identifier: AGPL-3.0-or-later

package site

import (
	"bytes"
	"path"
	"regexp"
	"strings"

	"github.com/go-enry/go-enry/v2"

	"fpp/internal/render"
)

// blobInfo is what the generator knows about a blob's content.
type blobInfo struct {
	size  int64
	text  bool
	lfs   bool
	bidi  bool
	lines int
	image string // sniffed image type: png, jpeg, gif, webp, avif, ico, svg
}

func classify(data []byte) *blobInfo {
	b := &blobInfo{size: int64(len(data)), text: render.IsText(data), image: sniffImage(data)}
	if b.text {
		b.lfs = len(data) < 1024 && bytes.HasPrefix(data, []byte("version https://git-lfs.github.com/spec/v1\n"))
		b.bidi = render.HasBidi(data)
		if len(data) > 0 {
			b.lines = bytes.Count(data, []byte{'\n'})
			if data[len(data)-1] != '\n' {
				b.lines++
			}
		}
	}
	return b
}

// mediaExt maps allowlisted image extensions to the sniffed type
// the content must have.
var mediaExt = map[string]string{
	".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif", ".webp": "webp",
	".avif": "avif", ".ico": "ico", ".svg": "svg",
}

// Byte classes: the URL prefix a file's bytes are served under.
const (
	classRaw   = "raw"   // text, served as text/plain
	classMedia = "media" // allowlisted image, extension matches content
	classDL    = "dl"    // everything else, served as an attachment
)

// byteClass decides how a file is served. An image is only "media" when its
// extension and its content agree (HTML named .png is a download).
func (b *blobInfo) byteClass(name string) string {
	if want, ok := mediaExt[strings.ToLower(path.Ext(name))]; ok && b.image == want && !b.lfs {
		return classMedia
	}
	if b.text {
		return classRaw
	}
	return classDL
}

var svgRe = regexp.MustCompile(`(?is)^\s*(<\?xml[^>]*>\s*)?(<!--.*?-->\s*)*(<!doctype svg[^>]*>\s*)?(<!--.*?-->\s*)*<svg[\s>]`)

func sniffImage(d []byte) string {
	switch {
	case bytes.HasPrefix(d, []byte("\x89PNG\r\n\x1a\n")):
		return "png"
	case bytes.HasPrefix(d, []byte("\xff\xd8\xff")):
		return "jpeg"
	case bytes.HasPrefix(d, []byte("GIF87a")), bytes.HasPrefix(d, []byte("GIF89a")):
		return "gif"
	case len(d) >= 12 && bytes.Equal(d[:4], []byte("RIFF")) && bytes.Equal(d[8:12], []byte("WEBP")):
		return "webp"
	case len(d) >= 12 && bytes.Equal(d[4:8], []byte("ftyp")) && (bytes.Equal(d[8:12], []byte("avif")) || bytes.Equal(d[8:12], []byte("avis"))):
		return "avif"
	case bytes.HasPrefix(d, []byte{0, 0, 1, 0}):
		return "ico"
	}
	head := d
	if len(head) > 4096 {
		head = head[:4096]
	}
	if render.IsText(head) && svgRe.Match(head) {
		return "svg"
	}
	return ""
}

// isMarkdown reports whether a file renders as markdown.
func isMarkdown(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".md", ".markdown", ".mdown", ".mkd", ".mkdn":
		return true
	}
	return false
}

// readmeRank orders README candidates; 0 = not a README.
func readmeRank(name string) int {
	switch strings.ToLower(name) {
	case "readme.md", "readme.markdown":
		return 3
	case "readme", "readme.txt":
		return 2
	}
	if strings.HasPrefix(strings.ToLower(name), "readme.") {
		return 1
	}
	return 0
}

var colorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// langColor is the language's color, or a neutral gray.
func langColor(lang string) string {
	if c := enry.GetColor(lang); colorRe.MatchString(c) {
		return c
	}
	return "#8b949e"
}

// detectLanguage returns the file's language name ("" if unknown).
func detectLanguage(name string, data []byte) string {
	head := data
	if len(head) > 16<<10 {
		head = head[:16<<10]
	}
	return enry.GetLanguage(path.Base(name), head)
}

// countsForStats reports whether a file counts toward the language bar
// (like GitHub linguist: no vendored, generated, documentation or data).
func countsForStats(name, lang string, data []byte) bool {
	if lang == "" || enry.IsVendor(name) || enry.IsDocumentation(name) || enry.IsDotFile(name) ||
		enry.IsConfiguration(name) || enry.IsImage(name) || enry.IsGenerated(name, data) {
		return false
	}
	t := enry.GetLanguageType(lang)
	return t == enry.Programming || t == enry.Markup
}
