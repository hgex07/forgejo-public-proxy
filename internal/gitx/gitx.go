// SPDX-License-Identifier: AGPL-3.0-or-later

// Package gitx is the hardened git exec wrapper.
//
// Every invocation:
//   - runs with an environment built from scratch: no system/global config,
//     an empty HOME (so no ~/.netrc or credential helper), no prompts, and only
//     the remote's URL scheme allowed as a transport;
//   - passes its config through GIT_CONFIG_COUNT, never argv: hooks, fsmonitor,
//     submodule recursion, redirects and credential helpers are all disabled,
//     and fetched objects are fsck'ed;
//   - puts the auth header in that env (remote commands only), so the token is
//     never in argv or on disk;
//   - uses --end-of-options and only ever receives validated object IDs and
//     ref names as arguments;
//   - parses NUL-delimited or length-prefixed output, with size caps.
//
// The builder never checks out a working tree: it reads objects only.
package gitx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// LocalPrefix namespaces every ref the builder creates.
	LocalPrefix = "refs/fpp/"

	localTimeout  = 2 * time.Minute
	remoteTimeout = 10 * time.Minute
	maxStderr     = 64 << 10
	// DefaultMaxOutput caps stdout of a single command.
	DefaultMaxOutput = 256 << 20
)

var oidRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// ValidOID reports whether s is a full lowercase SHA-1 or SHA-256 object ID.
func ValidOID(s string) bool { return oidRe.MatchString(s) }

// Repo is a bare repository on the builder that mirrors a subset of one remote.
type Repo struct {
	bin    string
	dir    string
	home   string
	remote string
	scheme string
	auth   string
}

// Open returns a handle for the bare repo at dir, fetching from remote with
// the given Authorization header value. home must be an empty directory
// private to the builder. Nothing is created until Init.
func Open(dir, home, remote, authHeader string) (*Repo, error) {
	bin, err := exec.LookPath("git")
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(remote)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return nil, errors.New("gitx: remote must be an http(s) URL without credentials")
	}
	if strings.ContainsAny(authHeader, "\r\n") {
		return nil, errors.New("gitx: invalid auth header")
	}
	if !filepath.IsAbs(dir) || !filepath.IsAbs(home) {
		return nil, errors.New("gitx: dir and home must be absolute")
	}
	return &Repo{bin: bin, dir: dir, home: home, remote: remote, scheme: u.Scheme, auth: authHeader}, nil
}

// OpenLocal returns a handle for a repo that never talks to a remote (used
// to build the public clone snapshot). Remote operations fail.
func OpenLocal(dir, home string) (*Repo, error) {
	bin, err := exec.LookPath("git")
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(dir) || !filepath.IsAbs(home) {
		return nil, errors.New("gitx: dir and home must be absolute")
	}
	return &Repo{bin: bin, dir: dir, home: home, scheme: "https"}, nil
}

// FastImport feeds a git fast-import stream (which must end with "done").
func (r *Repo) FastImport(ctx context.Context, stream io.Reader) error {
	_, err := r.run(ctx, runOpts{stdin: stream}, "fast-import", "--quiet", "--done", "--date-format=raw")
	return err
}

// ServeDumb prepares the repo to be served as static files over dumb HTTP:
// HEAD points at head (a full ref name, or "" to keep it), everything is in
// one pack, and info/refs plus objects/info/packs are written.
func (r *Repo) ServeDumb(ctx context.Context, head string) error {
	if head != "" {
		if !ValidRefName(head) {
			return errors.New("gitx: invalid HEAD ref")
		}
		if _, err := r.run(ctx, runOpts{}, "symbolic-ref", "HEAD", head); err != nil {
			return err
		}
	}
	if _, err := r.run(ctx, runOpts{}, "repack", "-a", "-d", "-q", "--no-write-bitmap-index"); err != nil {
		return err
	}
	if _, err := r.run(ctx, runOpts{}, "prune-packed", "-q"); err != nil {
		return err
	}
	_, err := r.run(ctx, runOpts{}, "update-server-info")
	return err
}

// Dir is the bare repo path.
func (r *Repo) Dir() string { return r.dir }

func (r *Repo) env(remote bool) []string {
	cfg := [][2]string{
		{"core.hooksPath", "/dev/null"},
		{"core.fsmonitor", "false"},
		{"core.attributesFile", "/dev/null"},
		{"core.excludesFile", "/dev/null"},
		{"protocol.allow", "never"},
		{"protocol.file.allow", "never"},
		{"protocol." + r.scheme + ".allow", "always"},
		{"transfer.fsckObjects", "true"},
		{"fetch.recurseSubmodules", "false"},
		{"submodule.recurse", "false"},
		{"http.followRedirects", "false"},
		{"credential.helper", ""},
		{"gc.auto", "0"},
		{"maintenance.auto", "false"},
		{"log.showSignature", "false"},
	}
	if remote {
		cfg = append(cfg, [2]string{"http.extraHeader", "Authorization: " + r.auth})
	}
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + r.home,
		"XDG_CONFIG_HOME=" + r.home,
		"LC_ALL=C",
		"TZ=UTC",
		"GIT_DIR=" + r.dir,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL=" + r.scheme,
		"GIT_PROTOCOL_FROM_USER=0",
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_NO_LAZY_FETCH=1",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_CONFIG_COUNT=" + strconv.Itoa(len(cfg)),
	}
	for i, kv := range cfg {
		env = append(env,
			fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]),
			fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]))
	}
	return env
}

// capped is an io.Writer that fails once more than max bytes are written.
type capped struct {
	buf bytes.Buffer
	max int64
	hit bool
}

func (c *capped) Write(p []byte) (int, error) {
	if int64(c.buf.Len()+len(p)) > c.max {
		c.hit = true
		return 0, errors.New("output limit exceeded")
	}
	return c.buf.Write(p)
}

type runOpts struct {
	remote bool
	stdin  io.Reader
	max    int64
}

func (r *Repo) run(ctx context.Context, o runOpts, args ...string) ([]byte, error) {
	timeout := localTimeout
	if o.remote {
		timeout = remoteTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if o.max == 0 {
		o.max = DefaultMaxOutput
	}
	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Env = r.env(o.remote)
	cmd.Dir = r.home
	cmd.Stdin = o.stdin
	stdout := &capped{max: o.max}
	stderr := &capped{max: maxStderr}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if stdout.hit {
		return nil, fmt.Errorf("git %s: output larger than %d bytes", args[0], o.max)
	}
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, r.sanitize(stderr.buf.String()))
	}
	return stdout.buf.Bytes(), nil
}

// sanitize trims stderr for error messages and scrubs the auth header.
func (r *Repo) sanitize(s string) string {
	if r.auth != "" {
		s = strings.ReplaceAll(s, r.auth, "[auth]")
		if _, cred, ok := strings.Cut(r.auth, " "); ok && cred != "" {
			s = strings.ReplaceAll(s, cred, "[auth]")
		}
	}
	s = strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return ' '
		}
		return c
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 500 {
		s = s[:500] + "…"
	}
	return s
}

// Init creates the bare repo if needed. objectFormat is "sha1" or "sha256"
// (empty = sha1). An existing repo with a different format is an error.
func (r *Repo) Init(ctx context.Context, objectFormat string) error {
	if objectFormat == "" {
		objectFormat = "sha1"
	}
	if objectFormat != "sha1" && objectFormat != "sha256" {
		return fmt.Errorf("gitx: unsupported object format %q", objectFormat)
	}
	if err := os.MkdirAll(r.home, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(r.dir, "HEAD")); err == nil {
		out, err := r.run(ctx, runOpts{}, "rev-parse", "--show-object-format")
		if err != nil {
			return err
		}
		if got := strings.TrimSpace(string(out)); got != objectFormat {
			return fmt.Errorf("gitx: %s has object format %s, remote uses %s", r.dir, got, objectFormat)
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(r.dir), 0o700); err != nil {
			return err
		}
		if _, err := r.run(ctx, runOpts{}, "init", "--bare", "--quiet", "--template=",
			"--object-format="+objectFormat, "--end-of-options", r.dir); err != nil {
			return err
		}
	}
	// info/attributes outranks in-tree .gitattributes. It disables
	// export-subst ($Format:%ae$ prints emails), filters and merge drivers,
	// and resets diff to unspecified: no repo-chosen driver applies, but git
	// still detects binary files by content ("-diff" would mark every file
	// binary and zero the numstat counts).
	info := filepath.Join(r.dir, "info")
	if err := os.MkdirAll(info, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(info, "attributes"), []byte(Attributes), 0o600)
}

// Attributes is the info/attributes content of every repo.
const Attributes = "* -export-subst -filter !diff -merge\n"

// RemoteRef is one advertised ref.
type RemoteRef struct {
	Name string // full ref name, e.g. refs/heads/main
	OID  string
}

// LsRemote lists the remote's branches and tags (peeled entries dropped).
func (r *Repo) LsRemote(ctx context.Context) ([]RemoteRef, error) {
	if r.remote == "" {
		return nil, errors.New("gitx: repo has no remote")
	}
	return r.lsRemote(ctx, r.remote)
}

// ProbeHidden returns nil only if `git ls-remote` of url (same scheme and
// host as the remote) fails with an answer that means "no access". Success, or
// a failure that proves nothing (network error), is an error: fail closed.
// The repo must be initialized.
func (r *Repo) ProbeHidden(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	ru, _ := url.Parse(r.remote)
	if err != nil || u.Scheme != ru.Scheme || u.Host != ru.Host {
		return errors.New("gitx: probe URL must be on the remote's host")
	}
	_, err = r.lsRemote(ctx, rawURL)
	if err == nil {
		return fmt.Errorf("%s is FETCHABLE over git", rawURL)
	}
	if noAccessRe.MatchString(err.Error()) {
		return nil
	}
	return fmt.Errorf("git probe of %s inconclusive: %w", rawURL, err)
}

var noAccessRe = regexp.MustCompile(`(?i)not found|authentication failed|could not read username|returned error: 40[134]|HTTP 40[134]`)

func (r *Repo) lsRemote(ctx context.Context, remote string) ([]RemoteRef, error) {
	out, err := r.run(ctx, runOpts{remote: true, max: 32 << 20},
		"ls-remote", "--heads", "--tags", "--end-of-options", remote)
	if err != nil {
		return nil, err
	}
	var refs []RemoteRef
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		oid, name, ok := strings.Cut(line, "\t")
		if !ok || !ValidOID(oid) {
			return nil, fmt.Errorf("gitx: malformed ls-remote line")
		}
		if strings.HasSuffix(name, "^{}") {
			continue
		}
		refs = append(refs, RemoteRef{Name: name, OID: oid})
	}
	return refs, nil
}

// FetchRef maps a remote ref to a local ref under LocalPrefix.
type FetchRef struct {
	Remote string // refs/heads/x or refs/tags/x
	Local  string // refs/fpp/...
}

// Fetch fetches exactly refs at the given depth (≥1), without tags or
// submodules, then deletes every local ref under LocalPrefix not in refs.
func (r *Repo) Fetch(ctx context.Context, refs []FetchRef, depth int) error {
	if r.remote == "" {
		return errors.New("gitx: repo has no remote")
	}
	if depth < 1 {
		return errors.New("gitx: depth must be ≥1")
	}
	if len(refs) == 0 {
		return errors.New("gitx: nothing to fetch")
	}
	want := map[string]bool{}
	args := []string{"fetch", "--quiet", "--no-tags", "--no-recurse-submodules",
		"--no-write-fetch-head", "--depth=" + strconv.Itoa(depth), "--end-of-options", r.remote}
	for _, f := range refs {
		if !(strings.HasPrefix(f.Remote, "refs/heads/") || strings.HasPrefix(f.Remote, "refs/tags/")) ||
			!ValidRefName(f.Remote) || !strings.HasPrefix(f.Local, LocalPrefix) || !ValidRefName(f.Local) {
			return fmt.Errorf("gitx: refusing refspec %q:%q", f.Remote, f.Local)
		}
		want[f.Local] = true
		args = append(args, "+"+f.Remote+":"+f.Local)
	}
	if _, err := r.run(ctx, runOpts{remote: true}, args...); err != nil {
		return err
	}
	have, err := r.LocalRefs(ctx)
	if err != nil {
		return err
	}
	var del strings.Builder
	for _, l := range have {
		if !want[l.Name] {
			fmt.Fprintf(&del, "delete %s\x00\x00", l.Name)
		}
	}
	if del.Len() == 0 {
		return nil
	}
	_, err = r.run(ctx, runOpts{stdin: strings.NewReader(del.String())}, "update-ref", "--stdin", "-z")
	return err
}

// LocalRef is a ref under LocalPrefix.
type LocalRef struct {
	Name string
	OID  string
	Type string // commit, tag, tree, blob
}

// LocalRefs lists refs under LocalPrefix.
func (r *Repo) LocalRefs(ctx context.Context) ([]LocalRef, error) {
	out, err := r.run(ctx, runOpts{}, "for-each-ref", "--format=%(objectname)%00%(objecttype)%00%(refname)", LocalPrefix)
	if err != nil {
		return nil, err
	}
	var refs []LocalRef
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\x00")
		if len(f) != 3 || !ValidOID(f[0]) {
			return nil, errors.New("gitx: malformed for-each-ref line")
		}
		refs = append(refs, LocalRef{OID: f[0], Type: f[1], Name: f[2]})
	}
	return refs, nil
}

// Shallow returns the set of commits whose parents were not fetched.
func (r *Repo) Shallow() (map[string]bool, error) {
	data, err := os.ReadFile(filepath.Join(r.dir, "shallow"))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, l := range strings.Fields(string(data)) {
		if !ValidOID(l) {
			return nil, errors.New("gitx: malformed shallow file")
		}
		set[l] = true
	}
	return set, nil
}

// RevList returns up to max commits reachable from tip, newest first.
func (r *Repo) RevList(ctx context.Context, tip string, max int) ([]string, error) {
	if !ValidOID(tip) {
		return nil, errors.New("gitx: invalid oid")
	}
	if max <= 0 {
		return nil, nil
	}
	out, err := r.run(ctx, runOpts{}, "rev-list", "--max-count="+strconv.Itoa(max), "--end-of-options", tip)
	if err != nil {
		return nil, err
	}
	oids := strings.Fields(string(out))
	for _, o := range oids {
		if !ValidOID(o) {
			return nil, errors.New("gitx: malformed rev-list output")
		}
	}
	return oids, nil
}

// Object is a raw git object.
type Object struct {
	OID  string
	Type string
	Data []byte
}

// ObjectSizes returns the type and size of each object, in order, with
// cat-file --batch-check. Missing objects are an error.
func (r *Repo) ObjectSizes(ctx context.Context, oids []string) ([]ObjectInfo, error) {
	if len(oids) == 0 {
		return nil, nil
	}
	in, err := oidList(oids)
	if err != nil {
		return nil, err
	}
	check, err := r.run(ctx, runOpts{stdin: strings.NewReader(in)}, "cat-file", "--batch-check")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSuffix(string(check), "\n"), "\n")
	if len(lines) != len(oids) {
		return nil, errors.New("gitx: truncated cat-file --batch-check output")
	}
	infos := make([]ObjectInfo, len(oids))
	for i, line := range lines {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != oids[i] {
			return nil, fmt.Errorf("gitx: object %s missing or unreadable", oids[i])
		}
		n, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("gitx: object %s has a malformed size", oids[i])
		}
		infos[i] = ObjectInfo{OID: oids[i], Type: f[1], Size: n}
	}
	return infos, nil
}

// AllObjects lists every object in the repo (cat-file
// --batch-all-objects), for auditing a repo fpp built itself.
func (r *Repo) AllObjects(ctx context.Context) ([]ObjectInfo, error) {
	out, err := r.run(ctx, runOpts{}, "cat-file", "--batch-all-objects", "--batch-check", "--unordered")
	if err != nil {
		return nil, err
	}
	var infos []ObjectInfo
	for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 || !ValidOID(f[0]) {
			return nil, errors.New("gitx: malformed cat-file --batch-check output")
		}
		n, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil || n < 0 {
			return nil, errors.New("gitx: malformed object size")
		}
		infos = append(infos, ObjectInfo{OID: f[0], Type: f[1], Size: n})
	}
	return infos, nil
}

// ObjectInfo is an object's type and size.
type ObjectInfo struct {
	OID  string
	Type string
	Size int64
}

func oidList(oids []string) (string, error) {
	var in strings.Builder
	for _, o := range oids {
		if !ValidOID(o) {
			return "", errors.New("gitx: invalid oid")
		}
		in.WriteString(o + "\n")
	}
	return in.String(), nil
}

// ReadObjects reads objects with cat-file --batch. Each object must be at
// most maxSize bytes (checked before anything is buffered). Missing objects
// are an error. Callers bound the total by batching.
func (r *Repo) ReadObjects(ctx context.Context, oids []string, maxSize int64) ([]Object, error) {
	infos, err := r.ObjectSizes(ctx, oids)
	if err != nil || len(infos) == 0 {
		return nil, err
	}
	var total int64
	for _, in := range infos {
		if in.Size > maxSize {
			return nil, fmt.Errorf("gitx: object %s too large (%d bytes)", in.OID, in.Size)
		}
		total += in.Size + 128
	}
	in, _ := oidList(oids)
	out, err := r.run(ctx, runOpts{stdin: strings.NewReader(in), max: total + 1},
		"cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	objs := make([]Object, 0, len(oids))
	for _, want := range oids {
		nl := bytes.IndexByte(out, '\n')
		if nl < 0 {
			return nil, errors.New("gitx: truncated cat-file output")
		}
		f := strings.Fields(string(out[:nl]))
		if len(f) != 3 || f[0] != want {
			return nil, fmt.Errorf("gitx: object %s missing", want)
		}
		n, err := strconv.Atoi(f[2])
		if err != nil || n < 0 || nl+1+n+1 > len(out) || out[nl+1+n] != '\n' {
			return nil, errors.New("gitx: malformed cat-file output")
		}
		objs = append(objs, Object{OID: want, Type: f[1], Data: out[nl+1 : nl+1+n]})
		out = out[nl+1+n+1:]
	}
	return objs, nil
}

// TreeEntry is one ls-tree entry.
type TreeEntry struct {
	Mode string // 100644, 100755, 120000, 160000
	Type string // blob or commit (submodule)
	OID  string
	Size int64  // -1 for submodules
	Path []byte // raw bytes; callers validate
}

// LsTree lists every non-tree entry of commit recursively.
func (r *Repo) LsTree(ctx context.Context, commit string) ([]TreeEntry, error) {
	if !ValidOID(commit) {
		return nil, errors.New("gitx: invalid oid")
	}
	out, err := r.run(ctx, runOpts{}, "ls-tree", "-r", "-z", "-l", "--full-tree", "--end-of-options", commit)
	if err != nil {
		return nil, err
	}
	var entries []TreeEntry
	for _, rec := range bytes.Split(out, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		meta, path, ok := bytes.Cut(rec, []byte{'\t'})
		if !ok {
			return nil, errors.New("gitx: malformed ls-tree record")
		}
		f := strings.Fields(string(meta))
		if len(f) != 4 || !ValidOID(f[2]) {
			return nil, errors.New("gitx: malformed ls-tree record")
		}
		size := int64(-1)
		if f[3] != "-" {
			if size, err = strconv.ParseInt(f[3], 10, 64); err != nil || size < 0 {
				return nil, errors.New("gitx: malformed ls-tree size")
			}
		}
		entries = append(entries, TreeEntry{Mode: f[0], Type: f[1], OID: f[2], Size: size, Path: path})
	}
	return entries, nil
}

// Change is one file changed by a commit (first-parent, no rename detection).
type Change struct {
	Status  byte // A, M, D, T
	Path    []byte
	OldMode string // 000000 when added
	NewMode string // 000000 when deleted
	OldOID  string // all zeros when added
	NewOID  string // all zeros when deleted
	Added   int    // -1 for binary
	Deleted int
}

// DiffTree lists the files changed between parent and commit. An empty
// parent means a root commit (everything added).
func (r *Repo) DiffTree(ctx context.Context, parent, commit string) ([]Change, error) {
	if !ValidOID(commit) || (parent != "" && !ValidOID(parent)) {
		return nil, errors.New("gitx: invalid oid")
	}
	args := []string{"diff-tree", "-r", "-z", "--no-commit-id", "--no-renames", "--no-ext-diff", "--no-textconv",
		"--raw", "--numstat"}
	if parent == "" {
		args = append(args, "--root", "--end-of-options", commit)
	} else {
		args = append(args, "--end-of-options", parent, commit)
	}
	out, err := r.run(ctx, runOpts{}, args...)
	if err != nil {
		return nil, err
	}
	return parseDiffTree(out)
}

func parseDiffTree(out []byte) ([]Change, error) {
	toks := bytes.Split(out, []byte{0})
	var changes []Change
	idx := map[string]int{}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if len(t) == 0 {
			continue
		}
		if t[0] == ':' {
			f := strings.Fields(string(t))
			if len(f) != 5 || len(f[4]) == 0 || i+1 >= len(toks) || !ValidOID(f[2]) || !ValidOID(f[3]) {
				return nil, errors.New("gitx: malformed diff-tree raw record")
			}
			i++
			p := toks[i]
			idx[string(p)] = len(changes)
			changes = append(changes, Change{Status: f[4][0], Path: p,
				OldMode: f[0][1:], NewMode: f[1], OldOID: f[2], NewOID: f[3]})
			continue
		}
		parts := bytes.SplitN(t, []byte{'\t'}, 3)
		if len(parts) != 3 {
			return nil, errors.New("gitx: malformed diff-tree numstat record")
		}
		j, ok := idx[string(parts[2])]
		if !ok {
			return nil, errors.New("gitx: numstat for unknown path")
		}
		if string(parts[0]) == "-" {
			changes[j].Added, changes[j].Deleted = -1, -1
			continue
		}
		a, err1 := strconv.Atoi(string(parts[0]))
		d, err2 := strconv.Atoi(string(parts[1]))
		if err1 != nil || err2 != nil {
			return nil, errors.New("gitx: malformed numstat counts")
		}
		changes[j].Added, changes[j].Deleted = a, d
	}
	return changes, nil
}

// ValidRefName is a conservative subset of git check-ref-format for full
// ref names (refs/...).
func ValidRefName(s string) bool {
	if !strings.HasPrefix(s, "refs/") || len(s) > 255 || strings.HasSuffix(s, "/") ||
		strings.HasSuffix(s, ".") || strings.HasSuffix(s, ".lock") || strings.Contains(s, "..") ||
		strings.Contains(s, "//") || strings.Contains(s, "@{") {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f || strings.ContainsRune(" ~^:?*[\\", c) {
			return false
		}
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "" || strings.HasPrefix(seg, ".") || strings.HasPrefix(seg, "-") {
			return false
		}
	}
	return true
}
