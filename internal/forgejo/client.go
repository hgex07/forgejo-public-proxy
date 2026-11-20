// SPDX-License-Identifier: AGPL-3.0-or-later

// Package forgejo is a minimal, read-only Forgejo API client. It implements
// only the calls the builder needs: repo info, releases,
// repo search (drift check) and access probes (canaries, push).
//
// Responses are decoded into narrow structs, so fields the builder must never
// carry (author emails, internal URLs, permissions) are dropped at the edge.
package forgejo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MaxResponseBytes bounds every response body.
const MaxResponseBytes = 16 << 20

const (
	pageSize = 50
	maxPages = 100
)

// Client talks to one Forgejo instance as one user.
type Client struct {
	base  *url.URL
	user  string
	token string
	http  *http.Client
}

// New returns a client for the instance at baseURL (Forgejo's root, without
// /api/v1). Redirects are never followed, so the token cannot be forwarded.
func New(baseURL, user, token string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, errors.New("forgejo: invalid base URL")
	}
	return &Client{
		base:  u,
		user:  user,
		token: token,
		http: &http.Client{
			Timeout: 60 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// StatusError is a non-2xx API response.
type StatusError struct {
	Path string
	Code int
}

func (e *StatusError) Error() string { return fmt.Sprintf("forgejo: GET %s: HTTP %d", e.Path, e.Code) }

// IsNotFound reports whether err is a 404 (Forgejo also uses it for "no access").
func IsNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusNotFound
}

// GitURL is the git-over-HTTP URL of repo ("owner/name").
func (c *Client) GitURL(repo string) string {
	return c.base.String() + "/" + escapeRepo(repo) + ".git"
}

// BasicAuthHeader is the header value git uses to authenticate (verified to
// work with read:repository tokens by scripts/verify-forgejo-access.sh).
func (c *Client) BasicAuthHeader() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.user+":"+c.token))
}

func escapeRepo(repo string) string {
	owner, name, _ := strings.Cut(repo, "/")
	return url.PathEscape(owner) + "/" + url.PathEscape(name)
}

// get performs an authenticated GET and returns the status and body.
func (c *Client) get(ctx context.Context, rawPath string, query url.Values, auth string) (int, []byte, error) {
	u, err := url.Parse(c.base.String() + rawPath)
	if err != nil {
		return 0, nil, err
	}
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "fpp")
	resp, err := c.http.Do(req)
	if err != nil {
		// url.Error includes the URL only; the token lives in a header.
		return 0, nil, fmt.Errorf("forgejo: GET %s: %w", rawPath, unwrapURLError(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return 0, nil, fmt.Errorf("forgejo: GET %s: %w", rawPath, err)
	}
	if len(body) > MaxResponseBytes {
		return 0, nil, fmt.Errorf("forgejo: GET %s: response larger than %d bytes", rawPath, MaxResponseBytes)
	}
	return resp.StatusCode, body, nil
}

func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func (c *Client) api(ctx context.Context, path string, query url.Values, out any) error {
	code, body, err := c.get(ctx, "/api/v1"+path, query, "token "+c.token)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return &StatusError{Path: path, Code: code}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("forgejo: GET %s: decode: %w", path, err)
	}
	return nil
}

// Version returns the server version string.
func (c *Client) Version(ctx context.Context) (string, error) {
	var v struct {
		Version string `json:"version"`
	}
	err := c.api(ctx, "/version", nil, &v)
	return v.Version, err
}

// Repo is the subset of repository metadata the builder publishes or needs.
type Repo struct {
	FullName      string    `json:"full_name"`
	Description   string    `json:"description"`
	Website       string    `json:"website"`
	Topics        []string  `json:"topics"`
	DefaultBranch string    `json:"default_branch"`
	Archived      bool      `json:"archived"`
	Empty         bool      `json:"empty"`
	ObjectFormat  string    `json:"object_format_name"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Repo fetches repo ("owner/name").
func (c *Client) Repo(ctx context.Context, repo string) (*Repo, error) {
	var r Repo
	if err := c.api(ctx, "/repos/"+escapeRepo(repo), nil, &r); err != nil {
		return nil, err
	}
	if !strings.EqualFold(r.FullName, repo) {
		return nil, fmt.Errorf("forgejo: asked for %s, got %s (renamed or redirected?)", repo, r.FullName)
	}
	return &r, nil
}

// Release is a published release. Author fields are deliberately absent.
type Release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []Asset   `json:"assets"`
}

// Asset is a release attachment.
type Asset struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// Releases lists repo's releases, newest first, excluding drafts.
func (c *Client) Releases(ctx context.Context, repo string) ([]Release, error) {
	var all []Release
	for page := 1; page <= maxPages; page++ {
		var batch []Release
		q := url.Values{"limit": {fmt.Sprint(pageSize)}, "page": {fmt.Sprint(page)}, "draft": {"false"}}
		if err := c.api(ctx, "/repos/"+escapeRepo(repo)+"/releases", q, &batch); err != nil {
			return nil, err
		}
		for _, r := range batch {
			if !r.Draft {
				all = append(all, r)
			}
		}
		if len(batch) < pageSize {
			return all, nil
		}
	}
	return nil, fmt.Errorf("forgejo: %s has more than %d releases", repo, pageSize*maxPages)
}

// VisibleRepos lists every repo the token can see (drift check).
func (c *Client) VisibleRepos(ctx context.Context) ([]string, error) {
	var all []string
	for page := 1; page <= maxPages; page++ {
		var res struct {
			OK   bool `json:"ok"`
			Data []struct {
				FullName string `json:"full_name"`
			} `json:"data"`
		}
		q := url.Values{"limit": {fmt.Sprint(pageSize)}, "page": {fmt.Sprint(page)}}
		if err := c.api(ctx, "/repos/search", q, &res); err != nil {
			return nil, err
		}
		if !res.OK {
			return nil, errors.New("forgejo: repos/search returned ok=false")
		}
		for _, r := range res.Data {
			all = append(all, r.FullName)
		}
		if len(res.Data) < pageSize {
			return all, nil
		}
	}
	return nil, fmt.Errorf("forgejo: more than %d visible repos", pageSize*maxPages)
}

// ProbeHidden returns nil only if the API definitively refuses repo
// (401/403/404). A 200 or any other outcome is an error: fail closed.
func (c *Client) ProbeHidden(ctx context.Context, repo string) error {
	code, _, err := c.get(ctx, "/api/v1/repos/"+escapeRepo(repo), nil, "token "+c.token)
	if err != nil {
		return err
	}
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return nil
	case http.StatusOK:
		return fmt.Errorf("canary %s is READABLE through the API", repo)
	default:
		return fmt.Errorf("canary %s: unexpected HTTP %d", repo, code)
	}
}

// ProbeNoPush returns nil only if the push handshake for repo is refused.
// The request is the first one `git push` sends and changes nothing.
func (c *Client) ProbeNoPush(ctx context.Context, repo string) error {
	q := url.Values{"service": {"git-receive-pack"}}
	code, _, err := c.get(ctx, "/"+escapeRepo(repo)+".git/info/refs", q, c.BasicAuthHeader())
	if err != nil {
		return err
	}
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	case http.StatusOK:
		return fmt.Errorf("token can PUSH to %s", repo)
	default:
		return fmt.Errorf("push probe on %s: unexpected HTTP %d", repo, code)
	}
}

// ProbeNoUser reports whether /user is denied (token lacks read:user).
func (c *Client) ProbeNoUser(ctx context.Context) (bool, error) {
	code, _, err := c.get(ctx, "/api/v1/user", nil, "token "+c.token)
	if err != nil {
		return false, err
	}
	return code == http.StatusUnauthorized || code == http.StatusForbidden, nil
}
