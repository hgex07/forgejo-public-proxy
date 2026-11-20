// SPDX-License-Identifier: AGPL-3.0-or-later

package testutil

import (
	"context"
	"encoding/base64"

	"fpp/internal/forgejo"
)

// FakeAPI is a policy.API backed by a GitServer, with canned repo metadata
// and releases. Every access probe passes.
type FakeAPI struct {
	Srv         *GitServer
	Repos       map[string]*forgejo.Repo
	ReleaseList map[string][]forgejo.Release
}

func (f *FakeAPI) Repo(_ context.Context, repo string) (*forgejo.Repo, error) {
	if r, ok := f.Repos[repo]; ok {
		return r, nil
	}
	return nil, &forgejo.StatusError{Path: repo, Code: 404}
}
func (f *FakeAPI) Releases(_ context.Context, repo string) ([]forgejo.Release, error) {
	return f.ReleaseList[repo], nil
}
func (f *FakeAPI) VisibleRepos(context.Context) ([]string, error) {
	var out []string
	for r := range f.Repos {
		out = append(out, r)
	}
	return out, nil
}
func (f *FakeAPI) ProbeHidden(context.Context, string) error { return nil }
func (f *FakeAPI) ProbeNoPush(context.Context, string) error { return nil }
func (f *FakeAPI) ProbeNoUser(context.Context) (bool, error) { return true, nil }
func (f *FakeAPI) GitURL(repo string) string                 { return f.Srv.RepoURL(repo) }
func (f *FakeAPI) BasicAuthHeader() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(f.Srv.User+":"+f.Srv.Pass))
}
