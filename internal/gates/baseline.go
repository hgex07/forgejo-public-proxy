// SPDX-License-Identifier: AGPL-3.0-or-later

package gates

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Baseline lists reviewed secret-scan false positives. Only secret-scan
// findings can be baselined; the token, the Forgejo host names and block
// leak_patterns can't (decided 2026-11-13: no exceptions).
//
//	{"ignore": [{"fingerprint": "1a2b3c4d5e6f7a8b", "reason": "test key in fixtures"}]}
type Baseline struct {
	Ignore []BaselineEntry `json:"ignore"`
}

// BaselineEntry is one reviewed finding.
type BaselineEntry struct {
	Fingerprint string `json:"fingerprint"`
	Reason      string `json:"reason"`
}

const maxBaselineBytes = 1 << 20

// LoadBaseline reads a baseline file strictly. An empty path is an empty
// baseline; a configured path that does not exist is an error.
func LoadBaseline(path string) (map[string]string, error) {
	out := map[string]string{}
	if path == "" {
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("secret scan baseline: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBaselineBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBaselineBytes {
		return nil, fmt.Errorf("secret scan baseline: larger than %d bytes", maxBaselineBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var b Baseline
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("secret scan baseline %s: %w", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("secret scan baseline %s: trailing data", path)
	}
	for i, e := range b.Ignore {
		if len(e.Fingerprint) != fingerprintLen || strings.Trim(e.Fingerprint, "0123456789abcdef") != "" {
			return nil, fmt.Errorf("secret scan baseline %s: ignore[%d]: fingerprint must be %d lowercase hex chars", path, i, fingerprintLen)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return nil, fmt.Errorf("secret scan baseline %s: ignore[%d]: reason is required", path, i)
		}
		out[e.Fingerprint] = e.Reason
	}
	return out, nil
}
