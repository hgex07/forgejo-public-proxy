// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"path"
	"strings"

	"github.com/google/licensecheck"
)

// IsLicenseFile reports whether a root-level file name looks like a license.
func IsLicenseFile(name string) bool {
	if strings.Contains(name, "/") {
		return false
	}
	base := strings.ToUpper(strings.TrimSuffix(name, path.Ext(name)))
	switch base {
	case "LICENSE", "LICENCE", "COPYING", "UNLICENSE", "LICENSE-MIT", "LICENSE-APACHE":
		return true
	}
	return false
}

// DetectLicense returns the SPDX id of the license text, or "" if no single
// license covers most of it.
func DetectLicense(text string) string {
	cov := licensecheck.Scan([]byte(text))
	if cov.Percent < 75 || len(cov.Match) == 0 {
		return ""
	}
	id := cov.Match[0].ID
	for _, m := range cov.Match[1:] {
		if m.ID != id {
			return ""
		}
	}
	return id
}
