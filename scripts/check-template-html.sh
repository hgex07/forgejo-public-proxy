#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# template.HTML (and its siblings that bypass html/template
# escaping) may appear only in internal/render/safe.go.
set -euo pipefail
cd "$(dirname "$0")/.."
# Only tracked and new (not ignored) Go files: local/ holds rendered sites
# that contain this repo's own source.
hits="$(git ls-files -z --cached --others --exclude-standard -- '*.go' \
  | xargs -0 -r grep -nE 'template\.(HTML|HTMLAttr|JS|JSStr|CSS|URL|Srcset)\b' \
  | grep -v '^internal/render/safe\.go:' | grep -v '_test\.go:' || true)"
if [[ -n "$hits" ]]; then
  echo "template escaping bypass outside internal/render/safe.go:" >&2
  echo "$hits" >&2
  exit 1
fi
echo "template.HTML rule: OK"
