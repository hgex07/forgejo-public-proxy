# Roadmap

fpp works end to end today: `plan`, `preview`, the gates, the output lint, `apply` and
the SSH deploy. What's left, roughly in order:

## Before 1.0

- **Launch checks.** An OWASP ZAP baseline scan and an external header scan of a live
  site, plus rollback and unpublish drills following [docs/RUNBOOK.md](docs/RUNBOOK.md).
- **Themes and customization.** A few palettes that pass WCAG AA contrast in light and
  dark, selected with `site.theme` (the key is reserved today), and more control over
  the site's look.
- **Stable config and URLs.** Until 1.0, config keys and the URL scheme may still change.

## Later

Each of these will be opt-in, never on by default.

- Instant builds from a Forgejo webhook instead of waiting for the timer.
- Atom feeds for releases and commits.
- Git LFS content, with a size cap.
- Release asset mirroring (today releases list their assets but don't serve them).
- A separate hostname for raw files.
- Per-repo isolation: a repo that fails its gates keeps its last good build while the
  others still update.
- Clone history: replay the published commit window as real commits in the clone
  snapshot, instead of one snapshot commit per branch or tag.
