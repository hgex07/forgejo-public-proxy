# Threat model

This is the threat model for fpp, kept current with the code. Each invariant names the
code or test that enforces it. "Operator" means fpp can't enforce it and it depends on
how you deploy.

It assumes the recommended deployment: the builder (fpp) runs in the LAN next to
Forgejo, and a separate web host in an isolated network (a DMZ) serves the static site
through a CDN or tunnel. The DMZ setup itself is not part of this repo.

## What we protect

| Asset | Where it lives | Why it matters |
|---|---|---|
| Unpublished repos, branches, history | Forgejo | The whole point: only what's allowlisted becomes public |
| Secrets inside published repos | Forgejo, builder | One leaked key outlives any unpublish; assume scraping within minutes |
| Bot token (`read:repository`, repository access All; reach is limited by the Restricted flag and per-repo grants) | Builder (systemd credential) | Reads every repo the bot is granted; with a bad grant, more |
| Deploy SSH key | Builder (systemd credential) | Write access to the web host's upload area only |
| Tunnel credential | Web host | Lets its holder serve content on the public hostname |
| LAN | Everything behind the DMZ | The DMZ must be a dead end |
| Metadata: emails, hostnames, IPs, timezones | Commits, READMEs, messages | Low value one at a time, high value to a profiler |

## Trust boundaries

1. **Internet → CDN/tunnel → web host.** Untrusted requests. Only GET/HEAD reach stock
   Caddy, which serves static files. No request is ever forwarded further.
2. **Web host → LAN.** Denied by the operator's firewall (ideally on the hypervisor or
   router and on the host itself). Only the LAN can start connections into the DMZ
   (rsync over SSH from the builder).
3. **Builder ↔ Forgejo.** The builder runs as its own user, possibly on Forgejo's host.
   It uses only the HTTP API and git-over-HTTP with its token, never the on-disk repos.
4. **Repo content → builder.** Repo contents are **hostile input**, because anyone with
   push access to a published repo controls them. They are parsed, never executed, and
   they can't change what gets published.
5. **Config → builder.** Trusted, but treated as error-prone: it is strictly validated and
   its defaults are secure.

## Attackers considered

- **Anonymous internet user / scraper**: reads everything public, probes for anything else,
  tries injection through crafted URLs.
- **Contributor to a published repo** (or a compromised account): plants XSS, path tricks,
  symlinks, huge files or `export-subst` payloads, and tries to exfiltrate through the
  builder.
- **Compromised web host**: tries to pivot to the LAN or read builder secrets.
- **Operator mistake**: typo in an allowlist, over-broad grant, forgotten `.env`.

Out of scope: a compromised Forgejo host or hypervisor, and the CDN itself (it sees
plaintext, which is acceptable because the content is public by intent).

## Invariants and enforcement

| # | Invariant | Enforced by | Status |
|---|---|---|---|
| I1 | No internet request causes a request to Forgejo or the LAN | fpp's output is static files only, and `fpp caddy-site` generates a `file_server` config with no proxying. The isolation of the web host is up to the operator | operator. Check that the web host can't reach the LAN after every network change (docs/RUNBOOK.md) |
| I2 | Web host holds no Forgejo credential | Push model: the builder rsyncs a finished site, the web host never connects inward; gates and output lint block the token value anywhere (`internal/gates`, `internal/lint`) | done |
| I3 | Published = allowlist ∩ bot access ∩ token scope | Restricted bot + scoped token (`scripts/verify-forgejo-access.sh`); canaries on every run; config rejects canaries in the allowlist (`internal/config`) | partial |
| I4 | Only allowlisted refs and windowed commits published | Shallow named-ref fetch; policy choke point; config caps `max_commits` ≤1000 and requires `tags.latest` ≥1 | partial |
| I5 | No emails, internal URLs, hostnames or token in output | Model never carries author emails; email redaction of messages, trailers and notes; Forgejo host names block with no exceptions; leak patterns; output lint over pages, archives and clone objects; config forbids `base_url` == Forgejo host | done (tests: `internal/gates`, `internal/lint`) |
| I6 | Repo content never served as active content | Sanitizer, `html/template`, CSP without `script-src`, raw/media/dl split; `scripts/check-template-html.sh`; output lint rejects every `<script>`, handlers, `style=`, dangerous URLs; `fpp caddy-site` generates the production headers and `fpp check-contract` verifies them, including non-canonical URL spellings | done. Operator check: `check-contract` after any fpp or Caddy change |
| I7 | Publishing fails closed | `fpp apply` stops at any gate finding, lint problem or error before deploying; the web host should validate every upload and keep the old release on rejection (operator); the published manifest only changes after an upload. The builder can't see a host-side rejection: `/build.txt` shows what is live (docs/RUNBOOK.md) | done. Operator check: `/build.txt` after an unpublish |
| I8 | New repo publication needs a human | `fpp apply -auto` refuses repos missing from the published manifest | done |

### Config-level guarantees (`internal/config`)

- Unknown keys, duplicate keys and extra YAML documents are errors; files over 1 MiB are rejected.
- The token and deploy key can only be referenced by systemd credential name. An inline
  secret fails to decode, and a path is rejected.
- URLs must not carry credentials, queries or fragments. `site.base_url` must be https and
  must not be the Forgejo host.
- The built-in exclude denylist always applies. Config can add to it but not remove from it.
- Owner, repo and slug segments can't be `.`/`..`, start with `-` or `.`, or end in `.git`.
  Slug owners can't shadow site paths (`_…`, `robots.txt`, …), and slugs must be unique
  case-insensitively.
- Branch names are checked against a conservative subset of `git check-ref-format`.
  Names that aren't URL-safe need an explicit public alias.
- Diffs can't be enabled while secret scanning is off. Turning off secret scanning,
  having a single canary, or enabling releases or external images produces a warning.

## Residual risks (accepted)

- A secret committed to a published branch is public within one build cycle if the
  scanner misses it. Mitigations: diffs off by default, a reviewed baseline, and the
  rotate-first runbook (docs/RUNBOOK.md).
- When the builder runs on Forgejo's host, a builder RCE runs as `fpp` beside Forgejo,
  limited by the systemd sandbox (docs/SETUP.md §7).
- The tunnel credential on the web host can be stolen if the host is compromised.
  Mitigations: rotation and the provider's tunnel-health alerts.
