# fpp: forgejo-public-proxy

<p align="center"><img src="docs/logo.svg" alt="fpp logo, the Forgejo logo on a shield" width="200"></p>

**Publish selected repositories from a private Forgejo as a static, read-only website, without exposing Forgejo to the internet.**

fpp runs next to your Forgejo instance. It reads only the repos, branches and tags you
allowlist and checks every byte it is about to publish for secrets and internal names.
It then renders a GitHub-style site made of plain static files that you can serve from
anywhere. Visitors never talk to Forgejo, and the web server needs no Forgejo
credentials.

Inspired by [stagit](https://codemadness.org/git/stagit/), which generates static HTML
pages for git repositories, and by
[immich-public-proxy](https://github.com/alangrainger/immich-public-proxy), which shares
Immich albums and photos without exposing Immich.

## Features

- **Code browser:** repo list, file tree, file view with syntax highlighting, rendered
  READMEs (sanitized Markdown), recent commits, optional diffs, branches, tags,
  releases, and `.zip`/`.tar.gz` source archives.
- **`git clone` works** against the static site. Each published repo gets a snapshot
  clone with one commit per published branch or tag, containing published files only.
- **No JavaScript, no cookies, no forms.** Every page is pre-rendered. The site ships a
  strict CSP and a fixed set of security headers (the "header contract").
- **English or Spanish** interface. Translations into other languages are welcome
  (`internal/site/i18n.go`).
- **Small public footprint by design.** Issues, pull requests, wikis, user profiles,
  blame and arbitrary-commit browsing are not published at all, and history beyond the
  configured window never leaves the builder. Features added later will be opt-in, never
  on by default.

## What keeps private data private

fpp is built to fail closed. A config typo, a forgotten `.env` or a key in an old
commit should stop the publish, not reach the web.

- **Allowlist only.** Repos, refs and history depth are opt-in per repo. A built-in
  denylist drops `.env*`, private keys, `*.pem` and similar files whatever the config says.
- **Least-privilege token, checked on every run.** The Forgejo bot is a Restricted
  user with a `read:repository` token. Each run proves that two canary repos are
  invisible to it (over the API and over git) and that it cannot push, or aborts.
- **Safety gates on the exact publish set.** Files, paths, both sides of published diffs,
  commit and tag messages, author names and release notes are all scanned:
  - email addresses are redacted;
  - [gitleaks](https://github.com/gitleaks/gitleaks) runs in-process; `gitleaks:allow`
    comments and path-based exemptions are ignored;
  - the Forgejo token and your Forgejo host names block the publish wherever they appear;
  - your own `leak_patterns` (internal domains, LAN ranges…) block or warn.
- **Output lint.** After rendering, fpp checks the finished site again, including
  archive contents and every object in the clone repos.
- **New repos need a human.** Scheduled runs (`apply -auto`) refuse a repo that was
  never published, or a public name that now points at a different source repo.
- **Static output.** The public side is just files. There is no fpp code, token or
  database on the web server to attack.

## Quick start

You need Go 1.27.4 or newer, git, and a Forgejo instance where you can create users.
Deploying with `fpp apply` also needs rsync and ssh.

**1. Build**

```sh
make build                       # → bin/fpp (static binary)
```

**2. Create the Forgejo bot.** Make a Restricted local user, grant it Read on the repos
you want to publish, and give it a `read:repository` token. Also create two canary repos
it is never granted. [docs/SETUP.md](docs/SETUP.md#1-forgejo-bot-and-token) has the
details and a script that verifies the setup.

**3. Store the token.** fpp never reads secrets from flags, the config or plain
environment variables, only from a credentials directory (the layout systemd's
`LoadCredential=` uses):

```sh
install -d -m 700 ~/.config/fpp/creds
install -m 600 /dev/stdin ~/.config/fpp/creds/forgejo-token   # paste the token, then Ctrl-D
```

**4. Configure**

```sh
cp deploy/builder/config.example.yaml config.yaml   # edit site, forgejo, publish.repos
bin/fpp check-config -config config.yaml
```

```yaml
publish:
  repos:
    - source: "me/dotfiles"                 # defaults: default branch, last 10 commits
    - source: "infra/homelab-scripts"
      slug: "tools/homelab"                 # public name, hides the internal one
      tags: { include: ["v*"], latest: 3 }
      releases: { enabled: true }
```

**5. Plan and preview**

```sh
export CREDENTIALS_DIRECTORY=~/.config/fpp/creds
bin/fpp plan    -config config.yaml -state ./state   # exposure report + gate findings
bin/fpp preview -config config.yaml -state ./state   # site at http://127.0.0.1:8080/
```

The exposure report lists every repo, ref and file that would become public,
everything left out and why, and what changed since the last publish. Read it before
your first apply.

**6. Deploy.** `fpp apply -no-deploy` runs every check and leaves the verified site in
`<state>/staging/site/`. Copy that directory to any static web server. With a `deploy`
section in the config, `fpp apply` uploads it for you with rsync over SSH; the web host
then has to activate the upload ([docs/SETUP.md](docs/SETUP.md#6-deploy) describes what
it receives). Whatever serves the site should send the security headers fpp expects:
`fpp caddy-site` prints them as a Caddy config, and `fpp check-contract` tests a running
server.

*Recommended setup:* run fpp next to Forgejo on a timer (`fpp apply -auto`), and serve the
site from a separate host that has no route back into your LAN, exposed through a
Cloudflare tunnel or something similar.

## Commands

| Command | What it does |
|---|---|
| `check-config` | Strictly validate the config (unknown keys are errors). No network access. `-print` shows the effective per-repo exposure policy; `-strict` treats warnings as errors. |
| `plan` | Access checks, fetch, policy and gates. Prints the exposure report; exits 1 if anything blocks. |
| `preview` | `plan`, then render, lint and serve on loopback with the production headers. |
| `apply` | `plan`, render, lint and deploy. Fails closed. `-auto` for timers, `-no-deploy` to stop after the lint. |
| `unpublish <slug>` | Rebuild and deploy without one repo (emergency removal). |
| `caddy-site` | Print a Caddy site block implementing the header contract. |
| `check-contract` | Check a running server against the header contract. |

Run `fpp <command> -h` for flags.

## Documentation

| Document | Contents |
|---|---|
| [docs/SETUP.md](docs/SETUP.md) | Bot and token, credentials, first plan, preview, gates and baselines, deploy, timer |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | What is live, removing something published by mistake, rollback, rotation |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, trust boundaries, attackers, invariants, accepted risks |
| [config.example.yaml](deploy/builder/config.example.yaml) | Every config option, commented |
| [ROADMAP.md](ROADMAP.md) | What's next before 1.0 and after |

## Status

Early, but working end to end in one homelab: [fpp.hgepro.me](https://fpp.hgepro.me)
is a live site with a couple of repos. Not done yet: more themes and customization, and
the launch checks. [ROADMAP.md](ROADMAP.md) has the details. Expect config and URL
changes before 1.0.

## FAQ

- **Why would I use this?**

  You self-host Forgejo and keep it off the internet, but still want to show some of
  your code (a portfolio, a few tools, your dotfiles). Mirroring to GitHub or a similar
  platform hands your code to someone else, which is what you self-host to avoid.
  Opening Forgejo to the internet exposes a large web app, its login page and
  everything a misconfigured permission lets through. fpp publishes exactly what you
  list and nothing else, as static files.

- **Why would I use this over stagit and similar tools?**

  stagit and its relatives generate static pages from repositories you point them at,
  and they do that well. fpp is for when your repos live in a Forgejo you keep off the
  internet and you want to publish a selection of them. Those repos can be private or
  public in Forgejo: fpp only sees what you grant its bot. Most of what it adds is about
  deciding what is safe to publish:

  - It reads through a Restricted Forgejo bot with a read-only token and an allowlist,
    and proves on every run that canary repos are out of reach. It never touches the
    repos on disk.
  - It publishes a window of history (the last 10 commits by default), not the whole
    log. Anything outside the window never leaves the builder.
  - It scans everything it is about to publish for secrets, emails and internal host
    names, and refuses to publish if it finds something.
  - It serves the site with a fixed header contract and sanitizes Markdown, and the
    `git clone` snapshot works over plain static files.

  If you just want static pages for local repos and don't need any of that, stagit is
  simpler and a better fit.

- **Was AI used to build it?**

  Yes. All the code was written by LLMs, under human direction and strict security
  guidelines. That is also why the next question matters.

- **Why would I trust this?**

  You shouldn't take it on faith, and you don't have to:

  - The design limits the damage a bug can do. The public side is static files with no
    code or credentials behind it, and anything fpp did not fetch cannot be published.
  - Every run fails closed. Canary repos, a push probe, secret scanning and an output
    lint must all pass before anything is written.
  - `fpp plan` shows you, file by file, what would become public before you publish,
    and `fpp preview` lets you browse the result locally.
  - The tests cover hostile input (planted secrets, bidi tricks, path traversal,
    symlinks) and fuzz the parsers, sanitizer and redactor. An automated security
    review before the public release found a few gaps, which are fixed.
  - It is relatively small, readable Go. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
    lists what it defends against and the risks it accepts.

  Start with a test repo, read the exposure report, and decide for yourself.

## Development

```sh
make ci       # vet, gofmt, staticcheck, template.HTML check, tests (-race), govulncheck, example config
make test     # tests only
make fuzz     # 30 s each: config parser, git object parsers, Markdown sanitizer, email redactor
```

## License

Copyright (C) 2026 hgex07

fpp is free software: you can redistribute it and/or modify it under the terms of the
GNU Affero General Public License as published by the Free Software Foundation, either
version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE).

The license covers fpp itself. A site rendered by fpp contains your repositories'
content, which keeps its own licenses.

The [logo](docs/logo.svg) is based on the [Forgejo](https://forgejo.org) logo by Caesar
Schinas, used under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). The
fpp logo is licensed under CC BY-SA 4.0 as well.
