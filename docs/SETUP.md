# Setup

## 1. Forgejo bot and token

1. Create a local user for the bot, tick **Restricted**, and give it a long random password.
2. Grant it **Read** on each repo you publish (collaborator, or a team with only the Code unit).
3. Create its token: repository access **All**, scope **`read:repository`** only.
   The Restricted flag and the per-repo grants limit what it can actually read.
4. Create two canaries the bot is never granted: one private and one public repo.
5. Run the probe script from where the builder will run. Every check must PASS:

   ```sh
   FORGEJO_URL=http://127.0.0.1:3000 BOT_USER=<bot> \
   ALLOWED_REPOS="owner/repo ..." \
   CANARY_PRIVATE=owner/canary-private CANARY_PUBLIC=owner/canary-public \
   TOKEN_FILE=/path/to/token ./scripts/verify-forgejo-access.sh
   ```

   Re-run it after Forgejo upgrades and after any change to the bot's grants.
   `fpp plan` repeats the canary and push checks on every run anyway, and aborts if
   any of them fails.

## 2. Credentials

`fpp` never takes secrets from argv, the config or plain environment variables. It reads
`$CREDENTIALS_DIRECTORY/<name>`, where `<name>` is the `credential:` value in the config
(`forgejo.token`, `deploy.ssh_key`).

- **Under systemd:** `LoadCredential=forgejo-token:/etc/fpp/credentials/forgejo-token` (and
  `LoadCredential=deploy-key:…` if you deploy with fpp) sets this up; see the unit in
  [section 7](#7-run-it-on-a-timer).
- **Anywhere else** (a dev shell, a CI runner): use a 0700 directory with one 0600 file per
  credential. `fpp` refuses symlinks and files readable by group or others.

```sh
install -d -m 700 ~/.config/fpp/creds
install -m 600 /dev/stdin ~/.config/fpp/creds/forgejo-token   # paste the token, then Ctrl-D
```

## 3. First plan

```sh
make build
CREDENTIALS_DIRECTORY=~/.config/fpp/creds \
  bin/fpp plan -config /etc/fpp/config.yaml -state /var/lib/fpp
```

`/etc/fpp/config.yaml` and `/var/lib/fpp` are the defaults (`$STATE_DIRECTORY` overrides
the latter under systemd), so `-config` and `-state` can be left out when you use them.
The examples below spell them out.

`plan` changes nothing outside the state directory. It:

1. runs the access checks: canaries hidden over the API and over git, push denied,
   `/user` denied, and a drift warning for any repo the bot can see that isn't
   allowlisted;
2. shallow-fetches only the configured refs into bare repos under `<state>/git/`;
3. builds the publish set and prints the exposure report: refs, file and commit
   counts, and everything **not** published with the reason (excluded, too large,
   invalid path, missing ref…);
4. diffs the result against `<state>/published/manifest.json`, the last applied
   manifest, and lists the paths that would become public.

Flags: `-v` lists every path and skipped item, and `-manifest-out FILE` saves the
planned manifest.

## 4. Preview the site

```sh
CREDENTIALS_DIRECTORY=~/.config/fpp/creds \
  bin/fpp preview -config /etc/fpp/config.yaml -state /var/lib/fpp
```

`preview` runs the same steps as `plan`, renders the site into `<state>/preview/` and
serves it on `http://127.0.0.1:8080/` with the headers production will send (CSP,
`nosniff`, forced `text/plain` for `raw/`, attachments for `dl/` and `archive/`, 405 for
anything but GET/HEAD). Only loopback addresses are accepted.

- `-out DIR` builds somewhere else. fpp only replaces a directory it created itself
  (it contains `.fpp-site`); anything else is refused.
- `-build-only` renders and exits; `-site DIR` serves an existing build.
- Set `site.language: es` for a Spanish interface.
- Clone from the preview with `git clone http://127.0.0.1:8080/<owner>/<repo>.git` (the
  page shows the production `base_url`). Snapshot repos are built under `<state>/clone/`.
- `preview` stops if the gates block or the output lint fails. `-ignore-gates` builds
  and serves anyway, for looking at the problem locally; never share such a build.

## 5. Gates and apply

`plan`, `preview` and `apply` all run the gates (`== Gates` in the report):

- **Email redaction** in commit and tag messages, trailers (`Co-authored-by`,
  `Signed-off-by`…), author names, release notes and repo metadata: `Name <a@b.c>`
  becomes `Name`, a bare address becomes `[email]`. Addresses listed in
  `gates.public_emails` stay.
- **Blocking, no exceptions:** the token value and the Forgejo host names (from
  `root_url` and `api_url`, except loopback) anywhere in published content, paths or
  messages; and any `leak_patterns` entry with `action: block`. Fix the content or
  exclude the path.
- **Secret scan** (gitleaks' default rules, run in-process; `gitleaks:allow` comments in
  repo content are ignored). Each finding prints a fingerprint. A reviewed false
  positive can be listed in the file named by `gates.secret_scan.baseline`, with a
  reason:

  ```json
  {"ignore": [{"fingerprint": "8493a272a6282907", "reason": "example token in docs, revoked"}]}
  ```

  A baselined finding still shows up, as a warning. If the secret is real: rotate it,
  and remove it from the published refs (rewriting history if it is inside the window).
- **Warnings:** `leak_patterns` with `action: warn`, and bidirectional control
  characters (the file page also shows a banner).

`plan` exits 1 when publishing would be blocked.

```sh
CREDENTIALS_DIRECTORY=~/.config/fpp/creds \
  bin/fpp apply -config /etc/fpp/config.yaml -state /var/lib/fpp -no-deploy
```

`apply` runs plan → gates → render into `<state>/staging/site` → output lint → deploy,
and stops at the first failure without publishing anything. The output lint fails on
the token, the host names or a block pattern anywhere in the staged site (HTML is also
checked after entity decoding, archives entry by entry, clone repos object by object);
on symlinks, special files or wrong modes; on files the renderer did not write; on repo
bytes, archives or clone repos that map to nothing published; on inline scripts, event
handlers, `style` attributes or `javascript:`/`data:` URLs in pages; and on the size
quota. `-auto` (the timer) refuses to publish a repo for the first time.

`fpp unpublish [-no-deploy] <slug>` runs `apply` without the repo published as `<slug>`
(its public `owner/repo`). Afterwards, remove it from the config, purge the CDN cache,
confirm `/build.txt` shows the printed build ID, and rotate anything it exposed
([RUNBOOK.md](RUNBOOK.md)).

## 6. Deploy

The `deploy` section is optional. Without it, only `apply -no-deploy` runs, and you copy
`<state>/staging/site/` to your web server yourself (rsync, a CI job, object storage…).
`fpp apply` without `-no-deploy` refuses to run.

With a `deploy` section, `fpp apply` uploads the staged site over SSH:

```yaml
deploy:
  target: "deploy@web.example.net"       # user@host, no port
  port: 22                               # optional
  ssh_key: { credential: "deploy-key" }  # private key, from the credentials directory
  known_hosts: "/etc/fpp/web_known_hosts" # pinned host key; required
```

ssh runs with an empty `$HOME`, no agent, no `~/.ssh/config`, and strict host key
checking against `known_hosts` only. Each upload does two things, relative to the
directory the SSH account lands in:

1. `rsync --delete` of the whole site into `staging/`;
2. a file named `ready`, written once the first step has completed.

fpp never reads anything back from the web host, so **activating the upload is the web
host's job**. A setup that holds up well:

- restrict the key in `authorized_keys` to rsync into one upload directory,
  e.g. `restrict,command="rrsync -wo /srv/sites/code/incoming" ssh-ed25519 …`, and make
  that file owned by root so the deploy user can't loosen it;
- watch for `ready` (a systemd `.path` unit or inotify), then check the upload (regular
  files and directories only, no group/world-writable modes, `index.html` present, under
  a size limit), copy it into a new read-only release directory, switch a `current`
  symlink to it with an atomic rename, delete `ready` and prune old releases;
- serve `current` with the Caddy config from `fpp caddy-site -host <hostname> -root
  /srv/sites/code/current`. It listens on plain HTTP port 8080, for a tunnel or a
  TLS-terminating proxy in front of it.

Serving `staging/` directly also works, but visitors can then see a half-uploaded site
and there is no previous release to roll back to. `deploy.keep_releases` (default 5) is
accepted for host-side scripts that read the config; fpp itself does not use it.

After a successful upload `apply` records the published manifest
(`<state>/published/manifest.json`) and prints the build ID. Unchanged sites are not
uploaded again. `/build.txt` on the public site shows which build is live; if it doesn't
change, the host rejected the upload (see [RUNBOOK.md](RUNBOOK.md#confirming-what-is-live)).

Run `fpp check-contract -base http://127.0.0.1:8080 -host <hostname> -site
<state>/staging/site` against the web server after the first deploy and after every
fpp or Caddy upgrade.

## 7. Run it on a timer

Run `apply -auto` from a systemd timer as a dedicated `fpp` user. `-auto` never publishes
a repo for the first time, so the first publish of each repo is a manual `fpp apply`
after reading `fpp plan`. A minimal pair of units:

```ini
# /etc/systemd/system/fpp-apply.service
[Unit]
Description=fpp: publish the static site
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=fpp
Group=fpp
ExecStart=/usr/local/bin/fpp apply -auto -config /etc/fpp/config.yaml
StateDirectory=fpp
StateDirectoryMode=0700
LoadCredential=forgejo-token:/etc/fpp/credentials/forgejo-token
LoadCredential=deploy-key:/etc/fpp/credentials/deploy-key
UMask=0077
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadOnlyPaths=/etc/fpp
NoNewPrivileges=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
Nice=10
MemoryMax=1G
TimeoutStartSec=30min
```

```ini
# /etc/systemd/system/fpp-apply.timer
[Unit]
Description=fpp: republish every 15 minutes

[Timer]
OnCalendar=*:0/15
RandomizedDelaySec=30s

[Install]
WantedBy=timers.target
```

If fpp shares a host with Forgejo, also hide Forgejo's data from it
(`InaccessiblePaths=-/var/lib/forgejo -/etc/forgejo` plus the database directories) and
limit its network with `IPAddressDeny=any` and `IPAddressAllow=` for Forgejo and the web
host. `IPAddressAllow=` needs cgroup BPF, which unprivileged containers often lack; use
an nftables rule matching the `fpp` user there instead.
