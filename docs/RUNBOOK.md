# Runbook

Incident and routine procedures for a running fpp deployment. The steps on the web host
depend on how you set it up (see [SETUP.md](SETUP.md#6-deploy)); this file assumes the
recommended shape: fpp uploads with rsync over SSH, the web host activates each upload
as a new release behind a `current` symlink, and a CDN or tunnel sits in front. Keep the
host-specific commands (addresses, users, unit names) in a private document next to your
config, not in a published repo.

## Confirming what is live

The builder can only push: it can't read anything back from the web host, and the host
may reject an upload (validation, size quota) while the builder reports "deployed".
Later runs with unchanged content skip the upload, so a rejected deploy is **not
retried by itself**.

Every site has `/build.txt`, a 16-hex-digit ID of exactly what is published (slugs,
public refs, commits, files). Only public data goes into it, and it changes whenever a
repo, ref or file is added or removed.

- `fpp apply` prints `build <id>` after a deploy, or "live build should be <id>" when it
  skips an unchanged site.
- Check it with `curl -s https://<site>/build.txt`. It is cached for up to 5 minutes, so
  purge the CDN cache when it matters.
- If the IDs differ after a few minutes, the host rejected the upload. Read the host's
  activation log, fix the cause, then force a new upload: delete
  `<state>/published/site.digest` and run `fpp apply` by hand.

## "I published something by mistake"

Work in this order. Step 3 is the one that matters if a secret was exposed.

1. **Stop serving.** The fastest stop is to take the site offline at the edge (stop the
   tunnel, or the web server). Otherwise run `fpp unpublish <slug>`, or exclude the path
   or remove the repo in the config (`exclude:`) and run `fpp apply` by hand.
2. **Purge the CDN cache** (whole host), then **confirm**:
   - `/build.txt` shows the ID that `fpp unpublish` or `apply` printed;
   - the removed repo's URL (`/<owner>/<repo>/`) returns 404;
   - so does its clone URL (`/<owner>/<repo>.git/info/refs`).
3. **Rotate the secret.** Assume it was scraped within minutes. Removing it from the site
   does not un-leak it, and older releases kept on the web host still contain it until
   they are pruned.
4. **Remove it at the source**, or exclude the path. Otherwise the next apply publishes
   it again. With `diffs: true`, check the commit window too: both sides of every
   published diff are public.
5. **Review the web server's access logs** for requests to the affected URLs.
6. Bring the site back online if you took it down.

After `fpp unpublish`, remove the repo from the config. The timer (`-auto`) treats a repo
that is still configured but no longer in the published manifest as new, and refuses to
run until you resolve it (invariant I8 in [THREAT_MODEL.md](THREAT_MODEL.md)).

## Rollback

If the web host keeps releases, point `current` at an older one (with an atomic rename,
as the activation does). Stop the builder timer first, or the next changed build
replaces it. `/build.txt` tells you which build is live.

## Rotation

- **Forgejo token:** create a new token for the bot (repository access **All**, scope
  `read:repository` only, as in [SETUP.md](SETUP.md#1-forgejo-bot-and-token); the
  Restricted flag and the per-repo grants are what limit it), replace the credential
  file (0600, owned by root), revoke the old token, and run `fpp plan` to confirm the
  access checks pass.
- **Deploy key:** generate a new ed25519 key on the builder, add its public half to the
  deploy user's `authorized_keys` on the web host with the same restrictions, run
  `fpp apply` by hand, then remove the old key.
- **Web host key:** if the web host's SSH host key changes, update `deploy.known_hosts`
  after checking the new key out of band. fpp never accepts an unknown host key.
- **Tunnel or CDN credentials:** rotate them at the provider, replace them on the web
  host, and restart whatever uses them.

## After changing fpp itself

- Install the new binary on the builder.
- Regenerate the web server config with `fpp caddy-site` and reload Caddy.
- Run `fpp check-contract` against it. It also probes non-canonical spellings of
  repo-byte URLs (doubled slashes, dot segments, percent-encoded and upper-case class
  segments).
- A header contract change (for example the CSP) fails `check-contract` until the Caddy
  config is regenerated.

## After changing the network

From the web host, check that it still can't open connections into your LAN: Forgejo,
the builder, the router's admin interface and a few other LAN addresses must all be
unreachable. Only the builder should be able to connect to it (SSH, for the deploy).

## Rebuilding the web host

It holds no state worth keeping. Rebuild it, re-add the deploy user and the activation,
restore the tunnel credential, update `deploy.known_hosts` if the host key changed, then
run `fpp apply` by hand. Delete `<state>/published/site.digest` first, or apply skips
the upload because the site is unchanged. Purge the cache, and check `/build.txt` and
the network isolation before you put the site back online.
