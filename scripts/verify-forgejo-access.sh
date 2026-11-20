#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# verify-forgejo-access.sh — probe what the public-mirror bot's token can and cannot do.
#
# Answers two questions (docs/SETUP.md §1):
#   1. Does the "Restricted" flag hide public repos from the bot?
#   2. Does a "Specific repositories" token work for git-over-HTTP fetch?
# ...and checks the rest of the access layers: canaries are unreadable, no write access,
# no scopes beyond read:repository, no repos visible beyond the allowlist.
#
# Nothing here modifies Forgejo. Every probe is a GET, a `git ls-remote`, or a request
# built to be rejected before it can change anything (see the issue-write probe).
# The token never appears in argv or output; it lives only in a 0600 temp dir.
#
# Run it where the builder will run (e.g. inside the Forgejo LXC):
#
#   FORGEJO_URL=http://127.0.0.1:3000 \
#   BOT_USER=public-mirror-bot \
#   ALLOWED_REPOS="me/dotfiles me/other" \
#   CANARY_PRIVATE=me/canary-private \
#   CANARY_PUBLIC=me/canary-public \
#   ./scripts/verify-forgejo-access.sh
#
# Optional: TOKEN_FILE=/path/to/token (otherwise you are prompted), CA_FILE=/path/ca.pem.
# Exit code: 0 = all layers hold, 1 = at least one FAIL, 2 = usage/connection error.
# Requires: bash, curl (>= 7.55), git (>= 2.32), base64. jq is used if present.

set -euo pipefail

: "${FORGEJO_URL:?set FORGEJO_URL, e.g. http://127.0.0.1:3000}"
: "${BOT_USER:?set BOT_USER}"
: "${ALLOWED_REPOS:?set ALLOWED_REPOS (space-separated owner/repo)}"
: "${CANARY_PRIVATE:?set CANARY_PRIVATE (a private repo the bot was never granted)}"
CANARY_PUBLIC="${CANARY_PUBLIC:-}"
TOKEN_FILE="${TOKEN_FILE:-}"
CA_FILE="${CA_FILE:-}"

base="${FORGEJO_URL%/}"
read -ra allowed <<<"$ALLOWED_REPOS"
first="${allowed[0]}"

for cmd in curl git base64; do
  command -v "$cmd" >/dev/null || { echo "missing required command: $cmd" >&2; exit 2; }
done

if [[ -n "$TOKEN_FILE" ]]; then
  token="$(tr -d '[:space:]' <"$TOKEN_FILE")"
else
  read -rsp "Token for $BOT_USER: " token
  echo
fi
[[ -n "$token" ]] || { echo "empty token" >&2; exit 2; }

umask 077
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

printf 'Authorization: token %s\n' "$token" >"$tmp/h_token"
printf 'Authorization: Basic %s\n' "$(printf '%s:%s' "$BOT_USER" "$token" | base64 | tr -d '\n')" >"$tmp/h_basic"
unset token

fails=0
warns=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fails=$((fails + 1)); }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$*"; warns=$((warns + 1)); }
info() { printf '  INFO %s\n' "$*"; }

# -q: ignore ~/.curlrc. No -n: ~/.netrc is never consulted.
curl_base=(-q -sS --max-time 20 -o "$tmp/body" -w '%{http_code}')
if [[ -n "$CA_FILE" ]]; then curl_base+=(--cacert "$CA_FILE"); fi

# http HEADERFILE URL [curl args...] -> prints the HTTP status (000 on connection error)
http() {
  local header="$1" url="$2" code
  shift 2
  code="$(curl "${curl_base[@]}" -H @"$header" "$@" "$url" 2>>"$tmp/curl_err")" || true
  printf '%s' "${code:-000}"
}

# api METHOD PATH [JSON] -> prints the HTTP status; response body is in $tmp/body
api() {
  local method="$1" path="$2" data="${3:-}"
  local extra=(-X "$method" -H 'Accept: application/json')
  if [[ -n "$data" ]]; then extra+=(-H 'Content-Type: application/json' --data "$data"); fi
  http "$tmp/h_token" "$base/api/v1/$path" "${extra[@]}"
}

# git_ls REPO HEADERFILE -> exit 0 if `git ls-remote` succeeds.
# The environment isolates git from your own config, credential helpers and ~/.netrc
# (git reads ~/.netrc on a 401), so only the bot token can authenticate.
git_env=(
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null HOME="$tmp"
  GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false
  GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.extraHeader
)
if [[ -n "$CA_FILE" ]]; then git_env+=(GIT_SSL_CAINFO="$CA_FILE"); fi
# The header (it holds the token) is exported in a subshell, never passed
# as an argument: argv is readable by any local user through /proc.
git_ls() {
  (
    unset GIT_CONFIG_PARAMETERS
    export "${git_env[@]}"
    GIT_CONFIG_VALUE_0="$(tr -d '\n' <"$2")"
    export GIT_CONFIG_VALUE_0
    exec git ls-remote --heads "$base/$1.git"
  ) >"$tmp/git_out" 2>"$tmp/git_err"
}

# ---------------------------------------------------------------------------
echo "== Connection"
code="$(api GET version)"
case "$code" in
  200)
    if command -v jq >/dev/null; then ver="$(jq -r '.version // empty' "$tmp/body")"; else
      ver="$(grep -o '"version":"[^"]*"' "$tmp/body" | cut -d'"' -f4 || true)"; fi
    info "Forgejo version: ${ver:-unknown}  (Specific-repository tokens need v15.0+)" ;;
  401) echo "  token rejected (HTTP 401): check BOT_USER / token" >&2; exit 2 ;;
  000) echo "  cannot connect to $base: $(tail -n1 "$tmp/curl_err")" >&2; exit 2 ;;
  *)   echo "  unexpected HTTP $code from $base/api/v1/version" >&2; exit 2 ;;
esac

echo "== API: allowed repos must be readable"
for r in "${allowed[@]}"; do
  code="$(api GET "repos/$r")"
  if [[ "$code" == 200 ]]; then pass "$r readable"
  else fail "$r -> HTTP $code (bot lacks Read on it, or it's not in the token's repo list)"; fi
done

echo "== API: canaries must NOT be readable"
check_hidden() {
  local r="$1" why="$2" code
  code="$(api GET "repos/$r")"
  case "$code" in
    401|403|404) pass "$r hidden (HTTP $code)" ;;
    200) fail "$r READABLE: $why" ;;
    *) warn "$r -> unexpected HTTP $code" ;;
  esac
}
check_hidden "$CANARY_PRIVATE" "the bot can read a private repo it was never granted"
if [[ -n "$CANARY_PUBLIC" ]]; then
  check_hidden "$CANARY_PUBLIC" "the bot sees public repos. Set Site Administration > User accounts > (bot) > Restricted"
else
  info "CANARY_PUBLIC not set: the Restricted-flag check is skipped (strongly recommended)"
fi

echo "== API: repos visible to the bot (repos/search)"
code="$(api GET 'repos/search?limit=50')"
if [[ "$code" == 200 ]]; then
  if command -v jq >/dev/null; then
    mapfile -t seen < <(jq -r '.data[].full_name' "$tmp/body" | sort -u)
  else # heuristic: repo full_names are the only full_name values with exactly one '/'
    info "jq not found: using a heuristic parser (may over-report; install jq for exact results)"
    mapfile -t seen < <(grep -o '"full_name":"[^"/]*/[^"/]*"' "$tmp/body" | cut -d'"' -f4 | sort -u)
  fi
  info "${#seen[@]} visible: ${seen[*]:-(none)}"
  for s in "${seen[@]}"; do
    [[ " ${allowed[*]} " == *" $s "* ]] || fail "$s is visible to the bot but not in ALLOWED_REPOS"
  done
  if (( ${#seen[@]} >= 50 )); then warn "50+ repos visible: list may be truncated"; fi
else
  warn "repos/search -> HTTP $code (could not list visible repos)"
fi

echo "== API: token scope should be read:repository only"
code="$(api GET user)"
case "$code" in
  401|403) pass "/user denied (no read:user scope)" ;;
  200) warn "/user allowed: token has read:user, which the builder doesn't need" ;;
  *) warn "/user -> HTTP $code" ;;
esac
# Built to fail: an issue without a title is rejected (422) by validation even when
# write access exists, so nothing gets created. 403 means the scope check stopped it.
code="$(api POST "repos/$first/issues" '{}')"
case "$code" in
  401|403) pass "issue write denied on $first (HTTP $code)" ;;
  404) pass "issue write denied on $first (HTTP 404; also seen when issues are disabled)" ;;
  422) fail "token has issue WRITE access (only the missing title stopped it)" ;;
  201) fail "an issue was CREATED on $first: token has write access; delete it and recreate the token" ;;
  *) warn "issue write probe -> HTTP $code" ;;
esac

echo "== git over HTTP"
for r in "${allowed[@]}"; do
  if git_ls "$r" "$tmp/h_basic"; then
    pass "$r fetchable with Basic auth (bot:token), $(wc -l <"$tmp/git_out") branches"
  elif git_ls "$r" "$tmp/h_token"; then
    warn "$r fetchable only with an 'Authorization: token' header, not Basic (note for the builder)"
  else
    fail "$r NOT fetchable over git: $(head -c 300 "$tmp/git_err" | tr '\n' ' ')"
    info "if the API checks above passed, this Forgejo version doesn't accept repo-scoped tokens"
    info "for git. Fallback: an all-repos read:repository token on the Restricted bot (docs/SETUP.md §1)"
  fi
done
for r in "$CANARY_PRIVATE" ${CANARY_PUBLIC:+"$CANARY_PUBLIC"}; do
  if git_ls "$r" "$tmp/h_basic" || git_ls "$r" "$tmp/h_token"; then
    fail "$r FETCHABLE over git"
  else
    pass "$r not fetchable over git"
  fi
done
# This is the first request `git push` makes; it can't change anything.
code="$(http "$tmp/h_basic" "$base/$first.git/info/refs?service=git-receive-pack")"
case "$code" in
  401|403) pass "push denied on $first (HTTP $code)" ;;
  200) fail "token can PUSH to $first" ;;
  *) warn "push probe -> HTTP $code" ;;
esac

echo
echo "Note: Forgejo answers 404 both for 'no access' and 'does not exist'."
echo "      Double-check that the canary names are spelled correctly."
if (( fails > 0 )); then
  echo "RESULT: $fails FAIL, $warns WARN"
  exit 1
fi
echo "RESULT: OK ($warns WARN)"
