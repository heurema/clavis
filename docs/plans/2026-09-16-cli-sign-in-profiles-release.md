# Plan: CLI sign-in, profiles and tagged releases

Status: agreed on September 16, 2026; to be delivered as three OpenSpec changes in the
order below. Each proposal cites this plan in its design's "Inherited decisions" table;
once a change is archived, its design becomes the canonical source and this plan is not
updated retroactively.

## Why

The first beta users arrived on September 16, 2026, and three inconveniences surfaced at
once:

- `clavis whoami` reported the server unreachable after a successful login, because the
  CLI never remembers the server: every command resolves the origin from `--server` or
  `CLAVIS_SERVER_URL` and silently falls back to `http://127.0.0.1:8080`.
- Sessions expire eight hours after login with no renewal, so an agent working through the
  evening is cut off mid-task and the person has to type a password again.
- `clavis version` prints `dev` after `go install github.com/heurema/clavis/cmd/clavis@v0.1.0-rc.1`,
  because the build identity is stamped only by Makefile linker flags.

Breaking changes remain allowed during the beta. A server release may require a CLI
upgrade, and moving the session directory forces one more sign-in; both go in release
notes. TLS terminates at the reverse proxy in front of the server; Clavis handles no
certificates anywhere in this plan.

## Change 1: version and release

Spec touched: deployment-packaging. Ships as v0.1.0-rc.2.

- `clavis version` and the server startup log fall back to the Go build information when
  the linker values are unset: the main module version gives the tag, the VCS settings give
  commit, date and the dirty flag. Linker flags keep precedence for release builds. The
  skill stamp written by `clavis skill install` becomes correct as a consequence.
- One GitHub workflow on a `v*` tag push. Release candidates (`-rc.N`) publish as
  pre-releases. Actions are pinned by commit SHA; only tools already on the runner plus the
  pinned Helm install are used. No goreleaser.
- The workflow runs the generated-source gates and the non-database tests, then builds:
  CLI binaries for darwin and linux on amd64 and arm64 with the Makefile linker flags, a
  checksums file, and a GitHub Release holding them; a multi-arch server image at
  `ghcr.io/heurema/clavis` tagged without the leading `v`, digest recorded in the release
  notes; the chart packaged with appVersion set from the tag and pushed as OCI to
  `ghcr.io/heurema/charts`. The chart version follows the app tag until a template-only
  release is actually needed.
- The workflow refuses a dirty tree or a tag that is not on `main`. Signing (cosign) is
  decided when the workflow is written.
- Users install with `go install` at a tag or download the checksummed binary; both report
  the same version.

## Change 2: profiles

Specs touched: cli-authentication, agent-skill. Ships as v0.1.0-rc.3. Must land before
change 3.

### File

`~/.clavis/config.toml`, TOML, strict decoding that rejects unknown keys, never holding a
secret. `CLAVIS_HOME` overrides the directory. Sessions move to `~/.clavis/sessions/` and
stay keyed by server origin, so two profiles naming one server share one session.

```toml
default = "fce"

[profiles.fce]
server = "https://clavis.int.fce.global"

[profiles.local]
server = "http://127.0.0.1:8080"
```

A profile is a name and a server URL, validated with the same canonical-origin rule login
uses. Output format, timeout, default connection and certificate settings were considered
and rejected: a profile-level output format would flip every agent on the machine to text;
one timeout would flatten the deliberate split between the five-second commands and the
query budget; a default connection hides the one thing an answer must state; certificates
are the reverse proxy's job.

### Commands

- `clavis login --profile NAME [--server URL]` creates or updates the profile and signs in.
  It sets the default only when no default exists yet, and says so.
- `clavis login --server URL` without a profile is a one-off and writes nothing.
- `clavis profiles list` shows every profile, the default, and whether a session exists.
- `clavis profiles use NAME` switches the default and prints the server and the signed-in
  user there.
- `clavis profiles remove NAME` refuses the default and never touches session files.

### Resolution of the server

1. `--server URL` or `--profile NAME` on the command line. Both at once is an error.
2. `CLAVIS_SERVER_URL` or `CLAVIS_PROFILE` in the environment. Both at once is an error.
3. The default profile.
4. Otherwise `INVALID_ARGUMENT` with the hint `clavis login --profile <name> --server <url>`.

The loopback default disappears from `login` and `doctor` alike.

### Visibility of the choice

Every networked result, success or failure, carries top-level `server` (the canonical
origin) and `profile` (empty for a one-off). This is additive, so `schemaVersion` stays 1.
Text output prints the server on its first line. The skill tells agents to read `server`
from every envelope, state it in their answer, target a server with `--profile` or
`CLAVIS_PROFILE` when needed, and never run `profiles use` or `login --profile`.

### Implementation notes

- The config is read only inside networked commands; offline commands never touch it, and
  an absent file is not an error. A corrupt file, an unknown profile, a profile without a
  server or a default naming a missing profile is `INVALID_ARGUMENT` naming the file and
  key, never a partial load. Writes use the temp-file-and-rename pattern under a lock.
- The session directory check keeps exact owner-only mode on `sessions/` but relaxes the
  parent to "not group- or world-writable", because users will create `~/.clavis` under a
  normal umask or symlink it from a dotfile manager. Storage failures name the path and the
  required mode.
- `doctor` adopts the canonical-origin rule so a server that passes `doctor` cannot fail
  `login`.
- The skill's setup paragraph is corrected: login accepts only `--password-stdin`; the
  `--password-file` and `--password-env` channels belong to connection credentials.
- Release note: everyone signs in once more after upgrading.

## Change 3: browser sign-in and session policy

Specs touched: local-authentication, cli-authentication; PRD session lifetime row.
Ships as v0.1.0 or a further candidate.

### Loopback sign-in

1. `clavis login` (without `--password-stdin`) generates a state value and a PKCE verifier
   and listens on `127.0.0.1:<random port>`.
2. It posts the port, the state and the code challenge to a start route. The server inserts
   a pending authorization row (challenge, port, expiry of a few minutes, no user yet) under
   a cap and a cleanup like the login limits, and returns an id. Nothing is created on a GET.
3. The CLI opens the browser at the authorize page addressed by that id, printing the link
   for the case where no browser opens. Without a browser session the login page is shown
   first; it accepts a return target only in the literal shape of the authorize page with a
   UUID, never a free URL, because a successful browser login otherwise lands on a page that
   is a 403 for members.
4. The authorize page shows the username and the requesting port and requires an explicit
   Approve click, protected by the existing origin and framing checks. On approval the
   server binds the row to the user, issues a one-time code stored as a digest, and redirects
   to `http://127.0.0.1:<port>/callback?code=...&state=...`. The redirect is built from the
   stored integer port only.
5. The CLI accepts one request on the callback, checks the state, answers a static "return
   to the terminal" page, and posts the code with the verifier to a token route. The server
   consumes the row in one delete-returning statement, re-reads the user under the login
   row lock, and issues a CLI-kind session exactly as password login does.
6. The CLI writes the session file and prints the identity. Pending rows live in
   PostgreSQL, so several replicas are fine.

`--password-stdin` remains for agents and CI. Device flow is deferred until a headless need
appears. Refresh tokens were rejected: every request already rechecks the session in the
database, so revocation is instant and a short-lived access token would add nothing.

### One session policy

- Every session, browser or CLI, has an idle expiry (seven days by default) and an absolute
  cap (thirty days by default), both configurable. Per-kind lifetimes were rejected as
  needless complexity.
- Renewal is one conditional update in the authenticate path: only when the session is
  unrevoked and unexpired, only when less than half the idle window remains, extending to
  the lesser of idle window and cap. When it affects no row the existing select runs. This
  keeps a renewal from resurrecting a session an administrator revoked in between and bounds
  the write to roughly one per session per half window regardless of agent loop rate.
- The CLI cache and the browser cookie carry only the absolute cap; idle expiry stays
  server-side. The CLI reports `UNAUTHENTICATED` locally, before any network call, when the
  cached cap has passed. `whoami` reports both expiries.
- A bounded cleanup of expired sessions and an index on `expires_at` arrive with the
  migration; thirty-day sessions would otherwise grow the table unboundedly.
- The local-authentication spec's "fixed lifetime without implicit renewal" and GET rule,
  the PRD session row and the hard-coded five-minute to twenty-four-hour bounds are amended
  in this change.

## Postponed

Windows support (the CLI cache and password prompt are POSIX-only), device flow, token
rotation on renewal, mutual TLS for sources.
