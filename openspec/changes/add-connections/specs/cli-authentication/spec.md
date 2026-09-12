## ADDED Requirements

### Requirement: Connection management commands

The CLI SHALL provide `connections list [--selector <terms>] [--limit N]`, `connections get --connection <id>`, `connections create --name <slug> --provider <type> --url <target> [--label key=value]... [--title] [--description] [--scope] [--timeout] [--max-rows] [--max-bytes] [--auth] [--auth-user] [--auth-header]`, `connections update --connection <id> [same fields]`, `connections set-credentials --connection <id>`, `connections enable|disable|delete --connection <id>` and `connections check --connection <id>`, where `<id>` is a UUID or a name. These commands SHALL use the stored session, the `--server`/`--timeout` flags, origin policy, bounded transport and result envelope of the other authenticated commands, SHALL call only the documented connection routes, and SHALL use one verb vocabulary shared with `users`.

Secrets for `create` and `set-credentials` SHALL be read through exactly one of: a hidden terminal prompt when interactive, `--password-stdin`, `--password-file <absolute path>` read with the bootstrap secret-file rules, or `--password-env <NAME>` naming an environment variable whose value is read by the CLI. Supplying more than one input, a flag carrying the secret value itself, a relative or unsafe file, or an unset variable SHALL exit 2 with `INVALID_ARGUMENT` before any request. The secret value SHALL never appear in arguments, results, prompts on stdout or errors.

Every mutating command SHALL accept `--dry-run`, forwarding it so the server validates and authorizes without committing, and SHALL render the result marked as a dry run. Results SHALL expose only safe connection records; errors SHALL render the server's `hint` when present, in JSON as `error.hint` and in text on its own line. `CONNECTION_EXISTS`, `CONNECTION_NOT_FOUND`, `CONNECTION_IN_USE`, `CREDENTIALS_UNAVAILABLE`, `FORBIDDEN` and `UNAUTHENTICATED` SHALL pass through per route; undocumented responses SHALL map to `INVALID_RESPONSE`. The JSON envelope SHALL keep `schemaVersion` 1, since `hint` is additive.

#### Scenario: Create from automation with a secret file
- **WHEN** an agent runs `connections create --name payments-prod-reporting --provider postgresql --url postgres://reporting@db:5432/payments?sslmode=require --label env=prod --password-file /run/secrets/reporting`
- **THEN** the CLI reads the file, sends one create request, prints the record with `id` and `name` and no secret, and exits 0

#### Scenario: Secret from a named environment variable
- **WHEN** an agent runs `connections set-credentials --connection payments-prod-reporting --password-env REPORTING_PW`
- **THEN** the CLI reads only that variable, never prints its value, and the argument list contains only the variable's name

#### Scenario: Secret value on the command line
- **WHEN** a command receives `--password <value>`, two secret inputs at once, a relative `--password-file` path, or an unset `--password-env` name
- **THEN** it exits 2 with `INVALID_ARGUMENT` and a hint listing the accepted inputs, without contacting the server

#### Scenario: Dry run
- **WHEN** `connections delete --connection x --dry-run` targets an enabled connection
- **THEN** the CLI exits 1 with `CONNECTION_IN_USE`, renders the hint, and the server has changed nothing and recorded nothing

#### Scenario: Selector listing as text
- **WHEN** `connections list --selector env=prod --output text` runs
- **THEN** each connection prints on one line with id, name, provider, status and last check outcome, followed by a truncation notice only when the server reports truncation

#### Scenario: Error hint rendering
- **WHEN** the server answers `CONNECTION_EXISTS` with a hint
- **THEN** JSON output contains `error.hint` and text output prints the hint on a separate line after the message
