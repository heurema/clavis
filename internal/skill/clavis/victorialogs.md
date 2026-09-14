# VictoriaLogs connections

Queries are LogsQL, forwarded to the source's query endpoint exactly as typed.
Rows come back as the source wrote them; ordering, aggregation and field
extraction happen in the query, never in the platform.

## Discover first

Logs carry stream fields (how they were shipped: cluster, namespace, service,
pod) and ordinary fields (what the application logged). Discovery needs a
query (`--match`, `*` for everything) and should carry a time window:

```sh
clavis query --connection <ref> --stream-field-names --match '*' --start -1h
clavis query --connection <ref> --stream-field-values service_name --match '*' --start -1h
clavis query --connection <ref> --field-names --match 'service_name:checkout' --start -1h
clavis query --connection <ref> --field-values level --match 'service_name:checkout' --start -1h --filter err
clavis query --connection <ref> --streams --match 'namespace:payments' --start -15m
```

Discovery sees stored fields only. A severity is often not a field but a key
inside the JSON message, so an empty `--field-values level` means "not stored
as a field", not "no levels": unpack it in the query (below) and count with a
stats pipe to learn the values the application actually writes (`warn` or
`warning`, `error` or `ERROR`).

Each answer is a list of `{value, hits}` pairs. `--filter <substring>` narrows
the values on the field endpoints; `--limit N` asks the source for at most N
values on the value and stream endpoints, and under a limit the `hits` counts
are not observed (the source returns a subset with zero hits). An empty list
means the field was not stored under that query and window, not that the
field does not exist somewhere else.

## Query

```sh
clavis query --connection <ref> --logsql 'service_name:checkout level:error | sort by (_time) desc' --start -1h --limit 50
clavis query --connection <ref> --logsql '_stream:{service_name="checkout"} error' --start 2026-09-14T09:00:00Z --end 2026-09-14T10:00:00Z --limit 100
clavis query --connection <ref> --logsql '* | stats by (service_name, level) count() as n | sort by (n) desc' --start -15m --limit 20
```

Two knobs look alike and are not: `--limit N` is the source's own limit on
the rows the query returns after its pipes (a `| stats` result is computed
over the whole window and then limited), forwarded as typed, and on raw rows
it makes the source sort by `_time` descending before cutting; `--max-rows N`
is the platform's cap on what it keeps. Without
`--limit` or a sort pipe the stream arrives in arbitrary order, so always end
a query that should be ordered with `| sort by (_time) desc` and pass a
`--limit`. The platform never adds a limit or a sort.

### JSON inside messages

Many services log a JSON object as the message. The message is the `_msg`
field, a string; its keys are not fields until the query unpacks them:

```sh
clavis query --connection <ref> --logsql 'service_name:checkout | unpack_json fields (level, msg, requestId) | fields _time, level, msg, requestId | sort by (_time) desc' --start -15m --limit 50
clavis query --connection <ref> --logsql 'service_name:checkout | unpack_json fields (level) | stats by (level) count() as n' --start -1h
```

`unpack_json` keeps the original `_msg`; add `| fields ...` to return only
what you need. Filter on an unpacked key with the `filter` pipe, and use `:=`
for an exact value (`level:warn` matches `warning` too):

```sh
clavis query --connection <ref> --logsql 'service_name:checkout | unpack_json fields (level, msg) | filter level:=warn | stats by (msg) count() as n | sort by (n) desc' --start -15m --limit 50
```

Check the actual keys first with a small `--limit` on the raw rows, because a
key that does not exist unpacks to nothing and a filter on it silently matches
no row.

## Bound the answer

The log stream is unbounded unless `--limit` bounds it. When the row cap or
byte cap is reached the platform stops reading, closes the connection and
returns the rows it kept with `truncated: true`; that means the source's
completion was not observed and more rows may exist. Pass `--limit` at or
below the cap with a sort pipe to choose which rows you get, or narrow the
query and the window. A single row larger than the reading ceiling fails as
`SOURCE_ERROR` with `errorType: response_too_large`; select fewer fields.

## Read the result

`data.resultType` is `logs` and `data.result` an array of the source's rows in
arrival order: every value is a string; `_time`, `_msg`, `_stream` and
`_stream_id` are the source's own fields, the rest are the stored fields.
Rows of a `| stats` pipe carry only the fields the pipe produced. Discovery
answers `fieldNames`, `fieldValues`, `streams`, `streamFieldNames` or
`streamFieldValues` as `{value, hits}` lists. `--output text` prints one row
per line with `_time`, `_msg`, the other fields as `key=value` and `_stream`
last, quoting a value that contains whitespace; for JSON messages prefer the
JSON output or an `unpack_json` query.

## Read a failure

`SOURCE_ERROR` carries `errorType: http_400` with the source's own parse
message for a rejected query; `http_503` when the source aborted at the
forwarded timeout; `malformed_response` when a line of the stream was not a
row (the source can write an error after rows; no rows are returned then).
Only a source that stops answering is `SOURCE_TIMEOUT`.

## Pitfalls

- Guessing field names. A filter on a field that does not exist returns no
  rows and no error. Discover first.
- Reading an unordered stream as "the latest". Without a sort pipe and a
  limit the rows are arbitrary.
- Zero hits under `--limit`. Not an absence of matches; rerun without the
  limit or with a narrower query when the counts matter.
- Treating message text as fields. Unpack in the query.

## Time formats

RFC 3339 (`2026-09-14T10:00:00Z`), Unix seconds and the source's relative
forms (`-1h`, `-15m`) work for `--start` and `--end`, and `--end` is
exclusive; `--at` and `--step` do not apply to logs and are refused with a
hint. A window can also live inside
the query (`_time:1h`). Prefer absolute times when the answer will be
compared or rerun, because separate relative windows move between requests.
