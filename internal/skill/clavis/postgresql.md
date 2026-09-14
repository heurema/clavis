# PostgreSQL connections

Queries are SQL, forwarded to PostgreSQL unchanged over one fresh session under
the connection's role. The role decides what a statement may do; Clavis does
not restrict statement types or wrap anything in a read-only transaction, so a
script that writes will write if the role allows it. Do not write unless the
user asked for exactly that.

## Discover first

There is no schema command; the catalog is a query like any other. Run it
before guessing table or column names:

```sh
clavis query --connection <ref> --sql "select table_schema, table_name, column_name, data_type from information_schema.columns where table_schema not in ('pg_catalog', 'information_schema') order by 1, 2, ordinal_position"
```

Narrow it with a `where table_name like '%order%'` when the catalog is large,
because the row cap applies to the catalog too. `data.results[0].rows` lists
one row per column; only tables the role may see appear.

## Query

```sh
clavis query --connection <ref> --sql 'select id, status, created_at from orders order by created_at desc limit 50'
clavis query --connection <ref> --sql-file /absolute/path/report.sql
clavis query --connection <ref> --sql-stdin <<'SQL'
select date_trunc('day', created_at) as day, count(*)
from orders
where created_at >= now() - interval '7 days'
group by 1 order by 1;
SQL
```

Put ordering and limits in the SQL. A statement without `ORDER BY` returns
rows in no particular order, and `LIMIT` is the only way to choose which rows
you get; the platform's row cap only cuts, it does not order. Name the columns
you need instead of `select *`, which wastes the byte cap on columns you will
not report. Several statements in one string run in order in one implicit
transaction; a failure anywhere rolls back the whole script and returns the
error alone.

## Bound the answer

The connection's statement timeout applies to each statement; the row cap and
byte cap apply to the whole answer. `--max-rows N` keeps at most N rows.
When `truncated` is true, the rows you got are the first ones the source
returned in its order; add an `ORDER BY` and a `LIMIT` at or below the cap
and rerun rather than reasoning from an arbitrary prefix.

## Read the result

`data.results` is a list with one entry per statement, each with `command`
(the tag word, `SELECT`, `UPDATE`), `columns` (name and PostgreSQL type),
`rows` (arrays in column order), `rowCount` and `truncated`. Every value is
the text PostgreSQL rendered: `123`, `2026-09-14 10:00:00+00`, `t`, or `null`
for SQL NULL. Convert types yourself from the column list; an `int8` beyond
2^53 and a `numeric` are exact strings. A statement without rows (an `UPDATE`)
has empty `columns` and `rows` and `rowCount` set to the affected count.

## Read a failure

`SOURCE_ERROR` carries PostgreSQL's own `sqlstate`, `message`, `detail`,
`hint`, `position` (an offset into your SQL) and `statement` (the index of the
failing statement, 0 for the first). `42P01` is a missing table, `42703` a
missing column: run the catalog query and fix the name. `42501` means the role
lacks the privilege: report it, do not look for another way. A statement that
runs past the connection's timeout is `SOURCE_TIMEOUT`, not a source error:
narrow the query.

## Pitfalls

- Guessing names. Always discover first; a wrong name costs a round trip and
  a `SOURCE_ERROR`, a wrong guess that happens to exist costs a wrong answer.
- Reading a truncated answer as complete. Check `truncated` on every result.
- Time zones. `now()` is the source's clock and time zone; compare with
  `timestamptz` columns explicitly (`at time zone 'UTC'`) when it matters and
  report the range you used.
- Wide rows. A single value larger than the byte cap can still be fetched
  alone, but a value beyond about 20 MiB cannot be retrieved through the CLI
  at all (`INVALID_RESPONSE`); select fewer or narrower columns.

## Time formats

Times live inside the SQL: `now() - interval '1 hour'`, `'2026-09-14T10:00:00Z'`
literals, `date_trunc`. The `--start`, `--end`, `--at` and `--step` flags do not
apply to SQL and are refused with a hint.
