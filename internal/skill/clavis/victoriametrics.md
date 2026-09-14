# VictoriaMetrics connections

Queries are PromQL (with VictoriaMetrics' MetricsQL extensions), forwarded to
the source's Prometheus API exactly as typed. Time strings, steps and selectors
are the source's own formats; the platform parses none of them.

## Discover first

Metric names are the values of the `__name__` label. List them, then the
labels and values of the metric you need:

```sh
clavis query --connection <ref> --label-values __name__ --match '{job=~".+"}' --start -1h
clavis query --connection <ref> --labels --match 'http_requests_total' --start -1h
clavis query --connection <ref> --label-values job --match 'http_requests_total' --start -1h
clavis query --connection <ref> --series 'http_requests_total{job="api"}' --start -15m
```

`--match` is a selector narrowing discovery; `--start` and `--end` bound it in
time. Discovery answers are bounded by the row cap: a truncated list is a
prefix, so narrow the selector rather than assuming the list is complete.

## Query

```sh
clavis query --connection <ref> --promql 'up'
clavis query --connection <ref> --promql 'up' --at 2026-09-14T10:00:00Z
clavis query --connection <ref> --promql 'sum(rate(http_requests_total[5m])) by (job)' --start -1h --step 1m
clavis query --connection <ref> --promql 'sum(rate(http_requests_total[5m])) by (job)' --start 2026-09-14T09:00:00Z --end 2026-09-14T10:00:00Z --step 60s
```

`--promql` alone is an instant query; `--at` pins it; `--start` with `--step`
makes it a range query and `--end` defaults to the source's now. `--at` cannot
be combined with `--start`, and `--step` needs `--start`. Aggregate in the
expression (`sum by`, `rate`, `topk`) rather than fetching raw series and
summing yourself: the source computes, the platform only bounds.

A ratio over a window, such as an error rate, is one instant query:

```sh
clavis query --connection <ref> --promql '100 * sum by (job) (increase(http_requests_total{status=~"5.."}[1h])) / sum by (job) (increase(http_requests_total[1h]))'
```

`increase` and `rate` extrapolate over the window and can overstate a counter
that has few samples; when the exact count matters, cross-check with
`http_requests_total - http_requests_total offset 1h`, which is the raw
difference. Discover the status values before writing `5..`: a source may
record only some of them.

## Bound the answer

The row cap counts samples across all series: one per vector entry, one per
matrix value. A range query over many series with a fine step reaches the cap
quickly; past it, matrix series keep the samples read so far and are marked
`truncated: true` inside the series, later series are empty and marked, and
the top-level `truncated` is true. Reduce samples by aggregating, coarsening
`--step`, narrowing the range or the selector. A body beyond the reading
ceiling fails as `SOURCE_ERROR` with `errorType: response_too_large`; the
same remedies apply. The connection's timeout is forwarded to the source,
which caps it at its own maximum.

## Read the result

`data.resultType` names the shape, decided by the source, not by your flags:
an instant query with a range selector (`up[5m]`) answers a `matrix`. `data.result`
is the Prometheus format: for a `vector`, entries with `metric` labels and
`value: [timestamp, "value"]`; for a `matrix`, `values` pairs; `scalar` and
`string` are one pair. Values are strings; parse them yourself. Discovery
answers `labels`, `labelValues` (string lists) or `series` (label sets).
`data.warnings` and `data.infos` are the source's notes about the query;
`data.isPartial` means a cluster answered from some of its nodes; both are
separate from `truncated` and worth repeating to the user.

## Read a failure

`SOURCE_ERROR` carries the source's own `errorType` and `message`: a
Prometheus server says `bad_data` for an expression that does not parse;
VictoriaMetrics writes the HTTP status, `422`, for a rejected or aborted
query, including one that hit the forwarded timeout. Only a source that stops
answering is `SOURCE_TIMEOUT`. A refusal about points per series or a
too-fine step is the source's own limit: coarsen `--step` or narrow the range.

## Pitfalls

- Reading a vector as a number. `value[1]` is a string; the first element is
  the evaluation timestamp.
- Trusting the request mode. Branch on `resultType`, never on the flags you
  passed.
- Empty results. A selector that matches nothing answers an empty `result`
  with no error; check discovery before concluding the metric is zero.
- Reversed ranges. The source clamps `--end` before `--start` rather than
  refusing; check the times you passed.

## Time formats

RFC 3339 (`2026-09-14T10:00:00Z`), Unix seconds (`1789380000`) and the
source's relative forms (`-1h`, `now`) all work for `--at`, `--start` and
`--end`; `--step` takes a duration (`60s`, `5m`). Prefer absolute times when
the answer will be compared or rerun.
