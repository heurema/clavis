## Why

On September 17, 2026, hours after `add-browser-sign-in-and-session-renewal` was merged, the owner signed a CLI in by hand against a local server and the CLI was never approved. Two defects, both introduced by that change, stack:

1. **The sign-in form is refused in Safari and Firefox.** `authorizePage` sends `Referrer-Policy: no-referrer` on the document it renders, and those browsers send `Origin: null` on a form POST from a `no-referrer` document. `originAllowed` rightly refuses an opaque origin, so `POST /login` answers 403 before any service call. The same header sits on the approval document, so the Approve click would be refused the same way. Browser sign-in, the only way to sign a CLI in, does not work in those browsers at all.
2. **A refused sign-in forgets what it was approving.** The refusal renders the sign-in document without the hidden return target, so the person's next attempt is an ordinary sign-in that lands on `/admin/users` while the CLI waits out its five minutes. Only failures raised after the body is parsed keep the target today.

The header was added late in the delivery as defence in depth and no browser exercised the flow afterwards: the manual run that used a real browser predates it, and every later check drove the form with `curl`, which sends whatever `Origin` it is told to. `v0.1.0` is not tagged yet, so this lands before the release.

## What Changes

- **Authentication documents SHALL keep the browser's `Origin` header on same-origin form submission.** The authorize, invalid-link and sign-in documents send `Referrer-Policy: strict-origin` instead of `no-referrer`: the full URL, with its challenge and state, still never reaches another origin, and a same-origin POST still carries a real `Origin`. The Approve redirect keeps `no-referrer`, because it governs only the loopback GET that follows.
- **BREAKING for no browser, but a wire change**: a document that a browser must post from SHALL NOT use a referrer policy that produces an opaque origin.
- **The return target moves from a hidden form field into the form's action URL** (`POST /login?next=<link>`). Every response to a refused sign-in then renders it, because the failure path reads it from the request URL rather than being handed it by each call site. The parsing rule is unchanged: exactly one `next` that parses as an authorization link, rendered rebuilt from its parsed values.
- The approval page keeps its other protections unchanged: explicit Approve click, origin and framing checks, and nothing written by a GET.
- **The sign-in page's failure text becomes one short line.** Today a refused password renders "Invalid username or password" followed by "Your password has been cleared. Enter it again to retry.", which restates what the empty field already shows, and a refused origin renders two sentences covering both origin and role. Each failure SHALL render one short sentence and no restatement of the form's visible state.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `local-authentication`: "Protected browser authentication" gains the referrer-policy rule and the rule that a refused sign-in keeps its return target, with scenarios for both. The requirement's description of where a successful sign-in lands is unchanged apart from naming the URL as the target's carrier.

## Impact

- `internal/web/auth_view.go` and `auth.templ`: the failure text and the removal of the cleared-password line.
- `internal/server/auth.go`: the referrer policy on `authorizePage` and its invalid-link and timeout renderings; `loginBrowser` and `loginFailure` read the target from the request URL; the form action carries it; the `fields` arithmetic for the body loses its `next` case.
- `internal/web/auth.templ` and `auth_models.go`: the sign-in form posts to the target-carrying action instead of rendering a hidden field.
- `internal/server/auth_test.go`, `authorize_test.go`, `database_test.go`: the refusal cases gain return-target assertions, and the header expectation changes.
- No database, CLI, chart or configuration change. The CLI builds the same link it does today.
- Verification gap this exposes: no automated test can see a browser's `Origin`. Task 1.3 runs the flow by hand in Safari and Firefox before the release, and the tasks record that as the standing check for this flow.
