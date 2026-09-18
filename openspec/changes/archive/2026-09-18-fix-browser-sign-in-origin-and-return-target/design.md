## Context

`authorizePage` sets `Referrer-Policy: no-referrer` on the document it renders (`internal/server/auth.go:680`), as does the `/authorize` timeout fallback (`:194`) and the Approve redirect (`:711`). Under `no-referrer`, Safari and Firefox send `Origin: null` on a form POST from that document; Chrome sends the real origin today but shipped the opaque behaviour once in Chrome 58. `originAllowed` (`:239-250`) refuses `null`, as the CSRF rule requires, so the sign-in form rendered by the authorize page is refused with 403 in those browsers, and so would the Approve form.

The return target lives in a hidden `next` field. `loginBrowser` (`:798`) refuses three times before it reads the body — origin, Authorization header or media type, duplicate session credentials — passing `""` to `loginFailure` each time, and the `/login` timeout fallback (`:190-192`) cannot read the body at all because the handler consumed it. Only the failures after `next, _ := returnLink(string(body))` (`:820`) keep it. `GET /login` already reads the target from the query (`:57-58`), and `loginLocation` (`:670-672`) already builds `/login?next=<link>` for the signed-out approve path.

Observed on September 17, 2026: `GET /authorize` 200, `POST /login` 403, then a sign-in from the 403 document (which carries no referrer policy) 303 to `/admin/users`, and the CLI timed out.

## Goals / Non-Goals

**Goals:**
- Browser sign-in works in Safari, Firefox and Chrome.
- No refusal path can lose the return target, by construction rather than by remembering to pass it.
- The authorize link's challenge and state still never reach another origin.

**Non-Goals:**
- Relaxing the origin rule. An opaque origin stays refused.
- Changing the approval flow, the one-time code, the CLI or the link's shape.

## Decisions

### 1. `strict-origin` on documents a browser posts from

Use `Referrer-Policy: strict-origin` on the authorize document, the invalid-link document and the sign-in document rendered for them, keeping `no-referrer` on the Approve 303 (`:711`), which governs only the loopback GET. `strict-origin` sends at most the origin (`http://host:port`) as `Referer`, never the path or query, so the challenge and state stay private, and it leaves the `Origin` header of a same-origin POST intact. `same-origin` would also work but sends the full URL back to our own origin, which the link's secrets do not need.

Pin the value with a comment naming the failure it prevents, and assert it in the tests that today assert `no-referrer`, so a later "harden the referrer policy" edit fails a test instead of breaking sign-in again.

Alternative: keep `no-referrer` and accept `null` when Sec-Fetch-Site says `same-origin`. That weakens the CSRF rule the whole browser surface rests on, for a header we chose ourselves.

### 2. The return target travels in the form's action URL

The sign-in form posts to `/login?next=<rebuilt link>` when the request that rendered it carried a valid target, and to `/login` otherwise. `loginFailure` derives the target itself with `returnLink(r.URL.RawQuery)` instead of taking it as a parameter, so every refusal renders it: the three early ones, the parse failures, the service failures and the timeout fallback, which still has the request URL. `loginBrowser` reads the target the same way for its redirect. The body then carries exactly two fields again, so `fields := 2 + min(len(values["next"]), 1)` (`:819`) becomes a constant and a body that still carries `next` is an unknown field, refused as before.

`web.LoginModel` loses `Next` and gains the action URL the form posts to; the template renders that action instead of a hidden input. `GET /login` keeps reading the query it already reads.

This removes the need to read the body before the origin check and the need for any hand-off through `operationState`.

Alternative: keep the hidden field and pass it through each refusal. That is the shape that produced this bug, and each new refusal path would have to remember it.

### 3. What the URL exposes

The link is already a URL the browser holds: the person opened `/authorize?...` with the same challenge and state, and `loginLocation` already redirects to `/login?next=<link>`. The request logger records route patterns, not URLs (`internal/server/server.go:75-81`), and `strict-origin` keeps the query out of `Referer`. A target that does not parse is dropped, so the URL can carry nothing else.

### 4. One short line per failure

`authMessage` (`internal/web/auth_view.go:17`) keeps one sentence per code: `INVALID_CREDENTIALS` stays "Invalid username or password", `FORBIDDEN` on the sign-in form loses its second clause about administration, since a person reading the sign-in page was refused for the request, not for a role. The template's "Your password has been cleared. Enter it again to retry." (`internal/web/auth.templ:67`) goes: the field is visibly empty, and the sentence adds nothing a person cannot see. `retryMessage` already reads as one line and stays.

Alternative: keep the guidance for people who miss the empty field. It is noise on every failure for a case the form itself already shows.

## Risks / Trade-offs

- [`strict-origin` leaks the origin as `Referer` to other origins] → The origin is not a secret; the path and query are, and they stay withheld. Nothing the documents link to is off-origin anyway.
- [A future edit "hardens" the policy back to `no-referrer`] → A test asserts the value and a comment names the consequence.
- [Shorter failure text loses a hint] → The removed line described the form's own state; the remaining sentence still names the failure.
- [The authorization link appears in the sign-in URL] → It already appears in the authorize URL and in the signed-out redirect; both are the same browser's own history.
- [Chrome behaves differently from Safari and Firefox here] → The fix does not depend on which browser sends what: no document a browser posts from uses an opaque-origin policy. Task 1.3 checks Safari, Firefox and Chrome.

## Migration Plan

None: one handler, two templates, no schema, no configuration, no CLI change. It ships in `v0.1.0` before the tag.

## Open Questions

None.
