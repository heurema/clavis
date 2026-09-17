import assert from "node:assert/strict"
import { EventEmitter } from "node:events"
import { createServer } from "node:http"
import { PassThrough } from "node:stream"
import { test } from "node:test"

import { browserSignIn, hiddenFields, printedLink } from "./browser-sign-in.mjs"

const challenge = "c".repeat(43)
const state = "s".repeat(43)

function listen(handler) {
  const server = createServer(handler)
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve(server)),
  )
}

// fakeLogin stands in for `clavis login --no-browser`: it prints the link for
// its own loopback listener and, once the callback arrives, prints a result
// and exits.
async function fakeLogin(baseURL) {
  const child = new EventEmitter()
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  child.exitCode = null
  child.signalCode = null
  child.callbacks = []
  const exit = (code, signal = null) => {
    if (child.exitCode !== null || child.signalCode !== null) return
    child.exitCode = code
    child.signalCode = signal
    callback.close()
    child.emit("close", code)
  }
  child.kill = (signal) => exit(null, signal)
  const callback = await listen((request, response) => {
    child.callbacks.push(request.url)
    response.end("<p>Signed in. You can return to the terminal.</p>")
    child.stdout.write('{"schemaVersion":1,"ok":true,"data":{}}\n')
    exit(0)
  })
  const port = callback.address().port
  const query = new URLSearchParams({ port, challenge, state })
  child.stderr.write(
    `Open this link to sign in:\n${baseURL}/authorize?${query}\n`,
  )
  return child
}

// fakeServer answers the sign-in form and Approve the way the real routes do,
// recording what the browser sent.
async function fakeServer({ refuse = false } = {}) {
  const seen = []
  const server = await listen(async (request, response) => {
    let body = ""
    for await (const chunk of request) body += chunk
    seen.push({
      method: request.method,
      url: request.url,
      origin: request.headers.origin,
      cookie: request.headers.cookie,
      body,
    })
    if (request.method === "POST" && request.url.startsWith("/login")) {
      if (refuse) {
        response.writeHead(401)
        return response.end("Invalid username or password")
      }
      // The target is in the action, never in the body the form submits.
      assert.deepEqual([...new URLSearchParams(body).keys()], [
        "username",
        "password",
      ])
      const next = new URLSearchParams(request.url.split("?")[1]).get("next")
      response.writeHead(303, {
        Location: next,
        "Set-Cookie": "clavis-dev-session=token; Path=/; HttpOnly",
      })
      return response.end()
    }
    if (request.method === "GET" && request.url.startsWith("/authorize?")) {
      const query = new URLSearchParams(request.url.split("?")[1])
      response.writeHead(200)
      return response.end(
        `<form><input type="hidden" name="port" value="${query.get("port")}"/>` +
          `<input type="hidden" name="challenge" value="${challenge}"/>` +
          `<input type="hidden" name="state" value="${state}"/>Approve</form>`,
      )
    }
    if (request.method === "POST" && request.url === "/authorize") {
      const fields = new URLSearchParams(body)
      response.writeHead(303, {
        Location: `http://127.0.0.1:${fields.get("port")}/callback?code=${"k".repeat(43)}&state=${fields.get("state")}`,
      })
      return response.end()
    }
    response.writeHead(404)
    response.end()
  })
  const baseURL = `http://127.0.0.1:${server.address().port}`
  return { server, baseURL, seen }
}

test("printedLink waits for a whole line naming the base URL", () => {
  const base = "http://127.0.0.1:8080"
  assert.equal(
    printedLink(`Open this link to sign in:\n${base}/authorize?x`, base),
    undefined,
  )
  assert.equal(
    printedLink(`Open this link to sign in:\n${base}/authorize?x\n`, base),
    `${base}/authorize?x`,
  )
  assert.equal(printedLink("https://elsewhere/authorize?x\n", base), undefined)
})

test("hiddenFields reads the three approval fields", () => {
  const document = `<input type="hidden" name="port" value="5000"/><input type="hidden" name="challenge" value="C"/><input type="hidden" name="state" value="S"/>`
  assert.deepEqual(hiddenFields(document), {
    port: "5000",
    challenge: "C",
    state: "S",
  })
  assert.throws(() => hiddenFields("<form></form>"), /no port field/)
})

test("browserSignIn signs in, approves and waits for the CLI's result", async () => {
  const { server, baseURL, seen } = await fakeServer()
  try {
    const child = await fakeLogin(baseURL)
    const signedIn = await browserSignIn({
      child,
      baseURL,
      origin: "https://public.example",
      username: "smoke-admin",
      password: "secret-password-value",
    })
    assert.equal(signedIn.code, 0)
    assert.equal(signedIn.result.ok, true)
    assert.match(
      signedIn.callback,
      new RegExp(
        `^http://127\\.0\\.0\\.1:\\d+/callback\\?code=k{43}&state=${state}$`,
      ),
    )
    assert.equal(child.callbacks.length, 1)
    assert.match(
      child.callbacks[0],
      new RegExp(`^/callback\\?code=k{43}&state=${state}$`),
    )
    const [form, document, approve] = seen
    assert.equal(form.origin, "https://public.example")
    const submitted = new URLSearchParams(form.body)
    assert.equal(submitted.get("username"), "smoke-admin")
    assert.equal(submitted.get("password"), "secret-password-value")
    // The action the form posted to is what carries the return target.
    assert.match(
      new URLSearchParams(form.url.split("?")[1]).get("next"),
      /^\/authorize\?port=\d+&challenge=c{43}&state=s{43}$/,
    )
    assert.equal(document.cookie, "clavis-dev-session=token")
    assert.equal(approve.url, "/authorize")
    assert.equal(approve.origin, "https://public.example")
    assert.equal(approve.cookie, "clavis-dev-session=token")
    assert.equal(new URLSearchParams(approve.body).get("state"), state)
  } finally {
    server.close()
  }
})

test("browserSignIn stops the CLI when the form refuses the sign-in", async () => {
  const { server, baseURL, seen } = await fakeServer({ refuse: true })
  try {
    const child = await fakeLogin(baseURL)
    const refused = await browserSignIn({
      child,
      baseURL,
      username: "smoke-member",
      password: "wrong-password-value",
    })
    assert.equal(refused.refused, true)
    assert.equal(refused.status, 401)
    assert.match(refused.page, /Invalid username or password/)
    assert.equal(child.signalCode, "SIGTERM")
    assert.equal(child.callbacks.length, 0)
    assert.equal(seen.length, 1)
    assert.equal(seen[0].origin, baseURL)
  } finally {
    server.close()
  }
})

test("browserSignIn fails when the CLI exits before printing a link", async () => {
  const child = new EventEmitter()
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  child.exitCode = null
  child.signalCode = null
  child.kill = () => {}
  const pending = browserSignIn({
    child,
    baseURL: "http://127.0.0.1:1",
    username: "smoke-admin",
    password: "secret-password-value",
  })
  child.exitCode = 2
  child.emit("close", 2)
  await assert.rejects(pending, /exited 2 before printing a link/)
})
