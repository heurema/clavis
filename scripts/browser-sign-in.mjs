// The browser's part of `clavis login --no-browser`, done with fetch so the
// smoke, image smoke and kind scripts exercise the real sign-in flow: the
// printed link, the sign-in form, Approve, the loopback callback and the
// CLI's own code exchange.

// hiddenFields reads the three hidden inputs of the authorize document.
export function hiddenFields(document) {
  const fields = {}
  for (const name of ["port", "challenge", "state"]) {
    const match = document.match(
      new RegExp(`<input type="hidden" name="${name}" value="([^"]*)"`),
    )
    if (!match) throw new Error(`The authorize document has no ${name} field`)
    fields[name] = match[1]
  }
  return fields
}

// printedLink returns the first complete stderr line that is an authorization
// link for the base URL.
export function printedLink(text, baseURL) {
  return text
    .split("\n")
    .slice(0, -1)
    .find((line) => line.startsWith(`${baseURL}/authorize?`))
}

function sessionCookie(response) {
  const cookie = response.headers
    .getSetCookie()
    .map((value) => value.split(";")[0])
    .find((value) =>
      /^(__Host-clavis-session|clavis-dev-session)=./.test(value),
    )
  if (!cookie) throw new Error("The sign-in form set no session cookie")
  return cookie
}

// browserSignIn drives a started `clavis login --no-browser` child whose
// stdout and stderr are pipes. baseURL is where requests go (the CLI's
// --server, possibly a port-forward); origin is the server's public origin the
// form checks, which defaults to baseURL. A sign-in the form refuses stops the
// CLI and returns { refused: true, status, page, code }; a completed one
// returns { code, result } with the CLI's parsed JSON result.
export async function browserSignIn({
  child,
  baseURL,
  origin = baseURL,
  username,
  password,
  timeoutMs = 60_000,
}) {
  let stdout = ""
  let stderr = ""
  child.stdout.on("data", (chunk) => {
    stdout += chunk.toString()
  })
  const closed = new Promise((resolve) =>
    child.once("close", (code) => resolve(code)),
  )
  const signal = AbortSignal.timeout(timeoutMs)
  const stopped = async () => {
    child.kill("SIGTERM")
    return await closed
  }
  try {
    const link = await new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("clavis login printed no sign-in link in time")),
        timeoutMs,
      )
      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString()
        const found = printedLink(stderr, baseURL)
        if (found) {
          clearTimeout(timer)
          resolve(found)
        }
      })
      closed.then((code) => {
        clearTimeout(timer)
        reject(new Error(`clavis login exited ${code} before printing a link`))
      })
    })
    const next = new URL(link).pathname + new URL(link).search
    const form = await fetch(`${baseURL}/login`, {
      method: "POST",
      redirect: "manual",
      headers: {
        Origin: origin,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ username, password, next }),
      signal,
    })
    const page = await form.text()
    if (form.status !== 303 || form.headers.get("location") !== next) {
      return { refused: true, status: form.status, page, code: await stopped() }
    }
    const cookie = sessionCookie(form)
    const authorize = await fetch(`${baseURL}${next}`, {
      redirect: "manual",
      headers: { Cookie: cookie },
      signal,
    })
    const document = await authorize.text()
    if (authorize.status !== 200 || !document.includes("Approve"))
      throw new Error(
        `The signed-in link answered ${authorize.status} without Approve`,
      )
    const fields = hiddenFields(document)
    const approve = await fetch(`${baseURL}/authorize`, {
      method: "POST",
      redirect: "manual",
      headers: {
        Origin: origin,
        Cookie: cookie,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams(fields),
      signal,
    })
    await approve.arrayBuffer()
    const callback = approve.headers.get("location") ?? ""
    if (
      approve.status !== 303 ||
      !callback.startsWith(`http://127.0.0.1:${fields.port}/callback?`)
    )
      throw new Error(
        `Approve answered ${approve.status} without the loopback callback`,
      )
    const answered = await fetch(callback, { redirect: "manual", signal })
    const confirmation = await answered.text()
    if (answered.status !== 200 || !confirmation.includes("Signed in."))
      throw new Error(`The CLI callback answered ${answered.status}`)
    const code = await Promise.race([
      closed,
      new Promise((_, reject) =>
        signal.addEventListener("abort", () =>
          reject(new Error("clavis login did not exit after the callback")),
        ),
      ),
    ])
    return { code, result: JSON.parse(stdout) }
  } catch (error) {
    if (child.exitCode === null && child.signalCode === null) await stopped()
    throw error
  }
}
