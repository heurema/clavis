package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/heurema/clavis/internal/auth"
	urfave "github.com/urfave/cli/v3"
)

// browserLoginWait bounds how long login waits for an approved callback.
var browserLoginWait = 5 * time.Minute

// BrowserOpener asks the platform to show a link. Its failure never fails a
// sign-in: the link has already been printed.
type BrowserOpener func(ctx context.Context, link string) error

// OpenBrowser runs the platform opener without a shell, with the link as its
// only argument, and does not wait for it.
func OpenBrowser(_ context.Context, link string) error {
	name := map[string]string{"darwin": "open", "linux": "xdg-open"}[runtime.GOOS]
	if name == "" {
		return errors.New("no platform browser opener")
	}
	command := exec.Command(name, link)
	if err := command.Start(); err != nil {
		return err
	}
	go func() { _ = command.Wait() }()
	return nil
}

// signedInPage is the static document the loopback callback answers once.
const signedInPage = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Clavis</title></head>" +
	"<body><p>Signed in. You can return to the terminal.</p></body></html>\n"

func randomSecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// callbackHandler accepts exactly one GET /callback carrying the expected
// state, compared in constant time, and a well-formed code. Every other request
// is refused and the wait goes on.
func callbackHandler(state string, codes chan<- auth.Secret) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		values, err := url.ParseQuery(r.URL.RawQuery)
		code := auth.Secret(values.Get("code"))
		if err != nil || r.Method != http.MethodGet || len(values) != 2 || len(values["state"]) != 1 || len(values["code"]) != 1 ||
			subtle.ConstantTimeCompare([]byte(values.Get("state")), []byte(state)) != 1 || !auth.ValidToken(code) {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		select {
		case codes <- code:
		default:
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, signedInPage)
	})
}

// browserLogin signs the CLI in through the browser: a loopback listener, the
// printed authorization link, one approved callback and the code exchange. The
// session is stored under the per-origin lock only after the exchange, so a
// person approving in the browser never holds other commands' lock.
func browserLogin(ctx context.Context, command *urfave.Command, streams IO, origin string, timeout time.Duration) Result {
	// Unsafe storage fails before anything listens or is printed.
	lockCtx, cancel := context.WithTimeout(ctx, min(timeout, 5*time.Second))
	cache, err := openCache(lockCtx, origin)
	cancel()
	if err != nil {
		return storageFailure(err)
	}
	_, err = cache.read()
	cache.close()
	if err != nil {
		return storageFailure(err)
	}
	verifier, err := randomSecret()
	if err != nil {
		return failure("DEPENDENCY_UNAVAILABLE", "Local sign-in could not start", nil)
	}
	state, err := randomSecret()
	if err != nil {
		return failure("DEPENDENCY_UNAVAILABLE", "Local sign-in could not start", nil)
	}
	digest := sha256.Sum256([]byte(verifier))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return failure("DEPENDENCY_UNAVAILABLE", "Local sign-in could not start", nil)
	}
	codes := make(chan auth.Secret, 1)
	server := &http.Server{Handler: callbackHandler(state, codes), ReadHeaderTimeout: 5 * time.Second,
		ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	link := origin + auth.CLIAuthorization{
		Port:      listener.Addr().(*net.TCPAddr).Port,
		Challenge: base64.RawURLEncoding.EncodeToString(digest[:]),
		State:     state,
	}.Link()
	_, _ = fmt.Fprintf(streams.Stderr, "Open this link to sign in:\n%s\n", link)
	if !command.Bool("no-browser") && streams.OpenBrowser != nil {
		_ = streams.OpenBrowser(ctx, link)
	}

	wait := time.NewTimer(browserLoginWait)
	defer wait.Stop()
	var code auth.Secret
	select {
	case code = <-codes:
	case <-wait.C:
		return failure("TIMEOUT", "No sign-in was approved in time; run clavis login again", nil)
	case <-ctx.Done():
		return failure("TIMEOUT", "Sign-in was canceled", nil)
	}
	// Let the callback finish its page, then stop listening before the code
	// is redeemed.
	shutdownCtx, cancel := context.WithTimeout(ctx, time.Second)
	_ = server.Shutdown(shutdownCtx)
	cancel()

	api := authTransport{origin: origin, timeout: timeout}
	var issued auth.LoginResponse
	if failed := api.call(ctx, http.MethodPost, auth.TokenPath, "", &auth.TokenRequest{Code: code, Verifier: auth.Secret(verifier)}, &issued); failed != nil {
		return *failed
	}
	lockCtx, cancel = context.WithTimeout(ctx, min(timeout, 5*time.Second))
	cache, err = openCache(lockCtx, origin)
	cancel()
	if err != nil {
		api.cleanup(issued.Token)
		return storageFailure(err)
	}
	defer cache.close()
	previous, err := cache.read()
	if err == nil {
		err = cache.write(cachedSession{Origin: origin, LoginResponse: issued})
	}
	if err != nil {
		api.cleanup(issued.Token)
		return storageFailure(err)
	}
	if previous != nil && previous.Token != issued.Token {
		api.cleanup(previous.Token)
	}
	return success(issued.Identity)
}
