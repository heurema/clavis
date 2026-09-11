package auth

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// CanonicalOrigin validates an external authentication origin, not a listener
// bind address. HTTP is allowed only for literal loopback addresses. The error
// never includes input; callers supply their own field or transport context.
func CanonicalOrigin(raw string) (string, error) {
	invalid := errors.New("invalid origin")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil ||
		u.Hostname() == "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") ||
		u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		strings.ContainsAny(raw, "\\?#") || strings.HasSuffix(u.Host, ":") {
		return "", invalid
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, "%") {
		return "", invalid
	}
	ip, ipErr := netip.ParseAddr(host)
	// Brackets belong only to IPv6 literals; bare IPv6 is not a URL authority.
	if strings.ContainsAny(u.Host, "[]") {
		if ipErr != nil || !ip.Is6() || !strings.HasPrefix(u.Host, "[") {
			return "", invalid
		}
	} else if strings.Contains(host, ":") {
		return "", invalid
	}
	if u.Scheme == "http" && (ipErr != nil || !ip.IsLoopback()) {
		return "", invalid
	}
	if ipErr == nil {
		host = ip.String()
	}
	port := u.Port()
	if port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return "", invalid
		}
		port = strconv.FormatUint(number, 10)
	}
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return u.Scheme + "://" + host, nil
}
