package signal

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Origins are scheme + host + optional port, never URL prefixes or wildcards.
func canonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || u.Opaque != "" {
		return "", fmt.Errorf("allowed origin must be http(s)://host[:port] without credentials, path, query or fragment")
	}
	host := strings.ToLower(u.Hostname())
	if strings.ContainsAny(host, "* ,\\\t\r\n") {
		return "", fmt.Errorf("invalid origin host")
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return "", fmt.Errorf("invalid IPv6 origin")
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("empty origin port")
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid origin port")
		}
		port = strconv.Itoa(n)
	}
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return u.Scheme + "://" + host, nil
}

func originPolicy(origins []string) (func(*http.Request) bool, error) {
	if len(origins) == 0 {
		return nil, nil
	} // Preserve gorilla's default exactly.
	allowed := make(map[string]bool, len(origins))
	for _, origin := range origins {
		canonical, err := canonicalOrigin(strings.TrimSpace(origin))
		if err != nil {
			return nil, err
		}
		allowed[canonical] = true
	}
	return func(r *http.Request) bool {
		values, present := r.Header["Origin"]
		if !present {
			return true
		} // Native clients.
		if len(values) != 1 {
			return false
		}
		u, err := url.Parse(values[0])
		if err != nil {
			return false
		}
		// Keep the existing same-Host rule (including its scheme independence).
		if strings.EqualFold(u.Host, r.Host) {
			return true
		}
		canonical, err := canonicalOrigin(values[0])
		return err == nil && allowed[canonical]
	}, nil
}
