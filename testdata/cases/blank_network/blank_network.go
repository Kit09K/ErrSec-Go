// Package blank_network tests PatternBlank on net/http and net/ packages.
//
// ErrSec expected findings (3 sites, all RISK: HIGH):
//   SITE-1  blank identifier  net/http  FetchRemoteConfig  line 23
//   SITE-2  blank identifier  net/http  PostEvent          line 36
//   SITE-3  blank identifier  net       ResolveHost        line 47
package blank_network

import (
	"io"
	"net"
	"net/http"
)

// SITE-1: http.Get error discarded.
// Fail-open: if the GET fails, resp is nil — resp.Body.Close() panics,
// and the caller may use a nil response as "empty config" (availability + integrity).
func FetchRemoteConfig(url string) []byte {
	resp, _ := http.Get(url)
	if resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body) // SITE-1b: ReadAll error also discarded
	return body
}

// SITE-2: http.Post error discarded.
// Fail-open: audit events may be silently lost — an attacker who blocks
// the audit endpoint effectively disables logging of their own actions.
func PostEvent(endpoint string, body io.Reader) {
	resp, _ := http.Post(endpoint, "application/json", body)
	if resp != nil {
		resp.Body.Close()
	}
}

// SITE-3: net.LookupHost error discarded.
// Fail-open: DNS failure returns empty addrs — caller may treat empty
// as "host unreachable" but continue with a fallback that bypasses ACLs.
func ResolveHost(hostname string) []string {
	addrs, _ := net.LookupHost(hostname)
	return addrs
}

// CORRECT: all errors checked.
func SafeFetch(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
