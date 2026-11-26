package util

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestOAuthChallenge(t *testing.T) {
	check := func(name, authorization, message string, expected int, required, forbidden string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			status, header, _ := oauthChallenge(
				"npcf-smpolicycontrol", authorization, errors.New(message),
				"http://pcf.free5gc.org:8000/npcf-smpolicycontrol/v1",
			)
			if status != expected {
				t.Fatalf("status = %d; want %d", status, expected)
			}
			if !strings.Contains(header, required) || strings.Contains(header, forbidden) {
				t.Fatalf("header %q; want %q and no %q", header, required, forbidden)
			}
		})
	}
	challenge := `Bearer realm="http://pcf.free5gc.org:8000/npcf-smpolicycontrol/v1"`
	check("missing", "", "missing bearer", http.StatusUnauthorized, challenge, `error=`)
	check("other-scheme", "Basic abc", "invalid bearer", http.StatusUnauthorized, challenge, `error=`)
	check("bare-bearer", "Bearer", "invalid bearer", http.StatusUnauthorized, challenge, `error=`)
	check("bearer-prefix", "BearerXYZ abc", "invalid bearer", http.StatusUnauthorized, challenge, `error=`)
	check("invalid", "Bearer invalid", "verify OAuth parse: malformed", http.StatusUnauthorized,
		`error="invalid_token"`, `insufficient_scope`)
	check("scope", "Bearer other.scope", scopeVerificationFailure, http.StatusForbidden,
		`error="insufficient_scope", scope="npcf-smpolicycontrol"`, `invalid_token`)
	check("partial-error", "Bearer invalid", scopeVerificationFailure+" extra", http.StatusUnauthorized,
		`error="invalid_token"`, `insufficient_scope`)
}

func TestOAuthChallengeNilAndHTTPS(t *testing.T) {
	const realm = "https://udr.free5gc.org:8000/nudr-dr/v2"
	status, header, _ := oauthChallenge("nudr-dr", "Bearer bad", errors.New("invalid"), realm)
	if status != 401 || !strings.Contains(header, `realm="https://udr.free5gc.org:8000/nudr-dr/v2"`) {
		t.Fatalf("HTTPS/version realm: status=%d header=%q", status, header)
	}
	status, header, reason := oauthChallenge("nudr-dr", "", nil, realm)
	if status != 0 || header != "" || reason != "" {
		t.Fatalf("unexpected response on nil error")
	}
}
