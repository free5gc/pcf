package util

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestOAuthChallenge(t *testing.T) {
	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"http://pcf.free5gc.org:8000/npcf-smpolicycontrol/v1/sm-policies/unknown", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	check := func(name, authorization, message string, expected int, required, forbidden string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			status, header, _ := oauthChallenge(
				req, "npcf-smpolicycontrol", authorization, errors.New(message),
				"http://pcf.free5gc.org:8000",
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

func TestChallengeIgnoresAttackerHost(t *testing.T) {
	r, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"http://pcf.free5gc.org:8000/npcf-smpolicycontrol/v1/invalid", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "attacker.example"
	_, header, _ := oauthChallenge(r, "npcf-smpolicycontrol", "", errors.New("missing"),
		"http://pcf.free5gc.org:8000")
	if strings.Contains(header, "attacker.example") || !strings.Contains(header, "pcf.free5gc.org:8000") {
		t.Fatalf("unsafe realm: %q", header)
	}
}

func TestOAuthChallengeNilAndHTTPS(t *testing.T) {
	r, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, "https://udr.free5gc.org:8000/nudr-dr/v2/lookup", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	r.TLS = &tls.ConnectionState{}
	status, header, _ := oauthChallenge(r, "nudr-dr", "Bearer bad", errors.New("invalid"), "https://udr.free5gc.org:8000")
	if status != 401 || !strings.Contains(header, `realm="https://udr.free5gc.org:8000/nudr-dr/v2"`) {
		t.Fatalf("HTTPS/version realm: status=%d header=%q", status, header)
	}
	status, header, reason := oauthChallenge(r, "nudr-dr", "", nil, "https://udr.free5gc.org:8000")
	if status != 0 || header != "" || reason != "" {
		t.Fatalf("unexpected response on nil error")
	}
}
