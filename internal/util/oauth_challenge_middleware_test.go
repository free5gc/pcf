package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/pkg/factory"
)

func TestRouterOAuthBearerResponse(t *testing.T) {
	const (
		service = "npcf-smpolicycontrol"
		path    = "/" + service + "/v1/sm-policies/test"
		realm   = `Bearer realm="http://pcf.free5gc.org:8000/npcf-smpolicycontrol/v1"`
		invalid = realm + `, error="invalid_token"`
	)

	originalConfig := factory.PcfConfig
	t.Cleanup(func() { factory.PcfConfig = originalConfig })
	factory.PcfConfig = &factory.Config{Configuration: &factory.Configuration{
		Sbi: &factory.Sbi{Scheme: "http", RegisterIPv4: "pcf.free5gc.org", Port: 8000},
	}}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(t.TempDir(), "nrf.pem")
	encodedKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKey})
	if err := os.WriteFile(certPath, encodedKey, 0o600); err != nil {
		t.Fatal(err)
	}
	pcf := &pcf_context.PCFContext{
		NfId: "pcf-instance", NrfNfInstanceID: "nrf-instance", NrfCertPem: certPath, OAuth2Required: true,
	}
	signed := func(issuer, audience, scope string, withExpiry bool) string {
		t.Helper()
		claims := jwt.MapClaims{"iss": issuer, "aud": audience, "scope": scope}
		if withExpiry {
			claims["exp"] = time.Now().Add(time.Hour).Unix()
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodRS512, claims).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return "Bearer " + token
	}

	tests := []struct {
		name, authorization string
		status              int
		challenge           string
	}{
		{"missing token", "", http.StatusUnauthorized, realm},
		{"invalid token", "Bearer malformed", http.StatusUnauthorized, invalid},
		{"wrong audience and scope", signed(pcf.NrfNfInstanceID, "other", "other", true), http.StatusUnauthorized, invalid},
		{"wrong issuer", signed("other", "PCF", service, true), http.StatusUnauthorized, invalid},
		{"missing expiration", signed(pcf.NrfNfInstanceID, "PCF", service, false), http.StatusUnauthorized, invalid},
		{
			"insufficient scope", signed(pcf.NrfNfInstanceID, pcf.NfId, "other", true), http.StatusForbidden,
			realm + `, error="insufficient_scope", scope="npcf-smpolicycontrol"`,
		},
		{"authorized", signed(pcf.NrfNfInstanceID, "PCF", service, true), http.StatusNoContent, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			reached := false
			router.GET(path, func(c *gin.Context) {
				NewRouterAuthorizationCheck(service).Check(c, pcf)
			}, func(c *gin.Context) {
				reached = true
				c.Status(http.StatusNoContent)
			})
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tt.status || reached != (tt.status == http.StatusNoContent) {
				t.Fatalf("status=%d handler reached=%v", rec.Code, reached)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != tt.challenge {
				t.Fatalf("challenge=%q want %q", got, tt.challenge)
			}
			if reached {
				return
			}
			if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
				t.Fatalf("Content-Type=%q", got)
			}
			var problem models.ProblemDetails
			if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if problem.Status != int32(tt.status) || problem.Title != http.StatusText(tt.status) {
				t.Fatalf("unexpected ProblemDetails: %+v", problem)
			}
		})
	}
}
