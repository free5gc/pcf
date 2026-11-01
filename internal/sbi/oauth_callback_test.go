package sbi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	nfcontext "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/pkg/factory"
)

type callbackOAuthApp struct {
	pcf
	cfg *factory.Config
	ctx *nfcontext.PCFContext
}

func (a *callbackOAuthApp) Config() *factory.Config        { return a.cfg }
func (a *callbackOAuthApp) Context() *nfcontext.PCFContext { return a.ctx }

// Use NewServer so this test also detects removal of callback middleware.
// Malformed JSON reaches the callback parser only after authorization succeeds.
func TestCallbackOAuthRoute(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	issuer, producer := uuid.NewString(), uuid.NewString()
	uri, err := url.Parse("urn:uuid:" + issuer)
	require.NoError(t, err)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	certPath := filepath.Join(t.TempDir(), "nrf.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	app := &callbackOAuthApp{cfg: &factory.Config{Configuration: &factory.Configuration{
		NfInstanceId: producer, Sbi: &factory.Sbi{BindingIPv4: "127.0.0.1", Port: 0},
		NrfUri: "http://127.0.0.1:8000", NrfCertPem: certPath,
	}}}
	app.ctx = &nfcontext.PCFContext{NfId: producer, NrfUri: app.cfg.Configuration.NrfUri, NrfCertPem: certPath}
	require.NoError(t, app.ctx.SetOAuth2Required(true))
	server, err := NewServer(app, "")
	require.NoError(t, err)
	for _, name := range []string{"missing", "valid", "wrong_scope", "wrong_audience", "expired", "disabled"} {
		t.Run(name, func(t *testing.T) {
			claims := jwt.MapClaims{
				"iss": issuer, "aud": producer,
				"exp": time.Now().Add(time.Hour).Unix(), "scope": "npcf-callback",
			}
			switch name {
			case "wrong_scope":
				claims["scope"] = "nnrf-disc"
			case "wrong_audience":
				claims["aud"] = uuid.NewString()
			case "expired":
				claims["exp"] = time.Now().Add(-time.Hour).Unix()
			case "disabled":
				require.NoError(t, app.ctx.SetOAuth2Required(false))
			}
			token, signErr := jwt.NewWithClaims(jwt.SigningMethodRS512, claims).SignedString(key)
			require.NoError(t, signErr)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
				factory.PcfCallbackResUriPrefix+"/amfstatus", strings.NewReader("{"))
			req.Header.Set("Content-Type", "application/json")
			if name != "missing" && name != "disabled" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			response := httptest.NewRecorder()
			server.router.ServeHTTP(response, req)
			want := http.StatusUnauthorized
			if name == "valid" || name == "disabled" {
				want = http.StatusBadRequest
			}
			require.Equal(t, want, response.Code, response.Body.String())
		})
	}
}
