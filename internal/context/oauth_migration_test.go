package context

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi/models"
)

// Exercise the NF context against the pinned OpenAPI implementation using real
// signed tokens and a temporary NRF certificate, without a deployed core.
func TestOAuthMigrationAuthorization(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	issuer, producer := uuid.NewString(), uuid.NewString()
	identity, err := url.Parse("urn:uuid:" + issuer)
	require.NoError(t, err)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{identity},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	certPath := filepath.Join(t.TempDir(), "nrf.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	ctx := &PCFContext{NfId: producer, NrfUri: "http://127.0.0.1:8000", NrfCertPem: certPath}
	require.NoError(t, ctx.SetOAuth2Required(true))
	require.True(t, ctx.OAuth2Required)
	require.Equal(t, issuer, ctx.NrfNfInstanceID)
	services := []models.Nrf_NFMgmt_ServiceName{
		models.Nrf_NFMgmt_ServiceName_NPCF_SMPOLICYCONTROL,
		ServiceNameNPCFCallback,
	}
	for _, service := range services {
		t.Run(string(service), func(t *testing.T) {
			for _, name := range []string{
				"valid_instance", "valid_type", "wrong_issuer", "wrong_audience",
				"expired", "missing_exp", "wrong_scope", "wrong_scheme", "bad_signature",
			} {
				t.Run(name, func(t *testing.T) {
					claims := jwt.MapClaims{
						"iss": issuer, "aud": producer,
						"exp": time.Now().Add(time.Hour).Unix(), "scope": string(service),
					}
					scheme := "Bearer "
					switch name {
					case "valid_type":
						claims["aud"] = "PCF"
					case "wrong_issuer":
						claims["iss"] = uuid.NewString()
					case "wrong_audience":
						claims["aud"] = uuid.NewString()
					case "expired":
						claims["exp"] = time.Now().Add(-time.Hour).Unix()
					case "missing_exp":
						delete(claims, "exp")
					case "wrong_scope":
						claims["scope"] = "unrelated-service"
					case "wrong_scheme":
						scheme = "Basic "
					}
					signingKey := key
					if name == "bad_signature" {
						signingKey, err = rsa.GenerateKey(rand.Reader, 2048)
						require.NoError(t, err)
					}
					token, signErr := jwt.NewWithClaims(jwt.SigningMethodRS512, claims).SignedString(signingKey)
					require.NoError(t, signErr)
					checkErr := ctx.AuthorizationCheck(scheme+token, service)
					if name == "valid_instance" || name == "valid_type" {
						require.NoError(t, checkErr)
					} else {
						require.Error(t, checkErr)
					}
				})
			}
		})
	}
	require.NoError(t, ctx.SetOAuth2Required(false))
	require.False(t, ctx.OAuth2Required)
	require.Empty(t, ctx.NrfNfInstanceID)
	require.NoError(t, ctx.AuthorizationCheck("", services[0]))
	_, pd, err := ctx.GetTokenCtxForNRF(models.Nrf_NFMgmt_ServiceName_NNRF_DISC)
	require.NoError(t, err)
	require.Nil(t, pd)
	require.NoError(t, os.WriteFile(certPath, []byte("invalid certificate"), 0o600))
	require.Error(t, ctx.SetOAuth2Required(true))
	require.False(t, ctx.OAuth2Required)
}
