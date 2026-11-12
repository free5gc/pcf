package context

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
)

// Exercise the actual OpenAPI HTTP client against a local NRF token endpoint.
// The endpoint is a fixture: NRF certificate and AllowedNfTypes enforcement
// require separate tests against the NRF implementation.
func TestOAuthMigrationTokenRequest(t *testing.T) {
	consumerID, nrfID := uuid.NewString(), uuid.NewString()
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/oauth2/token", r.URL.Path)
		if !assert.NoError(t, r.ParseForm()) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		assert.Equal(t, "client_credentials", r.PostForm.Get("grant_type"))
		assert.Equal(t, consumerID, r.PostForm.Get("nfInstanceId"))
		assert.Equal(t, "PCF", r.PostForm.Get("nfType"))
		assert.Equal(t, "NRF", r.PostForm.Get("targetNfType"))
		assert.Equal(t, "nnrf-disc", r.PostForm.Get("scope"))
		if n == 1 {
			assert.Empty(t, r.PostForm.Get("targetNfInstanceId"))
		} else {
			assert.Equal(t, nrfID, r.PostForm.Get("targetNfInstanceId"))
		}
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": fmt.Sprintf("fixture-token-%d", n), "token_type": "Bearer",
			"expires_in": 3600, "scope": "nnrf-disc",
		}))
	}))
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetHTTP1(true)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	defer server.Close()
	ctx := &PCFContext{NfId: consumerID, NrfUri: server.URL, NrfNfInstanceID: nrfID, OAuth2Required: true}
	scope := models.Nrf_NFMgmt_ServiceName_NNRF_DISC
	tokenValue := func(ctx context.Context) string {
		t.Helper()
		source, ok := ctx.Value(openapi.ContextOAuth2).(oauth2.TokenSource)
		require.True(t, ok)
		token, err := source.Token()
		require.NoError(t, err)
		return token.AccessToken
	}
	typeCtx, pd, err := ctx.GetTokenCtx(scope, models.Nrf_NFMgmt_NFType_NRF)
	require.NoError(t, err)
	require.Nil(t, pd)
	require.Equal(t, "fixture-token-1", tokenValue(typeCtx))
	instanceCtx, pd, err := ctx.GetTokenCtxForNRF(scope)
	require.NoError(t, err)
	require.Nil(t, pd)
	require.Equal(t, "fixture-token-2", tokenValue(instanceCtx))
	require.Equal(t, int32(2), calls.Load(), "instance targeting must not reuse a type-level token")
	cachedCtx, pd, err := ctx.GetTokenCtxForNRF(scope)
	require.NoError(t, err)
	require.Nil(t, pd)
	require.Equal(t, "fixture-token-2", tokenValue(cachedCtx))
	require.Equal(t, int32(2), calls.Load(), "identical requests should reuse a valid token")
	_, _, err = ctx.GetTokenCtxForNFInstance(scope, models.Nrf_NFMgmt_NFType_NRF, "invalid-id")
	require.Error(t, err)
	require.Equal(t, int32(2), calls.Load(), "invalid target must fail before sending a request")
	require.NoError(t, ctx.SetOAuth2Required(false))
	disabledCtx, pd, err := ctx.GetTokenCtxForNRF(scope)
	require.NoError(t, err)
	require.Nil(t, pd)
	require.Nil(t, disabledCtx.Value(openapi.ContextOAuth2))
	require.Equal(t, int32(2), calls.Load(), "disabled OAuth must not contact NRF")
}
