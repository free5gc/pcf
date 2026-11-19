package util

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi/models"
)

type oauthChallengeStub struct {
	err error
}

func (s oauthChallengeStub) AuthorizationCheck(_ string, _ models.Nrf_NFMgmt_ServiceName) error {
	return s.err
}

func TestRouterOAuthBearerResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name      string
		auth      string
		err       error
		status    int
		required  string
		forbidden string
	}{
		{
			name:      "missing bearer",
			err:       errors.New("verify OAuth Authorization header invalid"),
			status:    http.StatusUnauthorized,
			required:  `Bearer realm="http://localhost/npcf-smpolicycontrol/v1"`,
			forbidden: "error=",
		},
		{
			name:     "invalid bearer",
			auth:     "Bearer invalid.jwt.token",
			err:      errors.New("verify OAuth parse: invalid"),
			status:   http.StatusUnauthorized,
			required: `error="invalid_token"`,
		},
		{
			name:     "scope insufficient",
			auth:     "Bearer valid.other.scope",
			err:      errors.New(scopeVerificationFailure),
			status:   http.StatusForbidden,
			required: `error="insufficient_scope", scope="npcf-smpolicycontrol"`,
		},
		{
			name:   "valid bearer",
			auth:   "Bearer valid.jwt.token",
			status: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
				"http://pcf.free5gc.org:8000/npcf-smpolicycontrol/v1/sm-policies/unknown", nil)
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = req
			NewRouterAuthorizationCheck(models.Nrf_NFMgmt_ServiceName("npcf-smpolicycontrol")).
				Check(ctx, oauthChallengeStub{err: tt.err})
			if recorder.Code != tt.status {
				t.Fatalf("status: got %d want %d: %s", recorder.Code, tt.status, recorder.Body.String())
			}
			header := recorder.Header().Get("WWW-Authenticate")
			if !strings.Contains(header, tt.required) ||
				(tt.forbidden != "" && strings.Contains(header, tt.forbidden)) {
				t.Fatalf("challenge: got %q, required %q, forbidden %q", header, tt.required, tt.forbidden)
			}
		})
	}
}
