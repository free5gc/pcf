package sbi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestHTTPOAMGetAmPolicyDoesNotRegisterMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	server := &Server{router: router}
	wantHandlers := len(router.Handlers)

	for range 10 {
		response := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(response)

		server.HTTPOAMGetAmPolicy(ctx)

		if response.Code != http.StatusBadRequest {
			t.Fatalf("unexpected response status: got %d, want %d", response.Code, http.StatusBadRequest)
		}
	}

	if gotHandlers := len(router.Handlers); gotHandlers != wantHandlers {
		t.Fatalf("handler registered middleware during request: got %d handlers, want %d", gotHandlers, wantHandlers)
	}
}
