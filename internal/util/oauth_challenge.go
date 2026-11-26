package util

import (
	"net/http"
	"strconv"
	"strings"
)

// scopeVerificationFailure is the exact post-signature-verification error
// emitted by the currently pinned github.com/free5gc/openapi/oauth.VerifyOAuth.
// Do not use substring matching: other errors must remain fail-closed as 401.
// TODO: switch to a typed sentinel error once OpenAPI exposes one.
const scopeVerificationFailure = "OAuth scope verification failed: insufficient permissions"

// oauthChallenge converts an OAuth verification error to the R17/RFC6750
// Bearer response. It does not interpret JWT claims or verify any token: the
// NFContext.AuthorizationCheck call must perform that work first.
func oauthChallenge(
	serviceName, authorization string, authErr error, realm string,
) (int, string, string) {
	if authErr == nil {
		return 0, "", ""
	}

	challenge := "Bearer realm=" + strconv.Quote(realm)

	fields := strings.Fields(authorization)
	hasBearerToken := len(fields) >= 2 && strings.EqualFold(fields[0], "Bearer") && fields[1] != ""
	if !hasBearerToken {
		// RFC6750 §3.1: a request without credentials should not contain an
		// OAuth error code in its initial challenge.
		return http.StatusUnauthorized, challenge, "unauthorized"
	}
	if authErr.Error() == scopeVerificationFailure {
		challenge += ", error=\"insufficient_scope\", scope=" + strconv.Quote(serviceName)
		return http.StatusForbidden, challenge, "insufficient_scope"
	}
	challenge += ", error=\"invalid_token\""
	return http.StatusUnauthorized, challenge, "invalid_token"
}
