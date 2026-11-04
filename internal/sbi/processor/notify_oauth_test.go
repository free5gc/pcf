package processor

import (
	"net/http"
	"testing"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
)

func TestSMPolicyNotificationWithoutOAuth(t *testing.T) {
	const baseURL = "http://smf.example"
	openapi.InterceptInnerHttp2Client(t, false)
	t.Cleanup(gock.Off)
	gock.New(baseURL).Post("/notify/update").AddMatcher(func(req *http.Request, _ *gock.Request) (bool, error) {
		_, present := req.Header["Authorization"]
		return !present, nil
	}).Reply(http.StatusNoContent)

	p := &Processor{}
	p.SendSMPolicyUpdateNotification(baseURL+"/notify", &models.Pcf_SMPolCtrl_SmPolicyNotification{})
	require.True(t, gock.IsDone(), "expected notification without Authorization")
}
