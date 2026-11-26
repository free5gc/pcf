package sbi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi/models"
	nfcontext "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/sbi/processor"
	"github.com/free5gc/pcf/pkg/factory"
)

type callbackOAuthApp struct {
	pcf
	cfg *factory.Config
	ctx *nfcontext.PCFContext
}

func (a *callbackOAuthApp) Config() *factory.Config        { return a.cfg }
func (a *callbackOAuthApp) Context() *nfcontext.PCFContext { return a.ctx }

func (a *callbackOAuthApp) Processor() *processor.Processor { return &processor.Processor{PCF: a} }

func TestCallbackOAuthRoute(t *testing.T) {
	app := &callbackOAuthApp{cfg: &factory.Config{Configuration: &factory.Configuration{
		Sbi: &factory.Sbi{BindingIPv4: "127.0.0.1", Port: 0},
	}}}
	const service = models.Nrf_NFMgmt_ServiceName_NPCF_AM_POLICY_CONTROL
	const realm = "https://advertised.example:8443/npcf-am-policy-control/v1"
	app.ctx = &nfcontext.PCFContext{
		OAuth2Required: true, UriScheme: models.UriScheme_HTTP,
		RegisterIPv4: "pcf.example", SBIPort: 8000,
		PcfServiceUris: map[models.Nrf_NFMgmt_ServiceName]string{service: "http://:8000/npcf-am-policy-control/v1"},
	}
	_, err := NewServer(app, "")
	require.ErrorContains(t, err, string(service))
	app.ctx.PcfServiceUris[service] = realm
	server, err := NewServer(app, "")
	require.NoError(t, err)
	for _, tc := range []struct {
		path string
		body string
		want int
	}{
		{"/amfstatus", `{"amfStatusInfoList":[]}`, http.StatusNoContent},
		{"/nudr-notify/policy-data/imsi-1", "{}", http.StatusNotImplemented},
		{"/nudr-notify/influence-data/imsi-1/1", "[]", http.StatusNotFound},
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
			factory.PcfCallbackResUriPrefix+tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		server.router.ServeHTTP(response, req)
		require.Equal(t, tc.want, response.Code, tc.path)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		factory.PcfAMpolicyCtlResUriPrefix+"/policies", strings.NewReader("{"))
	response := httptest.NewRecorder()
	server.router.ServeHTTP(response, req)
	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.Equal(t, `Bearer realm="`+realm+`"`, response.Header().Get("WWW-Authenticate"))
}
