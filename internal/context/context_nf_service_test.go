package context

import (
	"testing"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pcf/pkg/factory"
)

func TestPCFRegistrationAPIPrefix(t *testing.T) {
	c := &PCFContext{
		UriScheme:    models.UriScheme_HTTP,
		RegisterIPv4: "127.0.0.7",
		SBIPort:      8000,
		NfService:    make(map[models.Nrf_NFMgmt_ServiceName]models.Nrf_NFMgmt_NFService),
	}
	c.InitNFService([]factory.Service{{ServiceName: "npcf-am-policy-control"}}, "1.0.2")
	s := c.NfService[models.Nrf_NFMgmt_ServiceName_NPCF_AM_POLICY_CONTROL]
	if s.ApiPrefix != "" {
		t.Fatalf("NFService.apiPrefix must be omitted when no deployment path exists; got %q", s.ApiPrefix)
	}
	if got := c.GetIPv4Uri(); got != "http://127.0.0.7:8000" {
		t.Fatalf("GetIPv4Uri for callbacks must remain functional: %q", got)
	}
}
