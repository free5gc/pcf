package consumer

import (
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"testing"
)

func TestPCFBindingIdentity(t *testing.T) {
	t.Run("IP", func(t *testing.T) {
		ctx := &pcf_context.PCFContext{RegisterIPv4: "10.101.200.19", SBIPort: 8000}
		fqdn, eps := pcfBindingIdentity(ctx)
		if fqdn != "" || len(eps) != 1 || eps[0].Ipv4Address != "10.101.200.19" {
			t.Fatalf("got fqdn %q endpoints %+v", fqdn, eps)
		}
	})
	t.Run("FQDN", func(t *testing.T) {
		ctx := &pcf_context.PCFContext{RegisterIPv4: "10.101.200.19", SBIPort: 8000, NfService: map[models.Nrf_NFMgmt_ServiceName]models.Nrf_NFMgmt_NFService{
			models.Nrf_NFMgmt_ServiceName_NPCF_POLICYAUTHORIZATION: {Fqdn: "pcf.example.org", IpEndPoints: []models.Nrf_NFMgmt_IpEndPoint{{Ipv4Address: "10.101.200.19", Port: 8000}}},
		}}
		fqdn, eps := pcfBindingIdentity(ctx)
		if fqdn != "pcf.example.org" || len(eps) != 1 {
			t.Fatalf("got fqdn %q endpoints %+v", fqdn, eps)
		}
	})
}
