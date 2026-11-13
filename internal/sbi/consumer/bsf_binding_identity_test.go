package consumer

import (
	"reflect"
	"testing"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
)

func TestPCFBindingIdentity(t *testing.T) {
	tcp := models.Nrf_NFMgmt_TransportProtocol_TCP
	tests := []struct {
		name     string
		ctx      *pcf_context.PCFContext
		wantFQDN string
		wantEps  []models.Nrf_NFMgmt_IpEndPoint
	}{
		{
			name: "PolicyAuthorization_service",
			ctx: &pcf_context.PCFContext{
				RegisterIPv4: "10.0.0.1",
				SBIPort:      8000,
				NfService: map[models.Nrf_NFMgmt_ServiceName]models.Nrf_NFMgmt_NFService{
					models.Nrf_NFMgmt_ServiceName_NPCF_POLICYAUTHORIZATION: {
						Fqdn:        "pcf.example.org",
						IpEndPoints: []models.Nrf_NFMgmt_IpEndPoint{{Transport: tcp, Port: 8000}},
					},
				},
			},
			wantFQDN: "pcf.example.org",
			wantEps:  []models.Nrf_NFMgmt_IpEndPoint{{Transport: tcp, Port: 8000}},
		},
		{
			name:    "Fallback_IP",
			ctx:     &pcf_context.PCFContext{RegisterIPv4: "10.0.0.1", SBIPort: 8000},
			wantEps: []models.Nrf_NFMgmt_IpEndPoint{{Ipv4Address: "10.0.0.1", Transport: tcp, Port: 8000}},
		},
		{
			name:     "Fallback_hostname",
			ctx:      &pcf_context.PCFContext{RegisterIPv4: "pcf.free5gc.org", SBIPort: 8000},
			wantFQDN: "pcf.free5gc.org",
			wantEps:  []models.Nrf_NFMgmt_IpEndPoint{{Transport: tcp, Port: 8000}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fqdn, eps := pcfBindingIdentity(tt.ctx)
			if fqdn != tt.wantFQDN || !reflect.DeepEqual(eps, tt.wantEps) {
				t.Fatalf("got (%q, %+v), want (%q, %+v)", fqdn, eps, tt.wantFQDN, tt.wantEps)
			}
		})
	}
}
