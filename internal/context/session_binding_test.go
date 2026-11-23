package context

import (
	"testing"

	"github.com/free5gc/openapi/models"
)

// An AF request without SUPI or GPSI is bound by UE address. With more than
// one UE, each UE must be found by its own address. Before the fix the result
// was that of the last UE UePool.Range visited, so only that UE could be
// found; with three UEs at least two lookups fail, whatever the order.
func TestSessionBindingByIPv4WithSeveralUEs(t *testing.T) {
	ctx := &PCFContext{}
	ues := map[string]string{ // SUPI -> UE address
		"imsi-208930000000001": "10.72.0.1",
		"imsi-208930000000002": "10.72.0.2",
		"imsi-208930000000003": "10.72.0.3",
	}
	for supi, ip := range ues {
		ue, err := ctx.NewPCFUe(supi)
		if err != nil {
			t.Fatal(err)
		}
		ue.SmPolicyData[supi+"-1"] = &UeSmPolicyData{
			PolicyContext: &models.Pcf_SMPolCtrl_SmPolicyContextData{
				Supi: supi, PduSessionId: 1, Dnn: "ims", Ipv4Address: ip,
			},
		}
	}

	for supi, ip := range ues {
		policy, err := ctx.SessionBinding(&models.Pcf_PolAuth_AppSessionContextReqData{
			UeIpv4: ip, Dnn: "ims",
		})
		if err != nil {
			t.Fatalf("SessionBinding(%s): %v", ip, err)
		}
		if got := policy.PolicyContext.Supi; got != supi {
			t.Fatalf("SessionBinding(%s) bound %s, want %s", ip, got, supi)
		}
	}

	if _, err := ctx.SessionBinding(&models.Pcf_PolAuth_AppSessionContextReqData{
		UeIpv4: "10.72.0.9", Dnn: "ims",
	}); err == nil {
		t.Fatal("an address no UE has was bound")
	}
}
