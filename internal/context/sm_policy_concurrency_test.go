package context

import (
	"fmt"
	"sync"
	"testing"

	"github.com/free5gc/openapi/models"
)

// The SMF creates and deletes SM policies for a UE's other PDU sessions while
// an AF app session is bound by the UE address, which walks the same UE's
// SmPolicyData. Run with -race.
func TestSMCreateDeleteVsSessionBinding(t *testing.T) {
	const supi = "imsi-208930000000001"
	ctx := &PCFContext{}
	ue, err := ctx.NewPCFUe(supi)
	if err != nil {
		t.Fatal(err)
	}
	ue.StoreSmPolicy(supi+"-1", &UeSmPolicyData{
		PolicyContext: &models.Pcf_SMPolCtrl_SmPolicyContextData{
			Supi: supi, PduSessionId: 1, Dnn: "ims", Ipv4Address: "10.72.0.1",
		},
	})

	var wg sync.WaitGroup
	for w := int32(0); w < 2; w++ {
		wg.Add(1)
		go func() { // SM policy create and delete, two PDU sessions at a time
			defer wg.Done()
			for i := int32(0); i < 1000; i++ {
				pduSessionID := 2 + w*5 + i%5
				smPolicyID := fmt.Sprintf("%s-%d", supi, pduSessionID)
				ue.NewUeSmPolicyData(smPolicyID, models.Pcf_SMPolCtrl_SmPolicyContextData{
					Supi: supi, PduSessionId: pduSessionID, Dnn: "internet",
					Ipv4Address: fmt.Sprintf("10.60.0.%d", pduSessionID),
				}, &models.Udr_DR_SmPolicyData{})
				ue.DeleteSmPolicy(smPolicyID)
			}
		}()
	}
	wg.Add(1)
	go func() { // app session create without SUPI
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			policy, err := ctx.SessionBinding(&models.Pcf_PolAuth_AppSessionContextReqData{
				UeIpv4: "10.72.0.1", Dnn: "ims",
			})
			if err != nil || policy.PolicyContext.PduSessionId != 1 {
				t.Errorf("SessionBinding(10.72.0.1) = %v, %v; want PDU session 1", policy, err)
				return
			}
		}
	}()
	wg.Wait()
}
