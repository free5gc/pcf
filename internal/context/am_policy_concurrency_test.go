package context

import (
	"sync"
	"testing"

	"github.com/free5gc/openapi/models"
)

func TestAMCreateVsSessionBinding(t *testing.T) {
	ctx := &PCFContext{}
	ue, err := ctx.NewPCFUe("imsi-001010000000001")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			ue.AMPolicyMu.Lock()
			ue.NewUeAMPolicyData("test", models.Pcf_AMPolCtrl_PolicyAssociationRequest{Gpsi: "msisdn-123"})
			ue.AMPolicyMu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			// This test only exercises GPSI lookup. It does not provide a UE IP.
			_, err := ctx.SessionBinding(&models.Pcf_PolAuth_AppSessionContextReqData{Gpsi: "msisdn-123"})
			if err == nil || err.Error() != "ue finding by MAC address does not support" {
				t.Errorf("SessionBinding returned unexpected error: %v", err)
				return
			}
		}
	}()
	wg.Wait()
}
