package processor

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/sbi/consumer"
	"github.com/free5gc/pcf/pkg/factory"
)

func TestConcurrentAMPolicyLifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldConfig := factory.PcfConfig
	factory.PcfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	t.Cleanup(func() { factory.PcfConfig = oldConfig })
	server := newAllocationTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprint(w, `{}`); err != nil {
			t.Errorf("write UDR response: %v", err)
		}
	}))
	feature, err := openapi.NewSupportedFeature("0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := &pcf_context.PCFContext{PcfSuppFeats: map[models.Nrf_NFMgmt_ServiceName]openapi.SupportedFeature{
		models.Nrf_NFMgmt_ServiceName_NPCF_AM_POLICY_CONTROL: feature,
	}}
	ue, err := ctx.NewPCFUe("imsi-001010000000001")
	if err != nil {
		t.Fatal(err)
	}
	ue.UdrUri = server.URL
	app := &allocationTestPCF{ctx: ctx}
	app.consumer, err = consumer.NewConsumer(app)
	if err != nil {
		t.Fatal(err)
	}
	p := &Processor{PCF: app}
	request := models.Pcf_AMPolCtrl_PolicyAssociationRequest{
		Supi:            ue.Supi,
		SuppFeat:        "0",
		NotificationUri: "http://localhost/notify",
		ServingPlmn:     &models.PlmnIdNid{Mcc: "001", Mnc: "01"},
		AccessType:      models.AccessType_3_GPP_ACCESS,
	}
	var wg sync.WaitGroup
	ids := make(chan string, 64)
	start := make(chan struct{})
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			response, location, pd := p.PostPoliciesProcedure("", request)
			if pd != nil || response == nil {
				t.Errorf("create failed: %+v", pd)
				return
			}
			id := path.Base(location)
			ids <- id
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			p.HandleGetPoliciesPolAssoId(c, id)
			update := models.Pcf_AMPolCtrl_PolicyAssociationUpdateRequest{
				NotificationUri: "http://localhost/updated",
			}
			_, pd = p.UpdatePostPoliciesPolAssoIdProcedure(id, update)
			if pd != nil {
				t.Errorf("update failed: %+v", pd)
			}
			if ue.FindAMPolicy(request.AccessType, request.ServingPlmn) == nil {
				t.Error("missing AM policy")
			}
			c, _ = gin.CreateTestContext(httptest.NewRecorder())
			p.HandleDeletePoliciesPolAssoId(c, id)
		}()
	}
	close(start)
	wg.Wait()
	close(ids)
	seen := map[string]bool{}
	for id := range ids {
		if seen[id] {
			t.Errorf("duplicate association ID %s", id)
		}
		seen[id] = true
	}
	if len(seen) != 64 {
		t.Errorf("created %d distinct associations, want 64", len(seen))
	}
	if len(ue.AMPolicyData) != 0 {
		t.Errorf("policies remain after deletion: %d", len(ue.AMPolicyData))
	}
}
