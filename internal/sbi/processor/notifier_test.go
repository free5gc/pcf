package processor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/util"
)

type trafficInfluenceTestPCF struct {
	PCF
	ctx *pcf_context.PCFContext
}

func (pcf *trafficInfluenceTestPCF) Context() *pcf_context.PCFContext {
	return pcf.ctx
}

func TestInfluenceNotificationBatchDeletion(t *testing.T) {
	processor, policy := newTrafficInfluenceTestProcessor(t)
	receivedChannel := make(chan *models.Pcf_SMPolCtrl_SmPolicyDecision, 1)
	callback := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var notification models.Pcf_SMPolCtrl_SmPolicyNotification
		if err := json.NewDecoder(r.Body).Decode(&notification); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		receivedChannel <- notification.SmPolicyDecision
		w.WriteHeader(http.StatusNoContent)
	}))
	callback.Config.Protocols = new(http.Protocols)
	callback.Config.Protocols.SetHTTP1(true)
	callback.Config.Protocols.SetUnencryptedHTTP2(true)
	callback.Start()
	defer callback.Close()
	policy.PolicyContext.NotificationUri = callback.URL
	ids := append(append([]string(nil), policy.InfluenceDataToPccRule["first"]...),
		policy.InfluenceDataToPccRule["second"]...)
	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	processor.HandleInfluenceDataUpdateNotify(ctx, "imsi-test", "1", []models.Udr_DR_TrafficInfluDataNotif{
		{ResUri: "/influenceData/first"}, {ResUri: "/influenceData/second"},
	})
	ctx.Writer.WriteHeaderNow()
	var received *models.Pcf_SMPolCtrl_SmPolicyDecision
	select {
	case received = <-receivedChannel:
	default:
		t.Fatal("SMF did not receive the TI batch notification")
	}
	if response.Code != http.StatusNoContent || received == nil {
		t.Fatalf("TI deletion callback failed: %d, %+v", response.Code, received)
	}
	for _, id := range ids {
		if value, exists := received.PccRules[id]; !exists || value != nil {
			t.Fatalf("batch deletion lost the marker for %s", id)
		}
	}
	if len(policy.PolicyDecision.PccRules) != 1 || len(policy.InfluenceDataToPccRule) != 0 {
		t.Fatal("batch deletion left TI rules in the cached policy")
	}
}

func TestInfluenceNotificationInvalidBatchDoesNotCommitDeletion(t *testing.T) {
	processor, policy := newTrafficInfluenceTestProcessor(t)
	before := append([]string(nil), policy.InfluenceDataToPccRule["first"]...)
	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	processor.HandleInfluenceDataUpdateNotify(ctx, "imsi-test", "1", []models.Udr_DR_TrafficInfluDataNotif{
		{ResUri: "/influenceData/first"},
		{ResUri: "/influenceData/bad", TrafficInfluData: &models.Udr_DR_TrafficInfluData{}},
	})
	ctx.Writer.WriteHeaderNow()
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid batch status = %d", response.Code)
	}
	if !reflect.DeepEqual(before, policy.InfluenceDataToPccRule["first"]) {
		t.Fatal("invalid batch partially removed cached TI ownership")
	}
	for _, id := range before {
		if policy.PolicyDecision.PccRules[id] == nil {
			t.Fatal("invalid batch partially removed cached TI rules")
		}
	}
}

func newTrafficInfluenceTestProcessor(t *testing.T) (*Processor, *pcf_context.UeSmPolicyData) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	base := util.CreateDefaultPccRules(1)
	policy := &pcf_context.UeSmPolicyData{
		PolicyContext: &models.Pcf_SMPolCtrl_SmPolicyContextData{Ipv4Address: "10.60.0.1"},
		PolicyDecision: &models.Pcf_SMPolCtrl_SmPolicyDecision{
			PccRules: map[string]*models.Pcf_SMPolCtrl_PccRule{base.PccRuleId: base},
		},
		PccRuleIdGenerator: 2,
	}
	data := models.Udr_DR_TrafficInfluData{
		TrafficFilters: []models.Nef_FlowInfo{{FlowDescriptions: []string{"permit out ip from any to assigned"}}},
		TrafficRoutes:  []models.RouteToLocation{{Dnai: "mec"}},
	}
	for _, id := range []string{"first", "second"} {
		if _, err := util.SetTrafficInfluencePolicy(policy, id, data, nil); err != nil {
			t.Fatal(err)
		}
	}
	ctx := &pcf_context.PCFContext{}
	ctx.UePool.Store("imsi-test", &pcf_context.UeContext{
		SmPolicyData: map[string]*pcf_context.UeSmPolicyData{"imsi-test-1": policy},
	})
	return &Processor{PCF: &trafficInfluenceTestPCF{ctx: ctx}}, policy
}
