package processor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/mohae/deepcopy"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/util"
	"github.com/free5gc/pcf/pkg/factory"
	"github.com/free5gc/util/idgenerator"
	"github.com/free5gc/util/mongoapi"
)

type influenceTestPCF struct {
	PCF
	ctx *pcf_context.PCFContext
}

func (p *influenceTestPCF) Context() *pcf_context.PCFContext { return p.ctx }

// Exercise the actual handler and MongoDB wire operations with a bounded allocator.
func TestInfluenceNotificationAllocation(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	for _, tc := range []struct {
		name        string
		first       string
		maxID       int64
		invalidLast bool
		success     bool
		fault       string
	}{
		{"first_allocation_failure", "new", 1, false, false, ""},
		{"later_allocation_failure", "new", 2, false, false, ""},
		{"update_before_failure", "existing", 2, false, false, ""},
		{"delete_before_failure", "delete", 1, false, false, ""},
		{"validation_after_reservation", "new", 2, true, false, ""},
		{"successful_batch", "new", 3, false, true, ""},
		{"successful_update", "existing", 3, false, true, ""},
		{"panic_after_transfer", "existing", 3, false, false, "response"},
		{"invalid_charging_after_reservation", "new", 3, false, false, "charging"},
	} {
		mt.Run(tc.name, func(mt *mtest.T) {
			gin.SetMode(gin.TestMode)
			oldClient := mongoapi.Client
			mongoapi.Client = nil
			if err := mongoapi.SetMongoDB("pcf_influence_test", "mongodb://127.0.0.1:1"); err != nil {
				mt.Fatal(err)
			}
			if err := mongoapi.Client.Disconnect(context.Background()); err != nil {
				mt.Fatal(err)
			}
			mongoapi.Client = mt.Client
			oldConfig := factory.PcfConfig
			factory.PcfConfig = &factory.Config{Configuration: &factory.Configuration{}}
			mt.Cleanup(func() { mongoapi.Client = oldClient; factory.PcfConfig = oldConfig })

			var calls atomic.Int32
			notifications := make(chan models.Pcf_SMPolCtrl_SmPolicyNotification, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/update" {
					mt.Errorf("unexpected callback: %s %s", r.Method, r.URL.Path)
				}
				var body models.Pcf_SMPolCtrl_SmPolicyNotification
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					mt.Error(err)
				}
				notifications <- body
				w.WriteHeader(http.StatusNoContent)
			}))
			protocols := new(http.Protocols)
			protocols.SetHTTP1(true)
			protocols.SetUnencryptedHTTP2(true)
			server.Config.Protocols = protocols
			server.Start()
			mt.Cleanup(server.Close)

			generator := idgenerator.NewGenerator(1, tc.maxID)
			holder, err := generator.Allocate()
			if err != nil {
				mt.Fatal(err)
			}
			ue := &pcf_context.UeContext{
				Supi:            "imsi-001010000000001",
				SmPolicyData:    make(map[string]*pcf_context.UeSmPolicyData),
				RatingGroupData: make(map[string][]int32),
			}
			policyID := ue.Supi + "-1"
			base := util.CreateDefaultPccRules(1)
			policy := &pcf_context.UeSmPolicyData{
				PcfUe: ue, PccRuleIdGenerator: 2, ChargingIdGenerator: 2,
				PolicyContext: &models.Pcf_SMPolCtrl_SmPolicyContextData{NotificationUri: server.URL, Ipv4Address: "10.60.0.1"},
				PolicyDecision: &models.Pcf_SMPolCtrl_SmPolicyDecision{
					PccRules: map[string]*models.Pcf_SMPolCtrl_PccRule{base.PccRuleId: base},
				},
			}
			newData := func() *models.Udr_DR_TrafficInfluData {
				return &models.Udr_DR_TrafficInfluData{
					Snssai:         &models.Snssai{Sst: 1, Sd: "010203"},
					TrafficFilters: []models.Nef_FlowInfo{{FlowDescriptions: []string{"permit out ip from any to assigned"}}},
					TrafficRoutes:  []models.RouteToLocation{{Dnai: "mec"}},
				}
			}
			if tc.first != "new" {
				if _, err := util.SetTrafficInfluencePolicy(policy, "existing", *newData(), nil); err != nil {
					mt.Fatal(err)
				}
			}
			initialDecision := deepcopy.Copy(policy.PolicyDecision).(*models.Pcf_SMPolCtrl_SmPolicyDecision)
			ue.SmPolicyData[policyID] = policy
			ue.RatingGroupData[policyID] = []int32{int32(holder)}
			ctx := &pcf_context.PCFContext{RatingGroupIdGenerator: generator}
			ctx.UePool.Store(ue.Supi, ue)
			p := &Processor{PCF: &influenceTestPCF{ctx: ctx}}
			snapshot := func() ([]byte, error) {
				return json.Marshal([]interface{}{
					policy.PolicyDecision, policy.TrafficInfluence,
					policy.PccRuleIdGenerator, policy.ChargingIdGenerator, policy.PackFiltIdGenerator, policy.PackFiltMapToPccRuleId,
				})
			}
			before, err := snapshot()
			if err != nil {
				mt.Fatal(err)
			}
			batch := []models.Udr_DR_TrafficInfluDataNotif{
				{ResUri: "/influenceData/" + tc.first, TrafficInfluData: newData()},
				{ResUri: "/influenceData/last", TrafficInfluData: newData()},
			}
			if tc.first == "delete" {
				batch[0].ResUri = "/influenceData/existing"
				batch[0].TrafficInfluData = nil
			}
			if tc.invalidLast {
				batch[1].TrafficInfluData.Snssai = nil
			}
			seed := bson.D{
				{Key: "ueId", Value: ue.Supi},
				{Key: "snssai", Value: "01010203"},
				{Key: "dnn", Value: ""},
				{Key: "filter", Value: ""},
				{Key: "chargingMethod", Value: "Online"},
			}
			find := func(docs ...bson.D) bson.D {
				return mtest.CreateCursorResponse(0, "pcf_influence_test."+chargingDataColl, mtest.FirstBatch, docs...)
			}
			reads := 2
			if tc.first == "delete" || tc.invalidLast || tc.maxID == 1 {
				reads = 1
			}
			for i := 0; i < reads; i++ {
				if tc.fault == "charging" && i == 1 {
					seed[len(seed)-1].Value = 123
				}
				mt.AddMockResponses(find(seed))
			}
			if tc.success || tc.fault == "response" {
				for i := 0; i < 2; i++ {
					mt.AddMockResponses(find(), mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}))
				}
			}
			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			if tc.fault == "response" {
				// A missing response writer panics at the final HTTP status, after ownership transfer.
				defer func() {
					if recover() == nil {
						mt.Fatal("fixture did not reach the response write")
					}
					if want := []int32{int32(holder), 2, 3}; !reflect.DeepEqual(ue.RatingGroupData[policyID], want) {
						mt.Fatalf("unexpected ownership after panic: %v", ue.RatingGroupData[policyID])
					}
					for next := int64(4); next <= tc.maxID; next++ {
						id, err := generator.Allocate()
						if err != nil || id != next {
							mt.Fatalf("unexpected available rating group after panic: %d (%v)", id, err)
						}
					}
					if _, err := generator.Allocate(); err == nil {
						mt.Fatal("owned rating group released after panic")
					}
				}()
				p.HandleInfluenceDataUpdateNotify(&gin.Context{}, ue.Supi, "1", batch)
				return
			}
			p.HandleInfluenceDataUpdateNotify(c, ue.Supi, "1", batch)
			c.Writer.WriteHeaderNow()
			if tc.success {
				if response.Code != http.StatusNoContent || calls.Load() != 1 {
					mt.Fatalf("success: HTTP %d, callbacks %d", response.Code, calls.Load())
				}
				if len(policy.TrafficInfluence.Requests) != 2 || len(ue.RatingGroupData[policyID]) != 3 {
					mt.Fatal("new resources not retained")
				}
				select {
				case notification := <-notifications:
					got, marshalErr := json.Marshal(notification.SmPolicyDecision)
					if marshalErr != nil {
						mt.Fatal(marshalErr)
					}
					delta := util.TrafficInfluencePolicyChanges(initialDecision, policy.PolicyDecision)
					want, marshalErr := json.Marshal(delta)
					if marshalErr != nil {
						mt.Fatal(marshalErr)
					}
					if string(got) != string(want) {
						mt.Fatal("SMF received a different decision")
					}
				default:
					mt.Fatal("missing notification")
				}
			} else {
				wantStatus, wantCause := http.StatusInternalServerError, util.INSUFFICIENT_RESOURCES
				if tc.invalidLast {
					wantStatus, wantCause = http.StatusBadRequest, util.ERROR_REQUEST_PARAMETERS
				}
				if tc.fault == "charging" {
					wantCause = "SYSTEM_FAILURE"
				}
				var problem models.ProblemDetails
				if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
					mt.Fatal(err)
				}
				if response.Code != wantStatus || int(problem.Status) != wantStatus || problem.Cause != wantCause {
					mt.Fatalf("unexpected error: %d %s", response.Code, response.Body.String())
				}
				after, err := snapshot()
				if err != nil {
					mt.Fatal(err)
				}
				if string(before) != string(after) || ue.SmPolicyData[policyID] != policy {
					mt.Fatal("failed batch modified the live policy")
				}
				if !reflect.DeepEqual(ue.RatingGroupData[policyID], []int32{int32(holder)}) {
					mt.Fatal("failed batch changed rating group ownership")
				}
				if calls.Load() != 0 {
					mt.Fatal("failed batch notified SMF")
				}
				for _, event := range mt.GetAllStartedEvents() {
					if event.CommandName != "find" {
						mt.Fatalf("failed batch wrote to MongoDB: %s", event.CommandName)
					}
				}
				for i := int64(1); i < tc.maxID; i++ {
					id, allocErr := generator.Allocate()
					if allocErr != nil || id == holder {
						mt.Fatalf("reservation leaked or live ID freed: %d %v", id, allocErr)
					}
				}
			}
			if _, err := generator.Allocate(); err == nil {
				mt.Fatal("live rating group unexpectedly released")
			}
		})
	}
}
