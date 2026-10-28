package processor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/sbi/consumer"
	"github.com/free5gc/pcf/internal/util"
	"github.com/free5gc/pcf/pkg/factory"
	"github.com/free5gc/util/idgenerator"
	"github.com/free5gc/util/mongoapi"
)

type allocationTestPCF struct {
	PCF
	ctx      *pcf_context.PCFContext
	consumer *consumer.Consumer
}

func (a *allocationTestPCF) Context() *pcf_context.PCFContext { return a.ctx }
func (a *allocationTestPCF) Config() *factory.Config          { return factory.PcfConfig }
func (a *allocationTestPCF) CancelContext() context.Context   { return context.Background() }
func (a *allocationTestPCF) Consumer() *consumer.Consumer     { return a.consumer }

// Use the driver's mock wire protocol, exercising the real mongoapi calls
// without requiring a running MongoDB, NRF, UDR, SMF, or UE.
func allocationTestProcessor(t *testing.T, mt *mtest.T, maxID int64, influences int) (
	*Processor, *pcf_context.UeContext, models.Pcf_SMPolCtrl_SmPolicyContextData,
) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	oldClient := mongoapi.Client
	mongoapi.Client = nil
	if err := mongoapi.SetMongoDB("pcf_allocation_test", "mongodb://127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	if err := mongoapi.Client.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	mongoapi.Client = mt.Client
	oldConfig := factory.PcfConfig
	factory.PcfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	t.Cleanup(func() { mongoapi.Client = oldClient; factory.PcfConfig = oldConfig })

	server := newAllocationTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/sm-data"):
			if _, err := fmt.Fprint(w, `{}`); err != nil {
				t.Error(err)
			}
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/influenceData"):
			data := make([]models.Udr_DR_TrafficInfluData, 0, influences)
			for i := 0; i < influences; i++ {
				data = append(data, models.Udr_DR_TrafficInfluData{
					ResUri: fmt.Sprintf("/influenceData/ti-%d", i),
					// Keep TI outside the existing 10.70.0.0/16 service rule so
					// each request exercises default-flow charging allocation.
					TrafficFilters: []models.Nef_FlowInfo{{FlowDescriptions: []string{
						fmt.Sprintf("permit out ip from 10.%d.0.0/16 to assigned", 80+i),
					}}},
					TrafficRoutes: []models.RouteToLocation{{Dnai: "mec"}},
				})
			}
			if err := json.NewEncoder(w).Encode(data); err != nil {
				t.Error(err)
			}
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/influenceData/subs-to-notify"):
			w.Header().Set("Location", "/influenceData/subs-to-notify/sub-1")
			w.WriteHeader(http.StatusCreated)
			if _, err := fmt.Fprint(w, `{}`); err != nil {
				t.Error(err)
			}
		default:
			t.Errorf("unexpected UDR request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	feature, err := openapi.NewSupportedFeature("0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := &pcf_context.PCFContext{
		RatingGroupIdGenerator: idgenerator.NewGenerator(1, maxID),
		PcfSuppFeats: map[models.Nrf_NFMgmt_ServiceName]openapi.SupportedFeature{
			models.Nrf_NFMgmt_ServiceName_NPCF_SMPOLICYCONTROL: feature,
		},
	}
	request := models.Pcf_SMPolCtrl_SmPolicyContextData{
		Supi: "imsi-001010000000001", PduSessionId: 2, Dnn: "internet", SuppFeat: "0",
		SliceInfo:      &models.Snssai{Sst: 1, Sd: "010203"},
		ServingNetwork: &models.PlmnIdNid{Mcc: "001", Mnc: "01"},
		AccessType:     models.AccessType_3_GPP_ACCESS,
		Ipv4Address:    "10.60.0.1",
		SubsDefQos:     &models.SubscribedDefaultQos{Var5qi: 9},
	}
	ue := &pcf_context.UeContext{
		Supi: request.Supi, UdrUri: server.URL,
		SmPolicyData:    make(map[string]*pcf_context.UeSmPolicyData),
		RatingGroupData: make(map[string][]int32),
		AMPolicyData: map[string]*pcf_context.UeAMPolicyData{
			"am": {ServingPlmn: request.ServingNetwork, AccessType: request.AccessType},
		},
	}
	ctx.UePool.Store(ue.Supi, ue)
	app := &allocationTestPCF{ctx: ctx}
	app.consumer, err = consumer.NewConsumer(app)
	if err != nil {
		t.Fatal(err)
	}
	return &Processor{PCF: app}, ue, request
}

func mockFind(coll string, docs ...bson.D) bson.D {
	return mtest.CreateCursorResponse(0, "pcf_allocation_test."+coll, mtest.FirstBatch, docs...)
}

func chargingSeed() bson.D {
	return bson.D{
		{Key: "ueId", Value: "imsi-001010000000001"},
		{Key: "snssai", Value: "01010203"},
		{Key: "dnn", Value: ""},
		{Key: "filter", Value: ""},
		{Key: "chargingMethod", Value: "Online"},
	}
}

func mockChargingInsert(mt *mtest.T) {
	mt.AddMockResponses(mockFind(chargingDataColl), mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}))
}

func assertProblem(t *testing.T, response *httptest.ResponseRecorder, status int, cause string) {
	t.Helper()
	var problem models.ProblemDetails
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if response.Code != status || int(problem.Status) != status || problem.Cause != cause {
		t.Errorf("unexpected error: HTTP %d, body %s", response.Code, response.Body.String())
	}
}

func TestCreateSmPolicyAllocationFailures(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	for _, tc := range []struct {
		name            string
		defaultCharging bool
		flow            bool
		influences      int
		maxID           int64
		wantSuccess     bool
		deleteFailure   bool
	}{
		{"1202_default", true, false, 0, 1, false, false},
		{"1204_first_flow", false, true, 0, 1, false, false},
		{"1204_flow_after_default", true, true, 0, 2, false, false},
		{"1203_second_influence", true, true, 2, 4, false, false},
		{"1203_rollback_delete_failure", true, true, 2, 4, false, true},
		{"successful_create", true, true, 2, 5, true, false},
	} {
		mt.Run(tc.name, func(mt *mtest.T) {
			p, ue, request := allocationTestProcessor(mt.T, mt, tc.maxID, tc.influences)
			generator := p.Context().RatingGroupIdGenerator
			holder, err := generator.Allocate()
			if err != nil {
				mt.Fatal(err)
			}
			holderID := ue.Supi + "-1"
			holderPolicy := ue.NewUeSmPolicyData(holderID, request, &models.Udr_DR_SmPolicyData{})
			ue.RatingGroupData[holderID] = []int32{int32(holder)}
			mt.AddMockResponses(mockFind(qosFlowDataColl))
			var flows []bson.D
			if tc.flow {
				flows = []bson.D{{
					{Key: "filter", Value: "10.70.0.0/16"},
					{Key: "precedence", Value: float64(128)},
					{Key: "qosRef", Value: float64(1)},
				}}
			}
			mt.AddMockResponses(mockFind(flowRuleDataColl, flows...))
			allocated := 0
			addCharging := func() bool {
				mt.AddMockResponses(mockFind(chargingDataColl, chargingSeed()))
				if int64(allocated)+1 == tc.maxID {
					return false
				}
				allocated++
				mockChargingInsert(mt)
				return true
			}
			proceed := true
			if tc.defaultCharging {
				proceed = addCharging()
			} else {
				mt.AddMockResponses(mockFind(chargingDataColl))
			}
			if proceed && tc.flow {
				proceed = addCharging()
			}
			for i := 0; proceed && i < tc.influences; i++ {
				proceed = addCharging()
			}
			if !tc.wantSuccess {
				for i := 0; i < allocated; i++ {
					if tc.deleteFailure && i == 0 {
						mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{
							Code: 2, Message: "injected delete failure",
						}))
						continue
					}
					mt.AddMockResponses(mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}))
				}
			}
			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			p.HandleCreateSmPolicyRequest(c, request)
			policyID := ue.Supi + "-2"
			if tc.wantSuccess {
				if response.Code != http.StatusCreated || response.Header().Get("Location") == "" {
					mt.Fatalf("create failed: %d %s", response.Code, response.Body.String())
				}
				if len(ue.SmPolicyData[policyID].PolicyDecision.PccRules) != 4 || len(ue.RatingGroupData[policyID]) != 4 {
					mt.Fatal("successful policy resources were rolled back")
				}
			} else {
				assertProblem(mt.T, response, http.StatusInternalServerError, util.INSUFFICIENT_RESOURCES)
				if ue.SmPolicyData[policyID] != nil {
					mt.Fatal("failed policy remains stored")
				}
				if _, ok := ue.RatingGroupData[policyID]; ok {
					mt.Fatal("failed policy rating groups remain")
				}
				if response.Header().Get("Location") != "" {
					mt.Fatal("failed create returned Location")
				}
				getResponse := httptest.NewRecorder()
				getCtx, _ := gin.CreateTestContext(getResponse)
				p.HandleGetSmPolicyContextRequest(getCtx, policyID)
				if getResponse.Code != http.StatusNotFound {
					mt.Fatalf("GET failed policy: %d", getResponse.Code)
				}
				reusable := tc.maxID - 1
				if tc.deleteFailure {
					reusable-- // The first charging copy remains in MongoDB.
				}
				for i := int64(0); i < reusable; i++ {
					id, allocErr := generator.Allocate()
					if allocErr != nil || id == holder || (tc.deleteFailure && id == holder+1) {
						mt.Fatalf("rating group leaked or holder freed: %d %v", id, allocErr)
					}
				}
			}
			if _, allocErr := generator.Allocate(); allocErr == nil {
				mt.Fatal("live rating group was freed")
			}
			if ue.SmPolicyData[holderID] != holderPolicy ||
				!reflect.DeepEqual(ue.RatingGroupData[holderID], []int32{int32(holder)}) {
				mt.Fatal("existing session changed")
			}
			deletes := 0
			for _, event := range mt.GetAllStartedEvents() {
				if event.CommandName == "delete" {
					deletes++
					entries, valuesErr := event.Command.Lookup("deletes").Array().Values()
					if valuesErr != nil {
						mt.Fatal(valuesErr)
					}
					filter := entries[0].Document().Lookup("q").Document()
					if filter.Lookup("ueId").StringValue() != ue.Supi || filter.Lookup("ratingGroup").Int32() == int32(holder) {
						mt.Fatal("cleanup includes unrelated charging data")
					}
				}
			}
			wantDeletes := allocated
			if tc.wantSuccess {
				wantDeletes = 0
			}
			if deletes != wantDeletes {
				mt.Fatalf("charging cleanup count %d, want %d", deletes, wantDeletes)
			}
		})
	}
}

func TestFailedCreatePreservesReplacedPolicy(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	for _, deleteFailure := range []bool{false, true} {
		mt.Run(fmt.Sprintf("existing_policy_delete_failure_%t", deleteFailure), func(mt *mtest.T) {
			p, ue, request := allocationTestProcessor(mt.T, mt, 2, 0)
			generator := p.Context().RatingGroupIdGenerator
			holder, err := generator.Allocate()
			if err != nil {
				mt.Fatal(err)
			}
			policyID := ue.Supi + "-2"
			previous := ue.NewUeSmPolicyData(policyID, request, &models.Udr_DR_SmPolicyData{})
			previous.PolicyDecision = &models.Pcf_SMPolCtrl_SmPolicyDecision{}
			ue.RatingGroupData[policyID] = []int32{int32(holder)}
			mt.AddMockResponses(mockFind(qosFlowDataColl), mockFind(flowRuleDataColl,
				bson.D{
					{Key: "filter", Value: "10.70.0.0/16"},
					{Key: "precedence", Value: float64(128)},
					{Key: "qosRef", Value: float64(1)},
				}),
				mockFind(chargingDataColl, chargingSeed()))
			mockChargingInsert(mt)
			mt.AddMockResponses(mockFind(chargingDataColl, chargingSeed()))
			if deleteFailure {
				mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{
					Code: 2, Message: "injected delete failure",
				}))
			} else {
				mt.AddMockResponses(mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}))
			}
			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			p.HandleCreateSmPolicyRequest(c, request)
			assertProblem(mt.T, response, http.StatusInternalServerError, util.INSUFFICIENT_RESOURCES)
			if ue.SmPolicyData[policyID] != previous ||
				!reflect.DeepEqual(ue.RatingGroupData[policyID], []int32{int32(holder)}) {
				mt.Fatal("failed replacement removed the existing session")
			}
			if !deleteFailure {
				if id, allocErr := generator.Allocate(); allocErr != nil || id == holder {
					mt.Fatalf("replacement rating group leaked or existing group freed: %d %v", id, allocErr)
				}
			}
			if _, allocErr := generator.Allocate(); allocErr == nil {
				mt.Fatal("existing rating group freed")
			}
		})
	}
}

// Successful replacement must relinquish the previous policy's rating groups.
// In particular, a later delete must not free the old and new generations twice.
func TestSuccessfulCreateReleasesReplacedPolicyGroups(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	for _, tc := range []struct {
		name           string
		createCharging bool
		deleteFailure  bool
	}{
		{name: "new_charging_group", createCharging: true},
		{name: "no_new_charging", createCharging: false},
		{name: "delete_failure_with_new_charging", createCharging: true, deleteFailure: true},
		{name: "delete_failure_without_new_charging", createCharging: false, deleteFailure: true},
	} {
		mt.Run(tc.name, func(mt *mtest.T) {
			p, ue, request := allocationTestProcessor(mt.T, mt, 2, 0)
			generator := p.Context().RatingGroupIdGenerator
			oldGroup, err := generator.Allocate()
			if err != nil {
				mt.Fatal(err)
			}
			policyID := ue.Supi + "-2"
			previous := ue.NewUeSmPolicyData(policyID, request, &models.Udr_DR_SmPolicyData{})
			previous.PolicyDecision = &models.Pcf_SMPolCtrl_SmPolicyDecision{}
			ue.RatingGroupData[policyID] = []int32{int32(oldGroup)}

			mt.AddMockResponses(mockFind(qosFlowDataColl), mockFind(flowRuleDataColl))
			if tc.createCharging {
				mt.AddMockResponses(mockFind(chargingDataColl, chargingSeed()))
				mockChargingInsert(mt)
			} else {
				mt.AddMockResponses(mockFind(chargingDataColl))
			}
			// Exercise a non-retryable MongoDB command error during commit.
			if tc.deleteFailure {
				mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{
					Code: 2, Message: "injected delete failure",
				}))
			} else {
				mt.AddMockResponses(mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}))
			}

			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			p.HandleCreateSmPolicyRequest(c, request)
			if response.Code != http.StatusCreated || response.Header().Get("Location") == "" {
				mt.Fatalf("replacement failed: HTTP %d %s", response.Code, response.Body.String())
			}
			if ue.SmPolicyData[policyID] == previous {
				mt.Fatal("previous policy was not replaced")
			}
			newGroups := ue.RatingGroupData[policyID]
			if tc.createCharging {
				if len(newGroups) != 1 || newGroups[0] == int32(oldGroup) {
					mt.Fatalf("old rating group retained by replacement: %v", newGroups)
				}
			} else if _, exists := ue.RatingGroupData[policyID]; exists {
				mt.Fatalf("replacement without charging retains old groups: %v", newGroups)
			}

			deletes := 0
			for _, event := range mt.GetAllStartedEvents() {
				if event.CommandName != "delete" {
					continue
				}
				deletes++
				entries, err := event.Command.Lookup("deletes").Array().Values()
				if err != nil {
					mt.Fatal(err)
				}
				filter := entries[0].Document().Lookup("q").Document()
				if filter.Lookup("ratingGroup").Int32() != int32(oldGroup) {
					mt.Fatal("replacement deleted another group's charging copy")
				}
			}
			if deletes != 1 {
				mt.Fatalf("charging cleanup count %d, want 1", deletes)
			}
			// Reacquire the released old ID. Any newly created group must remain
			// reserved until this replacement itself is deleted.
			gotOld := false
			reusable := 0
			for i := 0; i < 2; i++ {
				id, err := generator.Allocate()
				if err != nil {
					break
				}
				reusable++
				if tc.createCharging && id == int64(newGroups[0]) {
					mt.Fatal("new policy's rating group was freed")
				}
				if id == oldGroup {
					gotOld = true
				}
			}
			if gotOld == tc.deleteFailure {
				mt.Fatalf("old group reusable = %v, delete failure = %v", gotOld, tc.deleteFailure)
			}
			wantReusable := 2
			if tc.createCharging {
				wantReusable--
			}
			if tc.deleteFailure {
				wantReusable--
			}
			if reusable != wantReusable {
				mt.Fatalf("reusable groups = %d, want %d", reusable, wantReusable)
			}
		})
	}
}

func newAllocationTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server.Config.Protocols = protocols
	server.Start()
	t.Cleanup(server.Close)
	return server
}
