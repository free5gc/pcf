package processor

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/h2non/gock"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
)

const (
	aniTestSupi         = "imsi-208930000001241"
	aniTestSmPolicyID   = aniTestSupi + "-1"
	aniTestAppSessionID = aniTestSupi + "-1"
	aniTestAfURL        = "http://af.example/ani"
	// Supported features with only "NetLoc" (feature 6) set, and without it.
	netLocSuppFeat   = "20"
	noNetLocSuppFeat = "01"
)

// newAniTestSession stores an AF session bound to an SM policy in the PCF context. The global
// context is used because ArrangeExistEventSubscription looks AF sessions up through it.
func newAniTestSession(t *testing.T, afSuppFeat, smfSuppFeat string) (*Processor, *pcf_context.AppSessionData) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	pcfCtx := pcf_context.GetSelf()
	ue, err := pcf_context.NewUeContext(aniTestSupi)
	require.NoError(t, err)
	smPolicy := &pcf_context.UeSmPolicyData{
		PcfUe:          ue,
		AppSessions:    map[string]bool{aniTestAppSessionID: true},
		PolicyContext:  &models.Pcf_SMPolCtrl_SmPolicyContextData{PduSessionId: 1},
		PolicyDecision: &models.Pcf_SMPolCtrl_SmPolicyDecision{SuppFeat: smfSuppFeat},
	}
	ue.SmPolicyData[aniTestSmPolicyID] = smPolicy
	appSession := &pcf_context.AppSessionData{
		AppSessionId: aniTestAppSessionID,
		AppSessionContext: &models.Pcf_PolAuth_AppSessionContext{
			AscReqData:  &models.Pcf_PolAuth_AppSessionContextReqData{},
			AscRespData: &models.Pcf_PolAuth_AppSessionContextRespData{SuppFeat: afSuppFeat},
		},
		RelatedPccRuleIds: map[string]string{"1": "PccRuleId-1"},
		SmPolicyData:      smPolicy,
	}
	pcfCtx.UePool.Store(aniTestSupi, ue)
	pcfCtx.AppSessionPool.Store(aniTestAppSessionID, appSession)
	t.Cleanup(func() {
		pcfCtx.UePool.Delete(aniTestSupi)
		pcfCtx.AppSessionPool.Delete(aniTestAppSessionID)
	})
	return &Processor{PCF: &modAppSessionTestPCF{ctx: pcfCtx}}, appSession
}

func aniSubscription(reqAnis ...models.Pcf_PolAuth_RequiredAccessInfo) models.Pcf_PolAuth_EventsSubscReqData {
	return models.Pcf_PolAuth_EventsSubscReqData{
		Events: []models.Pcf_PolAuth_AfEventSubscription{{
			Event:       models.Pcf_PolAuth_AfEvent_ANI_REPORT,
			NotifMethod: models.Pcf_PolAuth_AfNotifMethod_ONE_TIME,
		}},
		NotifUri: aniTestAfURL,
		ReqAnis:  reqAnis,
	}
}

// TS 29.514 clause 4.2.6.6: the PCF immediately asks the SMF for the access network information.
func TestUpdateEventsSubscAniReportRequestsSmf(t *testing.T) {
	p, appSession := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	p.HandleUpdateEventsSubscContext(c, aniTestAppSessionID,
		aniSubscription(models.Pcf_PolAuth_RequiredAccessInfo_USER_LOCATION))

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp models.Pcf_PolAuth_EventsSubscPutData
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Empty(t, resp.NoNetLocSupp)
	require.Nil(t, resp.UeLoc, "the information is notified once reported by the SMF, not answered from the context")

	decision := appSession.SmPolicyData.PolicyDecision
	require.Contains(t, decision.PolicyCtrlReqTriggers, models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_AN_INFO)
	require.Equal(t, []models.Pcf_SMPolCtrl_RequestedRuleData{{
		RefPccRuleIds: []string{"PccRuleId-1"},
		ReqData:       []models.Pcf_SMPolCtrl_RequestedRuleDataType{models.Pcf_SMPolCtrl_RequestedRuleDataType_USER_LOC_INFO},
	}}, decision.LastReqRuleData)
	require.Contains(t, appSession.Events, models.Pcf_PolAuth_AfEvent_ANI_REPORT)
	require.Equal(t, []models.Pcf_PolAuth_RequiredAccessInfo{models.Pcf_PolAuth_RequiredAccessInfo_USER_LOCATION},
		appSessionReqAnis(appSession))
}

// TS 29.514 clause 4.2.6.6: without NetLoc support in the SMF, answer with noNetLocSupp.
func TestUpdateEventsSubscAniReportSmfWithoutNetLoc(t *testing.T) {
	p, appSession := newAniTestSession(t, netLocSuppFeat, noNetLocSuppFeat)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	p.HandleUpdateEventsSubscContext(c, aniTestAppSessionID,
		aniSubscription(models.Pcf_PolAuth_RequiredAccessInfo_USER_LOCATION))

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp models.Pcf_PolAuth_EventsSubscPutData
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, models.Pcf_SMPolCtrl_NetLocAccessSupport_ANR_NOT_SUPPORTED, resp.NoNetLocSupp)
	require.Equal(t, []models.Pcf_PolAuth_AfEventNotification{{Event: models.Pcf_PolAuth_AfEvent_ANI_REPORT}},
		resp.EvNotifs)

	decision := appSession.SmPolicyData.PolicyDecision
	require.NotContains(t, decision.PolicyCtrlReqTriggers, models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_AN_INFO)
	require.Empty(t, decision.LastReqRuleData)
	require.NotContains(t, appSession.Events, models.Pcf_PolAuth_AfEvent_ANI_REPORT)
}

// Without NetLoc negotiated with the NF service consumer, ANI_REPORT stays an unsupported event.
func TestUpdateEventsSubscAniReportNetLocNotNegotiated(t *testing.T) {
	p, appSession := newAniTestSession(t, noNetLocSuppFeat, netLocSuppFeat)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	// Not validated either: reqAnis is missing.
	p.HandleUpdateEventsSubscContext(c, aniTestAppSessionID, aniSubscription())

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	decision := appSession.SmPolicyData.PolicyDecision
	require.NotContains(t, decision.PolicyCtrlReqTriggers, models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_AN_INFO)
	require.Empty(t, decision.LastReqRuleData)
	require.NotContains(t, appSession.Events, models.Pcf_PolAuth_AfEvent_ANI_REPORT)
}

func TestUpdateEventsSubscAniReportWithoutReqAnis(t *testing.T) {
	p, appSession := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	p.HandleUpdateEventsSubscContext(c, aniTestAppSessionID, aniSubscription())

	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Empty(t, appSession.SmPolicyData.PolicyDecision.PolicyCtrlReqTriggers)
	require.Nil(t, appSession.Events)
}

// TS 29.514 clause 4.2.3.14: request of access network information at service information modification.
func TestModAppSessionAniReportRequestsSmf(t *testing.T) {
	p, appSession := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)

	var update models.Pcf_PolAuth_AppSessionContextUpdateData
	require.NoError(t, json.Unmarshal([]byte(`{"evSubsc":{"events":[{"event":"ANI_REPORT","notifMethod":"ONE_TIME"}],`+
		`"notifUri":"`+aniTestAfURL+`","reqAnis":["USER_LOCATION","UE_TIME_ZONE"]}}`), &update))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	p.HandleModAppSessionContext(c, aniTestAppSessionID, update)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	decision := appSession.SmPolicyData.PolicyDecision
	require.Contains(t, decision.PolicyCtrlReqTriggers, models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_AN_INFO)
	require.Equal(t, []models.Pcf_SMPolCtrl_RequestedRuleData{{
		RefPccRuleIds: []string{"PccRuleId-1"},
		ReqData: []models.Pcf_SMPolCtrl_RequestedRuleDataType{
			models.Pcf_SMPolCtrl_RequestedRuleDataType_USER_LOC_INFO,
			models.Pcf_SMPolCtrl_RequestedRuleDataType_MS_TIME_ZONE,
		},
	}}, decision.LastReqRuleData)
	require.Contains(t, appSession.Events, models.Pcf_PolAuth_AfEvent_ANI_REPORT)
	require.Len(t, appSessionReqAnis(appSession), 2)
}

// TS 29.514 clause 4.2.5.11: the access network information reported by the SMF is notified
// to the AF, limited to what it required, and the one-time subscription terminates.
func TestUpdateSmPolicyAnInfoNotifiesAf(t *testing.T) {
	ueLoc := &models.UserLocation{NrLocation: &models.NrLocation{
		Tai: &models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"},
	}}
	servingNetwork := &models.PlmnIdNid{Mcc: "208", Mnc: "93"}

	testCases := []struct {
		name       string
		reqAnis    []models.Pcf_PolAuth_RequiredAccessInfo
		report     models.Pcf_SMPolCtrl_SmPolicyUpdateContextData
		wantNotify models.Pcf_PolAuth_EventsNotification
	}{
		{
			name:    "user location only",
			reqAnis: []models.Pcf_PolAuth_RequiredAccessInfo{models.Pcf_PolAuth_RequiredAccessInfo_USER_LOCATION},
			report: models.Pcf_SMPolCtrl_SmPolicyUpdateContextData{
				UserLocationInfo: ueLoc,
				UeTimeZone:       "+08:00",
			},
			wantNotify: models.Pcf_PolAuth_EventsNotification{UeLoc: ueLoc},
		},
		{
			name: "location not available",
			reqAnis: []models.Pcf_PolAuth_RequiredAccessInfo{
				models.Pcf_PolAuth_RequiredAccessInfo_USER_LOCATION,
				models.Pcf_PolAuth_RequiredAccessInfo_UE_TIME_ZONE,
			},
			report: models.Pcf_SMPolCtrl_SmPolicyUpdateContextData{
				ServingNetwork: servingNetwork,
				UeTimeZone:     "+08:00",
			},
			wantNotify: models.Pcf_PolAuth_EventsNotification{PlmnId: servingNetwork, UeTimeZone: "+08:00"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p, appSession := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)
			appSession.Events = map[models.Pcf_PolAuth_AfEvent]models.Pcf_PolAuth_AfNotifMethod{
				models.Pcf_PolAuth_AfEvent_ANI_REPORT: models.Pcf_PolAuth_AfNotifMethod_ONE_TIME,
			}
			appSession.EventUri = aniTestAfURL
			appSession.AppSessionContext.AscReqData.EvSubsc = &models.Pcf_PolAuth_EventsSubscReqData{
				ReqAnis: tc.reqAnis,
			}
			smPolicy := appSession.SmPolicyData
			smPolicy.AddAccessNetworkInfoRequest(aniReqData(tc.reqAnis), []string{"PccRuleId-1"})

			openapi.InterceptInnerHttp2Client(t, false)
			t.Cleanup(gock.Off)
			var got models.Pcf_PolAuth_EventsNotification
			gock.New(aniTestAfURL).Post("/notify").AddMatcher(func(req *http.Request, _ *gock.Request) (bool, error) {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					return false, err
				}
				return true, json.Unmarshal(body, &got)
			}).Reply(http.StatusNoContent)

			report := tc.report
			report.RepPolicyCtrlReqTriggers = []models.Pcf_SMPolCtrl_PolicyControlRequestTrigger{
				models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_AN_INFO,
			}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			p.HandleUpdateSmPolicyContextRequest(c, aniTestSmPolicyID, report)

			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			require.True(t, gock.IsDone(), "expected an ANI_REPORT notification to the AF")
			want := tc.wantNotify
			want.EvNotifs = []models.Pcf_PolAuth_AfEventNotification{{Event: models.Pcf_PolAuth_AfEvent_ANI_REPORT}}
			want.EvSubsUri = got.EvSubsUri
			require.Equal(t, want, got)

			require.NotContains(t, appSession.Events, models.Pcf_PolAuth_AfEvent_ANI_REPORT)
			require.Empty(t, smPolicy.PolicyDecision.LastReqRuleData)
			if report.UserLocationInfo != nil {
				require.Equal(t, report.UserLocationInfo, smPolicy.PolicyContext.UserLocationInfo)
			}
		})
	}
}

func TestAniReqData(t *testing.T) {
	require.Equal(t, []models.Pcf_SMPolCtrl_RequestedRuleDataType{
		models.Pcf_SMPolCtrl_RequestedRuleDataType_MS_TIME_ZONE,
		models.Pcf_SMPolCtrl_RequestedRuleDataType_USER_LOC_INFO,
	}, aniReqData([]models.Pcf_PolAuth_RequiredAccessInfo{
		models.Pcf_PolAuth_RequiredAccessInfo_UE_TIME_ZONE,
		models.Pcf_PolAuth_RequiredAccessInfo_USER_LOCATION,
		models.Pcf_PolAuth_RequiredAccessInfo_UE_TIME_ZONE,
		"UNKNOWN",
	}))
	require.Empty(t, aniReqData(nil))
}
