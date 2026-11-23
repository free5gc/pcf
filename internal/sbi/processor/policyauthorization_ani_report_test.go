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

// Reports of access network information to AF sessions waiting for them (TS 29.514 clause 4.2.5.11).

const (
	aniTestAfURLA = "http://af-a.example/ani"
	aniTestAfURLB = "http://af-b.example/ani"
	aniTestSmfURL = "http://smf.example/sm-policy"
)

var (
	reqUserLocation = []models.Pcf_PolAuth_RequiredAccessInfo{models.Pcf_PolAuth_RequiredAccessInfo_USER_LOCATION}
	reqUeTimeZone   = []models.Pcf_PolAuth_RequiredAccessInfo{models.Pcf_PolAuth_RequiredAccessInfo_UE_TIME_ZONE}
	aniTestUeLoc    = &models.UserLocation{NrLocation: &models.NrLocation{
		Tai: &models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"},
	}}
)

// subscribeAni makes appSession wait for an ANI_REPORT, as after its subscription.
func subscribeAni(appSession *pcf_context.AppSessionData, afURL string,
	reqAnis []models.Pcf_PolAuth_RequiredAccessInfo,
) {
	appSession.Events = map[models.Pcf_PolAuth_AfEvent]models.Pcf_PolAuth_AfNotifMethod{
		models.Pcf_PolAuth_AfEvent_ANI_REPORT: models.Pcf_PolAuth_AfNotifMethod_ONE_TIME,
	}
	appSession.EventUri = afURL
	appSession.AppSessionContext.AscReqData.EvSubsc = &models.Pcf_PolAuth_EventsSubscReqData{ReqAnis: reqAnis}
	appSession.SmPolicyData.AddAccessNetworkInfoRequest(aniReqData(reqAnis),
		sortedPccRuleIds(appSession.RelatedPccRuleIds))
}

// addAniTestSession adds a second AF session bound to the SM policy of first.
func addAniTestSession(t *testing.T, first *pcf_context.AppSessionData, appSessionID, pccRuleID string,
) *pcf_context.AppSessionData {
	t.Helper()
	appSession := &pcf_context.AppSessionData{
		AppSessionId: appSessionID,
		AppSessionContext: &models.Pcf_PolAuth_AppSessionContext{
			AscReqData:  &models.Pcf_PolAuth_AppSessionContextReqData{},
			AscRespData: &models.Pcf_PolAuth_AppSessionContextRespData{SuppFeat: netLocSuppFeat},
		},
		RelatedPccRuleIds: map[string]string{"1": pccRuleID},
		SmPolicyData:      first.SmPolicyData,
	}
	first.SmPolicyData.AppSessions[appSessionID] = true
	pcf_context.GetSelf().AppSessionPool.Store(appSessionID, appSession)
	t.Cleanup(func() { pcf_context.GetSelf().AppSessionPool.Delete(appSessionID) })
	return appSession
}

// expectAfNotification captures the next event notification sent to afURL.
func expectAfNotification(afURL string, got *models.Pcf_PolAuth_EventsNotification) {
	gock.New(afURL).Post("/notify").AddMatcher(func(req *http.Request, _ *gock.Request) (bool, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return false, err
		}
		return true, json.Unmarshal(body, got)
	}).Reply(http.StatusNoContent)
}

// reportAni sends an SM policy update with the AN_INFO trigger and returns the decision answered.
func reportAni(t *testing.T, p *Processor, report models.Pcf_SMPolCtrl_SmPolicyUpdateContextData,
) models.Pcf_SMPolCtrl_SmPolicyDecision {
	t.Helper()
	report.RepPolicyCtrlReqTriggers = []models.Pcf_SMPolCtrl_PolicyControlRequestTrigger{
		models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_AN_INFO,
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	p.HandleUpdateSmPolicyContextRequest(c, aniTestSmPolicyID, report)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var decision models.Pcf_SMPolCtrl_SmPolicyDecision
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &decision))
	return decision
}

func interceptHTTP(t *testing.T) {
	t.Helper()
	openapi.InterceptInnerHttp2Client(t, false)
	t.Cleanup(gock.Off)
}

var anInfoTrigger = models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_AN_INFO

// Once reported, the one-time request is withdrawn from the SMF: lastReqRuleData and the AN_INFO
// trigger, while the triggers other AF sessions subscribed to are kept.
func TestAniReportWithdrawsRequest(t *testing.T) {
	interceptHTTP(t)
	p, appSession := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)
	subscribeAni(appSession, aniTestAfURLA, reqUeTimeZone)
	other := addAniTestSession(t, appSession, aniTestAppSessionID+"-b", "PccRuleId-2")
	other.Events = map[models.Pcf_PolAuth_AfEvent]models.Pcf_PolAuth_AfNotifMethod{
		models.Pcf_PolAuth_AfEvent_PLMN_CHG: models.Pcf_PolAuth_AfNotifMethod_EVENT_DETECTION,
	}
	decision := appSession.SmPolicyData.PolicyDecision
	decision.PolicyCtrlReqTriggers = append(decision.PolicyCtrlReqTriggers,
		models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_PLMN_CH)
	var got models.Pcf_PolAuth_EventsNotification
	expectAfNotification(aniTestAfURLA, &got)

	answered := reportAni(t, p, models.Pcf_SMPolCtrl_SmPolicyUpdateContextData{UeTimeZone: "+08:00"})

	require.True(t, gock.IsDone())
	require.Equal(t, "+08:00", got.UeTimeZone)
	require.Empty(t, answered.LastReqRuleData)
	require.NotContains(t, answered.PolicyCtrlReqTriggers, anInfoTrigger)
	require.Contains(t, answered.PolicyCtrlReqTriggers, models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_PLMN_CH)
}

// Overlapping requests: A requires the time zone, then B the location. The report answering A's
// request only carries the time zone: B keeps waiting, and gets the location from the next report.
func TestAniReportOverlappingRequests(t *testing.T) {
	interceptHTTP(t)
	p, sessionA := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)
	subscribeAni(sessionA, aniTestAfURLA, reqUeTimeZone)
	sessionB := addAniTestSession(t, sessionA, aniTestAppSessionID+"-b", "PccRuleId-2")
	subscribeAni(sessionB, aniTestAfURLB, reqUserLocation)

	var gotA models.Pcf_PolAuth_EventsNotification
	expectAfNotification(aniTestAfURLA, &gotA)
	answered := reportAni(t, p, models.Pcf_SMPolCtrl_SmPolicyUpdateContextData{UeTimeZone: "+08:00"})

	require.True(t, gock.IsDone(), "A gets its report")
	require.False(t, gock.HasUnmatchedRequest(), "B is not notified without the location")
	require.Equal(t, "+08:00", gotA.UeTimeZone)
	require.Contains(t, sessionB.Events, models.Pcf_PolAuth_AfEvent_ANI_REPORT)
	require.Equal(t, []models.Pcf_SMPolCtrl_RequestedRuleData{{
		RefPccRuleIds: []string{"PccRuleId-2"},
		ReqData:       []models.Pcf_SMPolCtrl_RequestedRuleDataType{models.Pcf_SMPolCtrl_RequestedRuleDataType_USER_LOC_INFO},
	}}, answered.LastReqRuleData, "the location is still requested")
	require.Contains(t, answered.PolicyCtrlReqTriggers, anInfoTrigger)

	var gotB models.Pcf_PolAuth_EventsNotification
	expectAfNotification(aniTestAfURLB, &gotB)
	answered = reportAni(t, p, models.Pcf_SMPolCtrl_SmPolicyUpdateContextData{
		UserLocationInfo: aniTestUeLoc, UeTimeZone: "+08:00",
	})

	require.True(t, gock.IsDone())
	require.Equal(t, aniTestUeLoc, gotB.UeLoc)
	require.Empty(t, gotB.UeTimeZone, "B did not require the time zone")
	require.Empty(t, answered.LastReqRuleData)
	require.NotContains(t, answered.PolicyCtrlReqTriggers, anInfoTrigger)
}

// The SMF does not have the information: after a second report without it, the AF gets what is
// available rather than waiting forever.
func TestAniReportIncompleteTwice(t *testing.T) {
	interceptHTTP(t)
	p, appSession := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)
	subscribeAni(appSession, aniTestAfURLA, append(reqUserLocation, reqUeTimeZone...))
	report := models.Pcf_SMPolCtrl_SmPolicyUpdateContextData{UeTimeZone: "+08:00"}

	answered := reportAni(t, p, report)
	require.False(t, gock.HasUnmatchedRequest())
	require.Contains(t, answered.PolicyCtrlReqTriggers, anInfoTrigger)

	var got models.Pcf_PolAuth_EventsNotification
	expectAfNotification(aniTestAfURLA, &got)
	answered = reportAni(t, p, report)

	require.True(t, gock.IsDone())
	require.Equal(t, "+08:00", got.UeTimeZone)
	require.Nil(t, got.UeLoc)
	require.NotContains(t, answered.PolicyCtrlReqTriggers, anInfoTrigger)
}

// TS 29.514 clause 5.6.2.9: "n3gppTai" and "n3IwfId" are not supplied to the AF within "n3gaLocation".
func TestAniReportN3gaLocation(t *testing.T) {
	reported := &models.UserLocation{N3gaLocation: &models.N3gaLocation{
		N3gppTai:   &models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"},
		N3IwfId:    "0102",
		UeIpv4Addr: "192.0.2.10",
		PortNumber: 4500,
	}}
	var notif models.Pcf_PolAuth_EventsNotification

	fillAccessNetworkInfo(&notif, models.Pcf_PolAuth_EventsNotification{UeLoc: reported}, reqUserLocation)

	require.Equal(t, &models.UserLocation{N3gaLocation: &models.N3gaLocation{
		UeIpv4Addr: "192.0.2.10",
		PortNumber: 4500,
	}}, notif.UeLoc)
	require.NotNil(t, reported.N3gaLocation.N3gppTai, "the reported location is not modified")
	require.Equal(t, "0102", reported.N3gaLocation.N3IwfId)
	require.Same(t, aniTestUeLoc, ueLocForAf(aniTestUeLoc), "other locations are reported as is")
}

// notifyAni sends an SM policy update notification to an SMF answering with campingRep.
func notifyAni(t *testing.T, p *Processor, appSession *pcf_context.AppSessionData,
	campingRep models.CreateSMPolicySmPolicyUpdateNotificationResponse200,
) {
	t.Helper()
	gock.New(aniTestSmfURL).Post("/update").Reply(http.StatusOK).JSON(campingRep)
	p.SendSMPolicyUpdateNotification(aniTestSmfURL, &models.Pcf_SMPolCtrl_SmPolicyNotification{
		ResourceUri:      "http://pcf.example/npcf-smpolicycontrol/v1/sm-policies/" + aniTestSmPolicyID,
		SmPolicyDecision: appSession.SmPolicyData.PolicyDecision,
	})
}

// TS 29.514 clause 4.2.4.6: the reason the access network does not support the report, received
// from the SMF, is provided to the AF in "noNetLocSupp".
func TestAniReportNotSupportedByAccessNetwork(t *testing.T) {
	interceptHTTP(t)
	p, appSession := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)
	subscribeAni(appSession, aniTestAfURLA, reqUserLocation)
	var got models.Pcf_PolAuth_EventsNotification
	expectAfNotification(aniTestAfURLA, &got)

	notifyAni(t, p, appSession, models.CreateSMPolicySmPolicyUpdateNotificationResponse200{
		NetLocAccSupp: models.Pcf_SMPolCtrl_NetLocAccessSupport_LOC_NOT_SUPPORTED,
	})

	require.True(t, gock.IsDone())
	require.Equal(t, models.Pcf_SMPolCtrl_NetLocAccessSupport_LOC_NOT_SUPPORTED, got.NoNetLocSupp)
	require.Equal(t, []models.Pcf_PolAuth_AfEventNotification{{Event: models.Pcf_PolAuth_AfEvent_ANI_REPORT}},
		got.EvNotifs)
	require.NotContains(t, appSession.Events, models.Pcf_PolAuth_AfEvent_ANI_REPORT)
	require.NotContains(t, appSession.SmPolicyData.PolicyDecision.PolicyCtrlReqTriggers, anInfoTrigger)
}

// The SMF may answer the notification with the access network information itself; when it is not
// what the AF session requires, the PCF asks again.
func TestAniReportInUeCampingRep(t *testing.T) {
	interceptHTTP(t)
	p, appSession := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)
	subscribeAni(appSession, aniTestAfURLA, reqUserLocation)
	// The SMF first answers with the time zone only...
	gock.New(aniTestSmfURL).Post("/update").Reply(http.StatusOK).
		JSON(models.CreateSMPolicySmPolicyUpdateNotificationResponse200{UeTimeZone: "+08:00"})
	var got models.Pcf_PolAuth_EventsNotification
	expectAfNotification(aniTestAfURLA, &got)

	// ...then with the location, when the PCF asks again.
	notifyAni(t, p, appSession, models.CreateSMPolicySmPolicyUpdateNotificationResponse200{
		UserLocationInfo: aniTestUeLoc,
	})

	require.True(t, gock.IsDone())
	require.Equal(t, aniTestUeLoc, got.UeLoc)
	require.NotContains(t, appSession.SmPolicyData.PolicyDecision.PolicyCtrlReqTriggers, anInfoTrigger)
}
