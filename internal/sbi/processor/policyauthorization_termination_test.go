package processor

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h2non/gock"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
)

// AF session termination initiated by the PCF (TS 29.514 clause 4.2.5.3) and the access network
// information requested at its deletion (TS 29.514 clause 4.2.4.6).

var terminationTestUeLoc = &models.UserLocation{NrLocation: &models.NrLocation{
	Tai:  &models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"},
	Ncgi: &models.Ncgi{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, NrCellId: "000000010"},
	UeLocationTimestamp: func() *time.Time {
		ts := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
		return &ts
	}(),
}}

// terminateWithAni terminates the SM policy of the AF session as the SMF does when the PDU session
// is released, providing the access network information, and checks the AF is asked to delete it.
func terminateWithAni(t *testing.T, p *Processor, appSession *pcf_context.AppSessionData) {
	t.Helper()
	openapi.InterceptInnerHttp2Client(t, false)
	t.Cleanup(gock.Off)
	appSession.AppSessionContext.AscReqData.NotifUri = aniTestAfURL
	var termination models.Pcf_PolAuth_TerminationInfo
	gock.New(aniTestAfURL).Post("/terminate").
		AddMatcher(func(req *http.Request, _ *gock.Request) (bool, error) {
			raw, err := io.ReadAll(req.Body)
			if err != nil {
				return false, err
			}
			return true, json.Unmarshal(raw, &termination)
		}).Reply(http.StatusNoContent)

	p.terminateAppSessions(appSession.SmPolicyData, &models.Pcf_SMPolCtrl_SmPolicyDeleteData{
		UserLocationInfo: terminationTestUeLoc,
		UeTimeZone:       "+08:00",
		ServingNetwork:   &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
	})

	require.True(t, gock.IsDone(), "expected the AF to be asked to delete the AF session")
	require.Equal(t, models.Pcf_PolAuth_TerminationCause_PDU_SESSION_TERMINATION, termination.TermCause)
	require.True(t, appSession.Terminated())
}

func requireAppSessionRemoved(t *testing.T) {
	t.Helper()
	_, inPool := pcf_context.GetSelf().AppSessionPool.Load(aniTestAppSessionID)
	require.False(t, inPool)
}

// The AF session is kept after the termination, so that the AF deleting it receives the access
// network information provided by the SMF at the termination of the PDU session.
func TestTerminatedAppSessionDeletionReturnsAni(t *testing.T) {
	p, appSession := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)
	terminateWithAni(t, p, appSession)

	// Only the deletion is accessible.
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	p.HandleModAppSessionContext(c, aniTestAppSessionID, models.Pcf_PolAuth_AppSessionContextUpdateData{})
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	w = deleteWithAni(t, p, models.Pcf_PolAuth_RequiredAccessInfo_USER_LOCATION,
		models.Pcf_PolAuth_RequiredAccessInfo_UE_TIME_ZONE)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp models.Pcf_PolAuth_AppSessionContext
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.EvsNotif)
	require.Equal(t, []models.Pcf_PolAuth_AfEventNotification{{Event: models.Pcf_PolAuth_AfEvent_ANI_REPORT}},
		resp.EvsNotif.EvNotifs)
	require.Equal(t, terminationTestUeLoc, resp.EvsNotif.UeLoc)
	require.Equal(t, "+08:00", resp.EvsNotif.UeTimeZone)
	require.Nil(t, resp.EvsNotif.PlmnId, "the serving PLMN is only provided without location")
	require.NotEmpty(t, resp.EvsNotif.EvSubsUri)
	requireAppSessionRemoved(t)

	// Deleted once.
	w = deleteWithAni(t, p, models.Pcf_PolAuth_RequiredAccessInfo_USER_LOCATION)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

func TestTerminatedAppSessionDeletionSmfWithoutNetLoc(t *testing.T) {
	p, appSession := newAniTestSession(t, netLocSuppFeat, noNetLocSuppFeat)
	terminateWithAni(t, p, appSession)

	w := deleteWithAni(t, p, models.Pcf_PolAuth_RequiredAccessInfo_USER_LOCATION)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp models.Pcf_PolAuth_AppSessionContext
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.EvsNotif)
	require.Equal(t, models.Pcf_SMPolCtrl_NetLocAccessSupport_ANR_NOT_SUPPORTED, resp.EvsNotif.NoNetLocSupp)
	require.Nil(t, resp.EvsNotif.UeLoc)
	requireAppSessionRemoved(t)
}

func TestTerminatedAppSessionDeletionWithoutAniRequest(t *testing.T) {
	p, appSession := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)
	terminateWithAni(t, p, appSession)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	p.HandleDeleteAppSessionContext(c, aniTestAppSessionID, nil)
	c.Writer.WriteHeaderNow()

	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	requireAppSessionRemoved(t)
}

// An invalid request leaves the terminated AF session for a valid deletion.
func TestTerminatedAppSessionInvalidDeletion(t *testing.T) {
	p, appSession := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)
	terminateWithAni(t, p, appSession)

	w := deleteWithAni(t, p) // ANI_REPORT without reqAnis

	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.True(t, appSession.Terminated())
	w = deleteWithAni(t, p, models.Pcf_PolAuth_RequiredAccessInfo_UE_TIME_ZONE)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	requireAppSessionRemoved(t)
}

// A terminated AF session not deleted by the AF is removed after a while.
func TestTerminatedAppSessionCleanup(t *testing.T) {
	timeout := appSessionTerminationTimeout
	appSessionTerminationTimeout = 20 * time.Millisecond
	t.Cleanup(func() { appSessionTerminationTimeout = timeout })
	p, appSession := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)
	terminateWithAni(t, p, appSession)

	require.Eventually(t, func() bool {
		_, inPool := pcf_context.GetSelf().AppSessionPool.Load(aniTestAppSessionID)
		return !inPool
	}, 2*time.Second, 10*time.Millisecond)
	require.False(t, appSession.Terminated())
}

// An AF session the AF is deleting while waiting for the access network information gets the one
// provided at the termination of the PDU session; it is not asked to delete it again.
func TestTerminationResumesDeletionWaitingForAni(t *testing.T) {
	openapi.InterceptInnerHttp2Client(t, false)
	t.Cleanup(gock.Off)
	p, appSession := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)
	appSession.AppSessionContext.AscReqData.NotifUri = aniTestAfURL
	aniReport, ok := appSession.MarkDeleting(true)
	require.True(t, ok)

	p.terminateAppSessions(appSession.SmPolicyData, &models.Pcf_SMPolCtrl_SmPolicyDeleteData{
		UeTimeZone: "+08:00",
	})

	select {
	case reported := <-aniReport:
		require.Equal(t, "+08:00", reported.UeTimeZone)
	case <-time.After(time.Second):
		t.Fatal("expected the access network information")
	}
	require.False(t, gock.HasUnmatchedRequest(), "the AF is already deleting the AF session")
	require.False(t, appSession.Terminated())
}

func TestAccessNetworkInfoAtTermination(t *testing.T) {
	netLoc := &pcf_context.UeSmPolicyData{
		PolicyDecision: &models.Pcf_SMPolCtrl_SmPolicyDecision{SuppFeat: netLocSuppFeat},
	}
	noNetLoc := &pcf_context.UeSmPolicyData{
		PolicyDecision: &models.Pcf_SMPolCtrl_SmPolicyDecision{SuppFeat: noNetLocSuppFeat},
	}
	data := &models.Pcf_SMPolCtrl_SmPolicyDeleteData{UeTimeZone: "+08:00"}

	require.Equal(t, &models.Pcf_PolAuth_EventsNotification{UeTimeZone: "+08:00"},
		accessNetworkInfoAtTermination(netLoc, data))
	require.Nil(t, accessNetworkInfoAtTermination(noNetLoc, data))
	require.Nil(t, accessNetworkInfoAtTermination(netLoc, nil))
	require.Nil(t, accessNetworkInfoAtTermination(netLoc, &models.Pcf_SMPolCtrl_SmPolicyDeleteData{}))
}
