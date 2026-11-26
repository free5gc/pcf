package processor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h2non/gock"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
)

// Reports of access network information to deletions of AF sessions waiting for them
// (TS 29.514 clause 4.2.4.6).

// smfNotifications answers the SM policy update notifications of the PCF without the information
// (204 No Content), and signals each.
func smfNotifications(t *testing.T) <-chan struct{} {
	t.Helper()
	notified := make(chan struct{}, 8)
	settleBackgroundNotifications(t)
	gock.New(aniTestSmfURL).Post("/update").Persist().
		AddMatcher(func(*http.Request, *gock.Request) (bool, error) {
			notified <- struct{}{}
			return true, nil
		}).Reply(http.StatusNoContent)
	return notified
}

// settleBackgroundNotifications lets the notifications sent in the background complete before the
// HTTP interception of the test is removed: the removal of the PCC rules of a deleted AF session is
// notified in the background, and completes after the test has seen it. To call after intercepting.
func settleBackgroundNotifications(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { time.Sleep(50 * time.Millisecond) })
}

func awaitSmfNotification(t *testing.T, notified <-chan struct{}) {
	t.Helper()
	select {
	case <-notified:
	case <-time.After(time.Second):
		t.Fatal("expected an SM policy update notification to the SMF")
	}
}

// deleteInBackground deletes an AF session requiring reqAnis, and returns its response once deleted.
// It returns once the PCF requested the information from the SMF.
func deleteInBackground(t *testing.T, p *Processor, appSession *pcf_context.AppSessionData,
	reqAnis []models.Pcf_PolAuth_RequiredAccessInfo, notified <-chan struct{},
) <-chan *httptest.ResponseRecorder {
	t.Helper()
	done := make(chan *httptest.ResponseRecorder, 1)
	evSubsc := aniSubscription(reqAnis...)
	go func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		p.HandleDeleteAppSessionContext(c, appSession.AppSessionId, &evSubsc)
		c.Writer.WriteHeaderNow()
		done <- w
	}()
	awaitSmfNotification(t, notified)
	return done
}

func deletionResponse(t *testing.T, done <-chan *httptest.ResponseRecorder) models.Pcf_PolAuth_EventsNotification {
	t.Helper()
	select {
	case w := <-done:
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp models.Pcf_PolAuth_AppSessionContext
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.NotNil(t, resp.EvsNotif)
		require.Equal(t, []models.Pcf_PolAuth_AfEventNotification{{Event: models.Pcf_PolAuth_AfEvent_ANI_REPORT}},
			resp.EvsNotif.EvNotifs)
		return *resp.EvsNotif
	case <-time.After(2 * time.Second):
		t.Fatal("expected the deletion to be answered")
		return models.Pcf_PolAuth_EventsNotification{}
	}
}

// Overlapping requests at deletion: A requires the time zone, then B the location. The reports answering
// earlier time zone requests only carry the time zone: B keeps waiting however many arrive, and gets the
// location from the report answering its request.
func TestDeleteAppSessionAniOverlappingRequests(t *testing.T) {
	p, sessionA := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)
	sessionA.SmPolicyData.PolicyContext.NotificationUri = aniTestSmfURL
	sessionB := addAniTestSession(t, sessionA, aniTestAppSessionID+"-b", "PccRuleId-2")
	interceptHTTP(t)
	notified := smfNotifications(t)

	doneA := deleteInBackground(t, p, sessionA, reqUeTimeZone, notified)
	doneB := deleteInBackground(t, p, sessionB, reqUserLocation, notified)
	reportAni(t, p, models.Pcf_SMPolCtrl_SmPolicyUpdateContextData{UeTimeZone: "+08:00"})

	gotA := deletionResponse(t, doneA)
	require.Equal(t, "+08:00", gotA.UeTimeZone)
	awaitSmfNotification(t, notified) // removal of A's PCC rules
	select {
	case w := <-doneB:
		t.Fatalf("B answered without the location: %d %s", w.Code, w.Body.String())
	case <-time.After(100 * time.Millisecond):
	}

	// Another delayed report answering an earlier time zone request: B keeps waiting.
	reportAni(t, p, models.Pcf_SMPolCtrl_SmPolicyUpdateContextData{UeTimeZone: "+08:00"})
	select {
	case w := <-doneB:
		t.Fatalf("B answered without the location: %d %s", w.Code, w.Body.String())
	case <-time.After(100 * time.Millisecond):
	}

	reportAni(t, p, models.Pcf_SMPolCtrl_SmPolicyUpdateContextData{UserLocationInfo: aniTestUeLoc, UeTimeZone: "+08:00"})

	gotB := deletionResponse(t, doneB)
	require.Equal(t, aniTestUeLoc, gotB.UeLoc)
	require.Empty(t, gotB.UeTimeZone, "B did not require the time zone")
	awaitSmfNotification(t, notified) // removal of B's PCC rules
	_, inPool := pcf_context.GetSelf().AppSessionPool.Load(sessionB.AppSessionId)
	require.False(t, inPool)
}

// TS 29.514 clause 4.2.4.6: the reason the access network does not support the report, received from
// the SMF in its answer to the request, is provided in "noNetLocSupp" without waiting for the timeout.
func TestDeleteAppSessionAniNotSupportedByAccessNetwork(t *testing.T) {
	p, appSession := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)
	appSession.SmPolicyData.PolicyContext.NotificationUri = aniTestSmfURL
	interceptHTTP(t)
	// The request is answered with the reason, then the removal of the PCC rules with 204.
	gock.New(aniTestSmfURL).Post("/update").Reply(http.StatusOK).
		JSON(models.CreateSMPolicySmPolicyUpdateNotificationResponse200{
			NetLocAccSupp: models.Pcf_SMPolCtrl_NetLocAccessSupport_LOC_NOT_SUPPORTED,
		})
	notified := smfNotifications(t)

	start := time.Now()
	w := deleteWithAni(t, p, models.Pcf_PolAuth_RequiredAccessInfo_USER_LOCATION)
	awaitSmfNotification(t, notified) // removal of the PCC rules

	require.Less(t, time.Since(start), aniDeletionTimeout)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp models.Pcf_PolAuth_AppSessionContext
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.EvsNotif)
	require.Equal(t, models.Pcf_SMPolCtrl_NetLocAccessSupport_LOC_NOT_SUPPORTED, resp.EvsNotif.NoNetLocSupp)
	require.Equal(t, []models.Pcf_PolAuth_AfEventNotification{{Event: models.Pcf_PolAuth_AfEvent_ANI_REPORT}},
		resp.EvsNotif.EvNotifs)
	requireAppSessionDeleted(t, appSession)
}

// A reason only answers the information it is about: LOC_NOT_SUPPORTED does not answer a deletion
// requiring the time zone, which keeps waiting for it (TS 29.514 clause 4.2.4.6).
func TestDeleteAppSessionAniUnsupportedReasonPerInformation(t *testing.T) {
	p, appSession := newAniTestSession(t, netLocSuppFeat, netLocSuppFeat)
	appSession.SmPolicyData.PolicyContext.NotificationUri = aniTestSmfURL
	interceptHTTP(t)
	// The SMF answers the request of another AF session with LOC_NOT_SUPPORTED
	var otherRequest atomic.Bool
	reason := gock.New(aniTestSmfURL).Post("/update").
		AddMatcher(func(*http.Request, *gock.Request) (bool, error) { return otherRequest.Load(), nil })
	reason.Reply(http.StatusOK).JSON(models.CreateSMPolicySmPolicyUpdateNotificationResponse200{
		NetLocAccSupp: models.Pcf_SMPolCtrl_NetLocAccessSupport_LOC_NOT_SUPPORTED,
	})
	notified := smfNotifications(t)
	done := deleteInBackground(t, p, appSession, reqUeTimeZone, notified)

	otherRequest.Store(true)
	p.SendSMPolicyUpdateNotification(aniTestSmfURL, &models.Pcf_SMPolCtrl_SmPolicyNotification{
		ResourceUri: "http://pcf.example/npcf-smpolicycontrol/v1/sm-policies/" + aniTestSmPolicyID,
	})
	otherRequest.Store(false)
	require.True(t, reason.Mock.Done(), "expected the SMF to answer with the reason")
	select {
	case w := <-done:
		t.Fatalf("answered without the time zone: %d %s", w.Code, w.Body.String())
	case <-time.After(100 * time.Millisecond):
	}

	reportAni(t, p, models.Pcf_SMPolCtrl_SmPolicyUpdateContextData{UeTimeZone: "+08:00"})

	got := deletionResponse(t, done)
	require.Equal(t, "+08:00", got.UeTimeZone)
	require.Empty(t, got.NoNetLocSupp, "the reason is not about the time zone")
	awaitSmfNotification(t, notified) // removal of the PCC rules
}
