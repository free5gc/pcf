package processor

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/util"
	"github.com/free5gc/util/metrics/sbi"
)

// AF session termination initiated by the PCF, TS 29.514 clause 4.2.5.3, and the access network
// information requested at its deletion, TS 29.514 clause 4.2.4.6.

// appSessionTerminationTimeout bounds how long the PCF keeps an AF session it terminated for the
// NF service consumer to delete it. TS 29.514 does not specify it; on expiry the AF session is
// deleted.
var appSessionTerminationTimeout = 30 * time.Second

// accessNetworkInfoAtTermination returns the access network information the SMF provides when it
// terminates the SM policy association with the NetLoc feature (TS 29.512 clause 4.2.5.2), or nil.
func accessNetworkInfoAtTermination(smPolicy *pcf_context.UeSmPolicyData,
	deleteData *models.Pcf_SMPolCtrl_SmPolicyDeleteData,
) *models.Pcf_PolAuth_EventsNotification {
	if deleteData == nil || smPolicy.PolicyDecision == nil ||
		!util.CheckSuppFeat(smPolicy.PolicyDecision.SuppFeat, netLocFeature) {
		return nil
	}
	if deleteData.UserLocationInfo == nil && deleteData.UeTimeZone == "" && deleteData.ServingNetwork == nil {
		return nil
	}
	return &models.Pcf_PolAuth_EventsNotification{
		UeLoc:      deleteData.UserLocationInfo,
		UeLocTime:  deleteData.UserLocationInfoTime,
		UeTimeZone: deleteData.UeTimeZone,
		PlmnId:     deleteData.ServingNetwork,
	}
}

// terminateAppSessions requests the NF service consumers to delete the AF sessions of a terminated
// PDU session (TS 29.514 clause 4.2.5.3). The AF sessions are kept until the NF service consumers
// delete them, at most appSessionTerminationTimeout, so that the access network information provided
// by the SMF can be returned at their deletion (TS 29.514 clause 4.2.4.6).
func (p *Processor) terminateAppSessions(smPolicy *pcf_context.UeSmPolicyData,
	deleteData *models.Pcf_SMPolCtrl_SmPolicyDeleteData,
) {
	pcfSelf := p.Context()
	timeout := appSessionTerminationTimeout
	ani := accessNetworkInfoAtTermination(smPolicy, deleteData)
	terminationInfo := models.Pcf_PolAuth_TerminationInfo{
		TermCause: models.Pcf_PolAuth_TerminationCause_PDU_SESSION_TERMINATION,
	}

	// Collected first: a deletion resumed below removes its AF session from smPolicy.AppSessions.
	var appSessions []*pcf_context.AppSessionData
	for appSessionID := range smPolicy.AppSessions {
		if val, exist := pcfSelf.AppSessionPool.Load(appSessionID); exist {
			appSessions = append(appSessions, val.(*pcf_context.AppSessionData))
		}
	}
	for _, appSession := range appSessions {
		appSessionID := appSession.AppSessionId
		if !appSession.MarkTerminated(ani, timeout, func() {
			if _, ok := appSession.TakeTermination(); ok {
				pcfSelf.AppSessionPool.Delete(appSessionID)
				logger.PolicyAuthLog.Infof("App Session Id[%s] Del: not deleted by the NF service consumer within %s",
					appSessionID, timeout)
			}
		}) {
			// Already being deleted by the NF service consumer, possibly waiting for the access
			// network information from the SMF: it is the one provided at the termination.
			if ani != nil {
				appSession.DeliverAccessNetworkInfo(*ani)
			}
			continue
		}
		p.SendAppSessionTermination(appSession, terminationInfo)
		logger.SmPolicyLog.Tracef("SMPolicy Terminate Related AppSession[%s]", appSessionID)
	}
}

// deleteTerminatedAppSession handles the deletion of an AF session terminated by the PCF, and returns
// false if the AF session is not terminated. Its PDU session is terminated: the access network
// information requested at deletion is the one the SMF provided at the termination.
func (p *Processor) deleteTerminatedAppSession(c *gin.Context, appSession *pcf_context.AppSessionData,
	eventsSubscReqData *models.Pcf_PolAuth_EventsSubscReqData,
) bool {
	if !appSession.Terminated() {
		return false
	}
	var evsNotif *models.Pcf_PolAuth_EventsNotification
	var waitAni bool
	if smPolicy := appSession.SmPolicyData; smPolicy != nil && smPolicy.PolicyDecision != nil {
		var pd *models.ProblemDetails
		evsNotif, waitAni, pd = aniAtDeletion(eventsSubscReqData, negotiatedSuppFeat(appSession.AppSessionContext),
			smPolicy)
		if pd != nil {
			c.Set(sbi.IN_PB_DETAILS_CTX_STR, pd.Cause)
			c.JSON(int(pd.Status), pd)
			return true
		}
	}
	ani, ok := appSession.TakeTermination()
	if !ok {
		return false
	}
	p.Context().AppSessionPool.Delete(appSession.AppSessionId)
	logger.PolicyAuthLog.Infof("App Session Id[%s] Del", appSession.AppSessionId)

	if waitAni {
		evsNotif = nil
		if ani != nil {
			evsNotif = &models.Pcf_PolAuth_EventsNotification{
				EvNotifs: []models.Pcf_PolAuth_AfEventNotification{{Event: models.Pcf_PolAuth_AfEvent_ANI_REPORT}},
			}
			fillAccessNetworkInfo(evsNotif, *ani, eventsSubscReqData.ReqAnis)
		}
	}
	if evsNotif == nil {
		c.Status(http.StatusNoContent)
		return true
	}
	evsNotif.EvSubsUri = fmt.Sprintf("%s/events-subscription",
		util.GetResourceUri(models.Nrf_NFMgmt_ServiceName_NPCF_POLICYAUTHORIZATION, appSession.AppSessionId))
	c.JSON(http.StatusOK, models.Pcf_PolAuth_AppSessionContext{EvsNotif: evsNotif})
	return true
}
