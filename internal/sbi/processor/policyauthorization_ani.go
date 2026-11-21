package processor

import (
	"slices"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/util"
)

// Request and report of access network information (ANI_REPORT),
// TS 29.514 clauses 4.2.2.14, 4.2.3.14, 4.2.5.11 and 4.2.6.6.

// netLocFeature is the number of the "NetLoc" feature in both TS 29.514 and TS 29.512 (clause 5.8).
const netLocFeature = 6

func hasAniReportEvent(events []models.Pcf_PolAuth_AfEventSubscription) bool {
	return slices.ContainsFunc(events, func(subs models.Pcf_PolAuth_AfEventSubscription) bool {
		return subs.Event == models.Pcf_PolAuth_AfEvent_ANI_REPORT
	})
}

// aniReqData maps the access network information required by the AF ("reqAnis")
// to the rule data requested from the SMF ("reqData" of "lastReqRuleData").
func aniReqData(reqAnis []models.Pcf_PolAuth_RequiredAccessInfo) []models.Pcf_SMPolCtrl_RequestedRuleDataType {
	var reqData []models.Pcf_SMPolCtrl_RequestedRuleDataType
	for _, reqAni := range reqAnis {
		var data models.Pcf_SMPolCtrl_RequestedRuleDataType
		switch reqAni {
		case models.Pcf_PolAuth_RequiredAccessInfo_USER_LOCATION:
			data = models.Pcf_SMPolCtrl_RequestedRuleDataType_USER_LOC_INFO
		case models.Pcf_PolAuth_RequiredAccessInfo_UE_TIME_ZONE:
			data = models.Pcf_SMPolCtrl_RequestedRuleDataType_MS_TIME_ZONE
		default:
			continue
		}
		if !slices.Contains(reqData, data) {
			reqData = append(reqData, data)
		}
	}
	return reqData
}

// validateAniSubscription checks an ANI_REPORT subscription before any policy state is changed:
// "reqAnis" shall be present when ANI_REPORT is subscribed (TS 29.514 EventsSubscReqData).
// Without NetLoc negotiated the event is ignored like any unsupported event, so nothing is checked.
func validateAniSubscription(events []models.Pcf_PolAuth_AfEventSubscription,
	reqAnis []models.Pcf_PolAuth_RequiredAccessInfo, negotiatedSuppFeat string,
) *models.ProblemDetails {
	if !hasAniReportEvent(events) || !util.CheckSuppFeat(negotiatedSuppFeat, netLocFeature) {
		return nil
	}
	if len(aniReqData(reqAnis)) == 0 {
		problemDetail := util.GetProblemDetail("reqAnis shall be present when ANI_REPORT is subscribed",
			util.ERROR_REQUEST_PARAMETERS)
		return &problemDetail
	}
	return nil
}

// handleAniSubscription processes the ANI_REPORT entry of eventSubs, if any:
//   - NetLoc not negotiated with the NF service consumer: the event is not supported and is dropped.
//   - SMF does not support NetLoc: the event is dropped and true is returned; the caller shall
//     answer with "noNetLocSupp" set to ANR_NOT_SUPPORTED (see addAniNotSupported).
//   - Otherwise the PCF immediately asks the SMF to report the information (TS 29.512 clause 4.2.6.5.4),
//     which is notified to the NF service consumer once received (TS 29.514 clause 4.2.5.11).
func handleAniSubscription(eventSubs map[models.Pcf_PolAuth_AfEvent]models.Pcf_PolAuth_AfNotifMethod,
	negotiatedSuppFeat string, smPolicy *pcf_context.UeSmPolicyData,
	reqAnis []models.Pcf_PolAuth_RequiredAccessInfo, relatedPccRuleIds map[string]string, updateSMpolicy *bool,
) (aniNotSupported bool) {
	if _, exist := eventSubs[models.Pcf_PolAuth_AfEvent_ANI_REPORT]; !exist {
		return false
	}
	if !util.CheckSuppFeat(negotiatedSuppFeat, netLocFeature) {
		logger.PolicyAuthLog.Warn("AF Event ANI_REPORT is not supported: NetLoc feature not negotiated")
		delete(eventSubs, models.Pcf_PolAuth_AfEvent_ANI_REPORT)
		return false
	}
	if !util.CheckSuppFeat(smPolicy.PolicyDecision.SuppFeat, netLocFeature) {
		logger.PolicyAuthLog.Info("Access network information report not supported by the SMF")
		// One-time event answered in the response: nothing left to report later.
		delete(eventSubs, models.Pcf_PolAuth_AfEvent_ANI_REPORT)
		return true
	}
	refPccRuleIds := make([]string, 0, len(relatedPccRuleIds))
	for _, pccRuleID := range relatedPccRuleIds {
		refPccRuleIds = append(refPccRuleIds, pccRuleID)
	}
	slices.Sort(refPccRuleIds)
	smPolicy.AddAccessNetworkInfoRequest(aniReqData(reqAnis), refPccRuleIds)
	*updateSMpolicy = true
	return false
}

// addAniNotSupported adds to the EventsNotification of a response that the access network
// information can't be reported because the SMF does not support NetLoc.
func addAniNotSupported(evsNotif *models.Pcf_PolAuth_EventsNotification) {
	evsNotif.EvNotifs = append(evsNotif.EvNotifs, models.Pcf_PolAuth_AfEventNotification{
		Event: models.Pcf_PolAuth_AfEvent_ANI_REPORT,
	})
	evsNotif.NoNetLocSupp = models.Pcf_SMPolCtrl_NetLocAccessSupport_ANR_NOT_SUPPORTED
}

// fillAccessNetworkInfo copies into the notification of one AF session the access network
// information it required (TS 29.514 clause 4.2.5.11). When the user location was required but
// is not available, the serving PLMN is provided instead.
func fillAccessNetworkInfo(sessionNotif *models.Pcf_PolAuth_EventsNotification,
	reported models.Pcf_PolAuth_EventsNotification, reqAnis []models.Pcf_PolAuth_RequiredAccessInfo,
) {
	wantLoc := len(reqAnis) == 0 || slices.Contains(reqAnis, models.Pcf_PolAuth_RequiredAccessInfo_USER_LOCATION)
	wantTz := len(reqAnis) == 0 || slices.Contains(reqAnis, models.Pcf_PolAuth_RequiredAccessInfo_UE_TIME_ZONE)
	if wantLoc {
		if reported.UeLoc != nil {
			sessionNotif.UeLoc = reported.UeLoc
			sessionNotif.UeLocTime = reported.UeLocTime
		} else if reported.PlmnId != nil {
			sessionNotif.PlmnId = reported.PlmnId
		}
	}
	if wantTz {
		sessionNotif.UeTimeZone = reported.UeTimeZone
	}
}

// negotiatedSuppFeat returns the features negotiated with the NF service consumer of an AF session.
func negotiatedSuppFeat(appSessCtx *models.Pcf_PolAuth_AppSessionContext) string {
	if appSessCtx == nil || appSessCtx.AscRespData == nil {
		return ""
	}
	return appSessCtx.AscRespData.SuppFeat
}

func appSessionReqAnis(appSession *pcf_context.AppSessionData) []models.Pcf_PolAuth_RequiredAccessInfo {
	if appSession.AppSessionContext == nil || appSession.AppSessionContext.AscReqData == nil ||
		appSession.AppSessionContext.AscReqData.EvSubsc == nil {
		return nil
	}
	return appSession.AppSessionContext.AscReqData.EvSubsc.ReqAnis
}
