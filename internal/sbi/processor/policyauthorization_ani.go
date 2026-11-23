package processor

import (
	"path"
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
	smPolicy.AddAccessNetworkInfoRequest(aniReqData(reqAnis), sortedPccRuleIds(relatedPccRuleIds))
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

func requiresAccessInfo(reqAnis []models.Pcf_PolAuth_RequiredAccessInfo) (loc, tz bool) {
	loc = len(reqAnis) == 0 || slices.Contains(reqAnis, models.Pcf_PolAuth_RequiredAccessInfo_USER_LOCATION)
	tz = len(reqAnis) == 0 || slices.Contains(reqAnis, models.Pcf_PolAuth_RequiredAccessInfo_UE_TIME_ZONE)
	return loc, tz
}

// fillAccessNetworkInfo copies into the notification of one AF session the access network
// information it required (TS 29.514 clause 4.2.5.11). When the user location was required but
// is not available, the serving PLMN is provided instead. The reason the access network does not
// support the report, if any, is provided too (TS 29.514 clause 4.2.4.6).
func fillAccessNetworkInfo(sessionNotif *models.Pcf_PolAuth_EventsNotification,
	reported models.Pcf_PolAuth_EventsNotification, reqAnis []models.Pcf_PolAuth_RequiredAccessInfo,
) {
	wantLoc, wantTz := requiresAccessInfo(reqAnis)
	if wantLoc {
		if reported.UeLoc != nil {
			sessionNotif.UeLoc = ueLocForAf(reported.UeLoc)
			sessionNotif.UeLocTime = reported.UeLocTime
		} else if reported.PlmnId != nil {
			sessionNotif.PlmnId = reported.PlmnId
		}
	}
	if wantTz {
		sessionNotif.UeTimeZone = reported.UeTimeZone
	}
	sessionNotif.NoNetLocSupp = reported.NoNetLocSupp
}

// ueLocForAf returns the user location to report to the AF: the "n3gppTai" and "n3IwfId" attributes
// within "n3gaLocation" shall not be supplied (TS 29.514 clause 5.6.2.9, EventsNotification).
// The location reported by the SMF is not modified.
func ueLocForAf(ueLoc *models.UserLocation) *models.UserLocation {
	if ueLoc == nil || ueLoc.N3gaLocation == nil ||
		(ueLoc.N3gaLocation.N3gppTai == nil && ueLoc.N3gaLocation.N3IwfId == "") {
		return ueLoc
	}
	afLoc := *ueLoc
	n3gaLoc := *ueLoc.N3gaLocation
	n3gaLoc.N3gppTai = nil
	n3gaLoc.N3IwfId = ""
	afLoc.N3gaLocation = &n3gaLoc
	return &afLoc
}

// aniReportComplete tells whether a report of access network information carries what an AF session
// requires: the user location (or the serving PLMN when it is not available) and the UE time zone, or
// the reason the access network does not support the report.
func aniReportComplete(reported models.Pcf_PolAuth_EventsNotification,
	reqAnis []models.Pcf_PolAuth_RequiredAccessInfo,
) bool {
	if reported.NoNetLocSupp != "" {
		return true
	}
	wantLoc, wantTz := requiresAccessInfo(reqAnis)
	if wantLoc && reported.UeLoc == nil && reported.PlmnId == nil {
		return false
	}
	return !wantTz || reported.UeTimeZone != ""
}

// refreshAccessNetworkInfoRequest updates the request of access network information to the SMF after a
// report: it keeps requesting what the AF sessions still waiting for a report require, and withdraws the
// request and the AN_INFO policy control request trigger once none waits (TS 29.512 clause 4.2.6.5.4).
// It returns true if an AF session still waits.
func (p *Processor) refreshAccessNetworkInfoRequest(smPolicy *pcf_context.UeSmPolicyData) (waiting bool) {
	smPolicy.RemoveAccessNetworkInfoRequest()
	for appSessionID := range smPolicy.AppSessions {
		val, exist := p.Context().AppSessionPool.Load(appSessionID)
		if !exist {
			continue
		}
		appSession := val.(*pcf_context.AppSessionData)
		if _, found := appSession.Events[models.Pcf_PolAuth_AfEvent_ANI_REPORT]; found {
			smPolicy.AddAccessNetworkInfoRequest(aniReqData(appSessionReqAnis(appSession)),
				sortedPccRuleIds(appSession.RelatedPccRuleIds))
			waiting = true
		}
	}
	smPolicy.ArrangeExistEventSubscription()
	return waiting
}

// accessNetworkInfoFromUeCampingRep returns the access network information the SMF provides in its
// answer to an SM policy update notification (UeCampingRep, TS 29.512 clause 4.2.3.10), if any: the
// information itself, or the reason the access network does not support its report.
func accessNetworkInfoFromUeCampingRep(rep *models.CreateSMPolicySmPolicyUpdateNotificationResponse200,
) (report models.Pcf_PolAuth_EventsNotification, ok bool) {
	if rep == nil || (rep.NetLocAccSupp == "" && rep.UserLocationInfo == nil && rep.UeTimeZone == "" &&
		rep.ServingNetwork == nil) {
		return report, false
	}
	report = models.Pcf_PolAuth_EventsNotification{
		EvNotifs:     []models.Pcf_PolAuth_AfEventNotification{{Event: models.Pcf_PolAuth_AfEvent_ANI_REPORT}},
		UeLoc:        rep.UserLocationInfo,
		UeTimeZone:   rep.UeTimeZone,
		NoNetLocSupp: rep.NetLocAccSupp,
	}
	if rep.UserLocationInfo == nil {
		report.PlmnId = rep.ServingNetwork
	}
	return report, true
}

// handleNotificationAccessNetworkInfo reports the access network information the SMF provides in its
// answer to an SM policy update notification to the AF sessions waiting for it, and asks the SMF again
// for the information AF sessions still wait for.
func (p *Processor) handleNotificationAccessNetworkInfo(notification *models.Pcf_SMPolCtrl_SmPolicyNotification,
	rep *models.CreateSMPolicySmPolicyUpdateNotificationResponse200, uri string,
) {
	report, ok := accessNetworkInfoFromUeCampingRep(rep)
	if !ok {
		return
	}
	smPolicyID := path.Base(notification.ResourceUri)
	ue := p.Context().PCFUeFindByPolicyId(smPolicyID)
	if ue == nil || ue.SmPolicyData[smPolicyID] == nil {
		logger.SmPolicyLog.Warnf("Access network information for unknown SM Policy[%s]", smPolicyID)
		return
	}
	smPolicy := ue.SmPolicyData[smPolicyID]
	p.sendSmPolicyRelatedAppSessionNotification(smPolicy, report, nil, nil, nil)
	if p.refreshAccessNetworkInfoRequest(smPolicy) {
		p.SendSMPolicyUpdateNotification(uri, &models.Pcf_SMPolCtrl_SmPolicyNotification{
			ResourceUri:      notification.ResourceUri,
			SmPolicyDecision: smPolicy.PolicyDecision,
		})
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

func sortedPccRuleIds(relatedPccRuleIds map[string]string) []string {
	pccRuleIds := make([]string, 0, len(relatedPccRuleIds))
	for _, pccRuleID := range relatedPccRuleIds {
		pccRuleIds = append(pccRuleIds, pccRuleID)
	}
	slices.Sort(pccRuleIds)
	return pccRuleIds
}
