package producer

import (
	"context"
	"fmt"
	"free5gc/lib/http_wrapper"
	"free5gc/lib/openapi"
	"free5gc/lib/openapi/models"
	pcf_context "free5gc/src/pcf/context"
	"free5gc/src/pcf/logger"
	"free5gc/src/pcf/util"
	"net/http"
	"strings"
	"time"

	"github.com/cydev/zero"
)

func transferMediaComponentRmToMediaComponent(medCompRm *models.MediaComponentRm) *models.MediaComponent {
	spVal := models.SpatialValidity{
		PresenceInfoList: medCompRm.AfRoutReq.SpVal.PresenceInfoList,
	}
	afRoutReq := models.AfRoutingRequirement{
		AppReloc:     medCompRm.AfRoutReq.AppReloc,
		RouteToLocs:  medCompRm.AfRoutReq.RouteToLocs,
		SpVal:        &spVal,
		TempVals:     medCompRm.AfRoutReq.TempVals,
		UpPathChgSub: medCompRm.AfRoutReq.UpPathChgSub,
	}
	medSubComps := make(map[string]models.MediaSubComponent)
	for id, medSubCompRm := range medCompRm.MedSubComps {
		medSubComps[id] = models.MediaSubComponent(medSubCompRm)
	}
	medComp := models.MediaComponent{
		AfAppId:     medCompRm.AfAppId,
		AfRoutReq:   &afRoutReq,
		ContVer:     medCompRm.ContVer,
		Codecs:      medCompRm.Codecs,
		FStatus:     medCompRm.FStatus,
		MarBwDl:     medCompRm.MarBwDl,
		MarBwUl:     medCompRm.MarBwUl,
		MedCompN:    medCompRm.MedCompN,
		MedSubComps: medSubComps,
		MedType:     medCompRm.MedType,
		MirBwDl:     medCompRm.MirBwDl,
		MirBwUl:     medCompRm.MirBwUl,
		ResPrio:     medCompRm.ResPrio,
	}
	return &medComp
}

// Handle Create/ Modify  Media SubComponent
func handleMediaSubComponent(smPolicy *pcf_context.UeSmPolicyData, medComp *models.MediaComponent,
	medSubComp *models.MediaSubComponent, var5qi int32) (*models.PccRule, *models.ProblemDetails) {
	var flowInfos []models.FlowInformation
	if tempFlowInfos, err := getFlowInfos(medSubComp); err != nil {
		problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
		return nil, &problemDetail
	} else {
		flowInfos = tempFlowInfos
	}
	pccRule := util.GetPccRuleByFlowInfos(smPolicy.PolicyDecision.PccRules, flowInfos)
	if pccRule == nil {
		maxPrecedence := getMaxPrecedence(smPolicy.PolicyDecision.PccRules)
		pccRule = util.CreatePccRule(smPolicy.PccRuleIdGenarator, maxPrecedence+1, nil, "", false)
		// Set QoS Data
		// TODO: use real arp
		qosData := util.CreateQosData(smPolicy.PccRuleIdGenarator, var5qi, 8)
		if var5qi <= 4 {
			// update Qos Data accroding to request BitRate
			var ul, dl bool

			qosData, ul, dl = updateQos_subComp(qosData, medComp, medSubComp)
			if problemDetails := modifyRemainBitRate(smPolicy, &qosData, ul, dl); problemDetails != nil {
				return nil, problemDetails
			}
		}
		// Set PackfiltId
		for i := range flowInfos {
			flowInfos[i].PackFiltId = util.GetPackFiltId(smPolicy.PackFiltIdGenarator)
			smPolicy.PackFiltMapToPccRuleId[flowInfos[i].PackFiltId] = pccRule.PccRuleId
			smPolicy.PackFiltIdGenarator++
		}
		// Set flowsInfo in Pcc Rule
		pccRule.FlowInfos = flowInfos
		// Set Traffic Control Data
		tcData := util.CreateTcData(smPolicy.PccRuleIdGenarator, medSubComp.FStatus)
		util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, &tcData, &qosData, nil, nil)
		smPolicy.PccRuleIdGenarator++
	} else {
		// update qos
		var qosData models.QosData
		for _, qosId := range pccRule.RefQosData {
			qosData = smPolicy.PolicyDecision.QosDecs[qosId]
			if qosData.Var5qi == var5qi && qosData.Var5qi <= 4 {
				var ul, dl bool
				qosData, ul, dl = updateQos_subComp(smPolicy.PolicyDecision.QosDecs[qosId], medComp, medSubComp)
				if problemDetails := modifyRemainBitRate(smPolicy, &qosData, ul, dl); problemDetails != nil {
					logger.PolicyAuthorizationlog.Errorf(problemDetails.Detail)
					return nil, problemDetails
				}
				smPolicy.PolicyDecision.QosDecs[qosData.QosId] = qosData
			}
		}
	}
	smPolicy.PolicyDecision.PccRules[pccRule.PccRuleId] = *pccRule
	return pccRule, nil
}

// Initial provisioning of service information (DONE)
// Gate control (DONE)
// Initial provisioning of sponsored connectivity information (DONE)
// Subscriptions to Service Data Flow QoS notification control (DONE)
// Subscription to Service Data Flow Deactivation (DONE)
// Initial provisioning of traffic routing information (DONE)
// Subscription to resources allocation outcome (DONE)
// Invocation of Multimedia Priority Services (TODO)
// Support of content versioning (TODO)
// HandlePostAppSessions - Creates a new Individual Application Session Context resource
func HandlePostAppSessionsContext(request *http_wrapper.Request) *http_wrapper.Response {
	logger.PolicyAuthorizationlog.Traceln("Handle Create AppSessions")

	appSessionContext := request.Body.(models.AppSessionContext)
	// ascReqData := AppSessionContext.AscReqData

	response, locationHeader, problemDetails := PostAppSessionsContextProcedure(appSessionContext)

	if response != nil {
		headers := http.Header{
			"Location": {locationHeader},
		}
		return http_wrapper.NewResponse(http.StatusCreated, headers, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
}

func PostAppSessionsContextProcedure(appSessionContext models.AppSessionContext) (*models.AppSessionContext,
	string, *models.ProblemDetails) {
	ascReqData := appSessionContext.AscReqData
	pcfSelf := pcf_context.PCF_Self()
	// Initial BDT policy indication(the only one which is not related to session)
	if ascReqData.BdtRefId != "" {
		if err := handleBackgroundDataTransferPolicyIndication(pcfSelf, &appSessionContext); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.ERROR_REQUEST_PARAMETERS)
			return nil, "", &problemDetail
		}
		appSessionId := fmt.Sprintf("BdtRefId-%s", ascReqData.BdtRefId)
		data := pcf_context.AppSessionData{
			AppSessionId:      appSessionId,
			AppSessionContext: &appSessionContext,
		}
		pcfSelf.AppSessionPool.Store(appSessionId, &data)
		locationHeader := util.GetResourceUri(models.ServiceName_NPCF_POLICYAUTHORIZATION, appSessionId)
		logger.PolicyAuthorizationlog.Tracef("App Session Id[%s] Create", appSessionId)
		return &appSessionContext, locationHeader, nil
	}
	if ascReqData.UeIpv4 == "" && ascReqData.UeIpv6 == "" && ascReqData.UeMac == "" {
		problemDetail := util.GetProblemDetail("Ue UeIpv4 and UeIpv6 and UeMac are all empty", util.ERROR_REQUEST_PARAMETERS)
		return nil, "", &problemDetail
	}
	if ascReqData.AfRoutReq != nil && ascReqData.Dnn == "" {
		problemDetail := util.GetProblemDetail("DNN shall be present", util.ERROR_REQUEST_PARAMETERS)
		return nil, "", &problemDetail
	}
	var smPolicy *pcf_context.UeSmPolicyData
	if tempSmPolicy, err := pcfSelf.SessionBinding(ascReqData); err != nil {
		problemDetail := util.GetProblemDetail(fmt.Sprintf("Session Binding failed[%s]",
			err.Error()), util.PDU_SESSION_NOT_AVAILABLE)
		return nil, "", &problemDetail
	} else {
		smPolicy = tempSmPolicy
	}
	logger.PolicyAuthorizationlog.Infof("Session Binding Success - UeIpv4[%s], UeIpv6[%s], UeMac[%s]",
		ascReqData.UeIpv4, ascReqData.UeIpv6, ascReqData.UeMac)
	ue := smPolicy.PcfUe
	updateSMpolicy := false

	var requestSuppFeat openapi.SupportedFeature
	if tempRequestSuppFeat, err := openapi.NewSupportedFeature(ascReqData.SuppFeat); err != nil {
		logger.PolicyAuthorizationlog.Errorf(err.Error())
	} else {
		requestSuppFeat = tempRequestSuppFeat
	}

	nSuppFeat := pcfSelf.PcfSuppFeats[models.ServiceName_NPCF_POLICYAUTHORIZATION].NegotiateWith(requestSuppFeat).String()
	// InfluenceOnTrafficRouting = 1 in 29514 &  Traffic Steering Control support = 1 in 29512
	traffRoutSupp := util.CheckSuppFeat(nSuppFeat, 1) && util.CheckSuppFeat(smPolicy.PolicyDecision.SuppFeat, 1)
	relatedPccRuleIds := make(map[string]string)

	if ascReqData.MedComponents != nil {
		// Handle Pcc rules
		maxPrecedence := getMaxPrecedence(smPolicy.PolicyDecision.PccRules)
		for _, medComp := range ascReqData.MedComponents {
			var pccRule *models.PccRule
			var appId string
			var routeReq *models.AfRoutingRequirement
			// TODO: use specific algorithm instead of default, details in subsclause 7.3.3 of TS 29513
			var var5qi int32 = 9
			if medComp.MedType != "" {
				var5qi = util.MediaTypeTo5qiMap[medComp.MedType]
			}

			if medComp.MedSubComps != nil {
				for _, medSubComp := range medComp.MedSubComps {
					if tempPccRule, problemDetail := handleMediaSubComponent(smPolicy,
						&medComp, &medSubComp, var5qi); problemDetail != nil {
						return nil, "", problemDetail
					} else {
						pccRule = tempPccRule
					}
					key := fmt.Sprintf("%d-%d", medComp.MedCompN, medSubComp.FNum)
					relatedPccRuleIds[key] = pccRule.PccRuleId
					updateSMpolicy = true
				}
				continue
			} else if medComp.AfAppId != "" {
				// if medComp.AfAppId has value -> find pccRule by ascReqData.AfAppId, otherwise create a new pcc rule
				appId = medComp.AfAppId
				routeReq = medComp.AfRoutReq
			} else if ascReqData.AfAppId != "" {
				appId = ascReqData.AfAppId
				routeReq = ascReqData.AfRoutReq
			} else {
				problemDetail := util.GetProblemDetail("Media Component needs flows of subComp or afAppId",
					util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				return nil, "", &problemDetail
			}

			pccRule = util.GetPccRuleByAfAppId(smPolicy.PolicyDecision.PccRules, appId)
			if pccRule == nil { // create new pcc rule
				pccRule = util.CreatePccRule(smPolicy.PccRuleIdGenarator, maxPrecedence+1, nil, appId, false)
				// Set QoS Data
				// TODO: use real arp
				qosData := util.CreateQosData(smPolicy.PccRuleIdGenarator, var5qi, 8)
				if var5qi <= 4 {
					// update Qos Data accroding to request BitRate
					var ul, dl bool
					qosData, ul, dl = updateQos_Comp(qosData, &medComp)
					if problemDetails := modifyRemainBitRate(smPolicy, &qosData, ul, dl); problemDetails != nil {
						return nil, "", problemDetails
					}
				}
				util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, nil, &qosData, nil, nil)
				smPolicy.PccRuleIdGenarator++
				maxPrecedence++
			} else {
				// update qos
				var qosData models.QosData
				for _, qosId := range pccRule.RefQosData {
					qosData = smPolicy.PolicyDecision.QosDecs[qosId]
					if qosData.Var5qi == var5qi && qosData.Var5qi <= 4 {
						var ul, dl bool
						qosData, ul, dl = updateQos_Comp(smPolicy.PolicyDecision.QosDecs[qosId], &medComp)
						if problemDetails := modifyRemainBitRate(smPolicy, &qosData, ul, dl); problemDetails != nil {
							return nil, "", problemDetails
						}
						smPolicy.PolicyDecision.QosDecs[qosData.QosId] = qosData
					}
				}
			}
			// Initial provisioning of traffic routing information
			if traffRoutSupp {
				pccRule = provisioningOfTrafficRoutingInfo(smPolicy, appId, routeReq, medComp.FStatus)
			}
			key := fmt.Sprintf("%d", medComp.MedCompN)
			relatedPccRuleIds[key] = pccRule.PccRuleId
			updateSMpolicy = true
		}
	} else if ascReqData.AfAppId != "" {
		// Initial provisioning of traffic routing information
		if ascReqData.AfRoutReq != nil && traffRoutSupp {
			logger.PolicyAuthorizationlog.Infof("AF influence on Traffic Routing - AppId[%s]", ascReqData.AfAppId)
			pccRule := provisioningOfTrafficRoutingInfo(smPolicy, ascReqData.AfAppId, ascReqData.AfRoutReq, "")
			key := fmt.Sprintf("appId-%s", ascReqData.AfAppId)
			relatedPccRuleIds[key] = pccRule.PccRuleId
			updateSMpolicy = true
		} else {
			problemDetail := util.GetProblemDetail("Traffic routing not supported", util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			return nil, "", &problemDetail
		}
	} else {
		problemDetail := util.GetProblemDetail("AF Request need AfAppId or Media Component to match Service Data Flow",
			util.ERROR_REQUEST_PARAMETERS)
		return nil, "", &problemDetail
	}

	// Event Subscription
	eventSubs := make(map[models.AfEvent]models.AfNotifMethod)
	if ascReqData.EvSubsc != nil {
		for _, subs := range ascReqData.EvSubsc.Events {
			if subs.NotifMethod == "" {
				// default value "EVENT_DETECTION"
				subs.NotifMethod = models.AfNotifMethod_EVENT_DETECTION
			}
			eventSubs[subs.Event] = subs.NotifMethod
			var trig models.PolicyControlRequestTrigger
			switch subs.Event {
			case models.AfEvent_ACCESS_TYPE_CHANGE:
				trig = models.PolicyControlRequestTrigger_AC_TY_CH
			// case models.AfEvent_FAILED_RESOURCES_ALLOCATION:
			// 	// Subscription to Service Data Flow Deactivation
			// 	trig = models.PolicyControlRequestTrigger_RES_RELEASE
			case models.AfEvent_PLMN_CHG:
				trig = models.PolicyControlRequestTrigger_PLMN_CH
			case models.AfEvent_QOS_NOTIF:
				// Subscriptions to Service Data Flow QoS notification control
				for _, pccRuleId := range relatedPccRuleIds {
					pccRule := smPolicy.PolicyDecision.PccRules[pccRuleId]
					for _, qosId := range pccRule.RefQosData {
						qosData := smPolicy.PolicyDecision.QosDecs[qosId]
						qosData.Qnc = true
						smPolicy.PolicyDecision.QosDecs[qosId] = qosData
					}
				}
				trig = models.PolicyControlRequestTrigger_QOS_NOTIF
			case models.AfEvent_SUCCESSFUL_RESOURCES_ALLOCATION:
				// Subscription to resources allocation outcome
				trig = models.PolicyControlRequestTrigger_SUCC_RES_ALLO
			case models.AfEvent_USAGE_REPORT:
				trig = models.PolicyControlRequestTrigger_US_RE
			default:
				logger.PolicyAuthorizationlog.Warn("AF Event is unknown")
				continue
			}
			if !util.CheckPolicyControlReqTrig(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig) {
				smPolicy.PolicyDecision.PolicyCtrlReqTriggers = append(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig)
				updateSMpolicy = true
			}

		}
	}

	// Initial provisioning of sponsored connectivity information
	if ascReqData.AspId != "" && ascReqData.SponId != "" {
		// SponsoredConnectivity = 2 in 29514 &  SponsoredConnectivity support = 12 in 29512
		supp := util.CheckSuppFeat(nSuppFeat, 2) && util.CheckSuppFeat(smPolicy.PolicyDecision.SuppFeat, 12)
		if !supp {
			problemDetail := util.GetProblemDetail("Sponsored Connectivity not supported", util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			return nil, "", &problemDetail
		}
		umId := util.GetUmId(ascReqData.AspId, ascReqData.SponId)
		var umData *models.UsageMonitoringData
		if tempUmData, err := extractUmData(umId, eventSubs, ascReqData.EvSubsc.UsgThres); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			return nil, "", &problemDetail
		} else {
			umData = tempUmData
		}
		if err := handleSponsoredConnectivityInformation(smPolicy, relatedPccRuleIds, ascReqData.AspId,
			ascReqData.SponId, ascReqData.SponStatus, umData, &updateSMpolicy); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			return nil, "", &problemDetail
		}
	}

	// Allocate App Session Id
	appSessionId := ue.AllocUeAppSessionId(pcfSelf)
	appSessionContext.AscRespData = &models.AppSessionContextRespData{
		SuppFeat: nSuppFeat,
	}
	// Associate App Session to SMPolicy
	smPolicy.AppSessions[appSessionId] = true
	data := pcf_context.AppSessionData{
		AppSessionId:      appSessionId,
		AppSessionContext: &appSessionContext,
		SmPolicyData:      smPolicy,
	}
	if len(relatedPccRuleIds) > 0 {
		data.RelatedPccRuleIds = relatedPccRuleIds
		data.PccRuleIdMapToCompId = reverseStringMap(relatedPccRuleIds)
	}
	appSessionContext.EvsNotif = &models.EventsNotification{}
	// Set Event Subsciption related Data
	if len(eventSubs) > 0 {
		data.Events = eventSubs
		data.EventUri = ascReqData.EvSubsc.NotifUri
		if _, exist := eventSubs[models.AfEvent_PLMN_CHG]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_PLMN_CHG,
			}
			appSessionContext.EvsNotif.EvNotifs = append(appSessionContext.EvsNotif.EvNotifs, afNotif)
			plmnId := smPolicy.PolicyContext.ServingNetwork
			if plmnId != nil {
				appSessionContext.EvsNotif.PlmnId = &models.PlmnId{
					Mcc: plmnId.Mcc,
					Mnc: plmnId.Mnc,
				}
			}
		}
		if _, exist := eventSubs[models.AfEvent_ACCESS_TYPE_CHANGE]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_ACCESS_TYPE_CHANGE,
			}
			appSessionContext.EvsNotif.EvNotifs = append(appSessionContext.EvsNotif.EvNotifs, afNotif)
			appSessionContext.EvsNotif.AccessType = smPolicy.PolicyContext.AccessType
			appSessionContext.EvsNotif.RatType = smPolicy.PolicyContext.RatType
		}
	}
	if appSessionContext.EvsNotif.EvNotifs == nil {
		appSessionContext.EvsNotif = nil
	}
	pcfSelf.AppSessionPool.Store(appSessionId, &data)
	locationHeader := util.GetResourceUri(models.ServiceName_NPCF_POLICYAUTHORIZATION, appSessionId)
	logger.PolicyAuthorizationlog.Tracef("App Session Id[%s] Create", appSessionId)
	// Send Notification to SMF
	if updateSMpolicy {
		smPolicyId := fmt.Sprintf("%s-%d", ue.Supi, smPolicy.PolicyContext.PduSessionId)
		notification := models.SmPolicyNotification{
			ResourceUri:      util.GetResourceUri(models.ServiceName_NPCF_SMPOLICYCONTROL, smPolicyId),
			SmPolicyDecision: smPolicy.PolicyDecision,
		}
		SendSMPolicyUpdateNotification(ue, smPolicyId, notification)
	}
	return &appSessionContext, locationHeader, nil
}

// HandleDeleteAppSession - Deletes an existing Individual Application Session Context
func HandleDeleteAppSessionContext(request *http_wrapper.Request) *http_wrapper.Response {
	eventsSubscReqData := request.Body.(*models.EventsSubscReqData)
	appSessionId := request.Params["appSessionId"]
	logger.PolicyAuthorizationlog.Tracef("Handle Del AppSessions, AppSessionId[%s]", appSessionId)

	problemDetails := DeleteAppSessionContextProcedure(appSessionId, eventsSubscReqData)
	if problemDetails == nil {
		return http_wrapper.NewResponse(http.StatusNoContent, nil, nil)
	} else {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
}

func DeleteAppSessionContextProcedure(appSessionId string,
	eventsSubscReqData *models.EventsSubscReqData) *models.ProblemDetails {
	pcfSelf := pcf_context.PCF_Self()
	var appSession *pcf_context.AppSessionData
	if val, ok := pcfSelf.AppSessionPool.Load(appSessionId); ok {
		appSession = val.(*pcf_context.AppSessionData)
	}
	if appSession == nil {
		problemDetail := util.GetProblemDetail("can't find app session", util.APPLICATION_SESSION_CONTEXT_NOT_FOUND)
		return &problemDetail
	}
	if eventsSubscReqData != nil {
		logger.PolicyAuthorizationlog.Warnf("Delete AppSessions does not support with Event Subscription")
	}
	// Remove related pcc rule resourse
	smPolicy := appSession.SmPolicyData
	for _, pccRuleId := range appSession.RelatedPccRuleIds {
		if err := smPolicy.RemovePccRule(pccRuleId); err != nil {
			logger.PolicyAuthorizationlog.Warnf(err.Error())
		}
	}

	delete(smPolicy.AppSessions, appSessionId)

	logger.PolicyAuthorizationlog.Tracef("App Session Id[%s] Del", appSessionId)

	// TODO: AccUsageReport
	// if appSession.AccUsage != nil {

	// 	resp := models.AppSessionContext{
	// 		EvsNotif: &models.EventsNotification{
	// 			UsgRep: appSession.AccUsage,
	// 		},
	// 	}
	// 	message.SendHttpResponseMessage(httpChannel, nil, http.StatusOK, resp)
	// } else {
	// }

	pcfSelf.AppSessionPool.Delete(appSessionId)

	smPolicy.ArrangeExistEventSubscription()

	// Notify SMF About Pcc Rule moval
	smPolicyId := fmt.Sprintf("%s-%d", smPolicy.PcfUe.Supi, smPolicy.PolicyContext.PduSessionId)
	notification := models.SmPolicyNotification{
		ResourceUri:      util.GetResourceUri(models.ServiceName_NPCF_SMPOLICYCONTROL, smPolicyId),
		SmPolicyDecision: smPolicy.PolicyDecision,
	}
	SendSMPolicyUpdateNotification(smPolicy.PcfUe, smPolicyId, notification)
	logger.PolicyAuthorizationlog.Tracef("Send SM Policy[%s] Update Notification", smPolicyId)
	return nil
}

// HandleGetAppSession - Reads an existing Individual Application Session Context
func HandleGetAppSessionContext(request *http_wrapper.Request) *http_wrapper.Response {
	appSessionId := request.Params["appSessionId"]
	logger.PolicyAuthorizationlog.Tracef("Handle Get AppSessions, AppSessionId[%s]", appSessionId)

	problemDetails, response := GetAppSessionContextProcedure(appSessionId)
	if problemDetails == nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
}

func GetAppSessionContextProcedure(appSessionId string) (*models.ProblemDetails, *models.AppSessionContext) {
	pcfSelf := pcf_context.PCF_Self()

	var appSession *pcf_context.AppSessionData
	if val, ok := pcfSelf.AppSessionPool.Load(appSessionId); ok {
		appSession = val.(*pcf_context.AppSessionData)
	}
	if appSession == nil {
		problemDetail := util.GetProblemDetail("can't find app session", util.APPLICATION_SESSION_CONTEXT_NOT_FOUND)
		return &problemDetail, nil
	}
	logger.PolicyAuthorizationlog.Tracef("App Session Id[%s] Get", appSessionId)
	return nil, appSession.AppSessionContext
}

// HandleModAppSession - Modifies an existing Individual Application Session Context
func HandleModAppSessionContext(request *http_wrapper.Request) *http_wrapper.Response {
	appSessionId := request.Params["appSessionId"]
	appSessionContextUpdateData := request.Body.(models.AppSessionContextUpdateData)
	logger.PolicyAuthorizationlog.Tracef("Handle Modify AppSessions, AppSessionId[%s]", appSessionId)

	problemDetails, response := ModAppSessionContextProcedure(appSessionId, appSessionContextUpdateData)
	if problemDetails == nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
}

func ModAppSessionContextProcedure(appSessionId string,
	appSessionContextUpdateData models.AppSessionContextUpdateData) (*models.ProblemDetails, *models.AppSessionContext) {
	pcfSelf := pcf_context.PCF_Self()
	var appSession *pcf_context.AppSessionData
	if val, ok := pcfSelf.AppSessionPool.Load(appSessionId); ok {
		appSession = val.(*pcf_context.AppSessionData)
	}
	if appSession == nil {
		problemDetail := util.GetProblemDetail("can't find app session", util.APPLICATION_SESSION_CONTEXT_NOT_FOUND)
		return &problemDetail, nil
	}
	appContext := appSession.AppSessionContext
	if appSessionContextUpdateData.BdtRefId != "" {
		appContext.AscReqData.BdtRefId = appSessionContextUpdateData.BdtRefId
		if err := handleBackgroundDataTransferPolicyIndication(pcfSelf, appContext); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.ERROR_REQUEST_PARAMETERS)
			return &problemDetail, nil
		}
		logger.PolicyAuthorizationlog.Tracef("App Session Id[%s] Updated", appSessionId)
		return nil, appContext

	}
	smPolicy := appSession.SmPolicyData
	if smPolicy == nil {
		problemDetail := util.GetProblemDetail("Can't find related PDU Session", util.REQUESTED_SERVICE_NOT_AUTHORIZED)
		return &problemDetail, nil
	}
	// InfluenceOnTrafficRouting = 1 in 29514 &  Traffic Steering Control support = 1 in 29512
	traffRoutSupp := util.CheckSuppFeat(appContext.AscRespData.SuppFeat,
		1) && util.CheckSuppFeat(smPolicy.PolicyDecision.SuppFeat, 1)
	relatedPccRuleIds := make(map[string]string)
	// Event Subscription
	eventSubs := make(map[models.AfEvent]models.AfNotifMethod)
	updateSMpolicy := false

	if appSessionContextUpdateData.MedComponents != nil {
		maxPrecedence := getMaxPrecedence(smPolicy.PolicyDecision.PccRules)
		for compN, medCompRm := range appSessionContextUpdateData.MedComponents {
			medComp := transferMediaComponentRmToMediaComponent(&medCompRm)
			removeMediaComp(appSession, compN)
			if zero.IsZero(medComp) {
				// remove MediaComp(media Comp is null)
				continue
			}
			// modify MediaComp(remove and reinstall again)
			var pccRule *models.PccRule
			var appId string
			var routeReq *models.AfRoutingRequirement
			// TODO: use specific algorithm instead of default, details in subsclause 7.3.3 of TS 29513
			var var5qi int32 = 9
			if medComp.MedType != "" {
				var5qi = util.MediaTypeTo5qiMap[medComp.MedType]
			}
			if medComp.MedSubComps != nil {
				for _, medSubComp := range medComp.MedSubComps {
					if tempPccRule, problemDetail := handleMediaSubComponent(smPolicy, medComp,
						&medSubComp, var5qi); problemDetail != nil {
						return problemDetail, nil
					} else {
						pccRule = tempPccRule
					}
					key := fmt.Sprintf("%d-%d", medComp.MedCompN, medSubComp.FNum)
					relatedPccRuleIds[key] = pccRule.PccRuleId
					updateSMpolicy = true
				}
				continue
			} else if medComp.AfAppId != "" {
				// if medComp.AfAppId has value -> find pccRule by reqData.AfAppId, otherwise create a new pcc rule
				appId = medComp.AfAppId
				routeReq = medComp.AfRoutReq
			} else if appSessionContextUpdateData.AfAppId != "" {
				appId = appSessionContextUpdateData.AfAppId
				routeReq = medComp.AfRoutReq
			} else {
				problemDetail := util.GetProblemDetail("Media Component needs flows of subComp or afAppId",
					util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				return &problemDetail, nil
			}

			pccRule = util.GetPccRuleByAfAppId(smPolicy.PolicyDecision.PccRules, appId)
			if pccRule == nil { // create new pcc rule
				pccRule = util.CreatePccRule(smPolicy.PccRuleIdGenarator, maxPrecedence+1, nil, appId, false)
				// Set QoS Data
				// TODO: use real arp
				qosData := util.CreateQosData(smPolicy.PccRuleIdGenarator, var5qi, 8)
				if var5qi <= 4 {
					// update Qos Data accroding to request BitRate
					var ul, dl bool
					qosData, ul, dl = updateQos_Comp(qosData, medComp)
					if problemDetail := modifyRemainBitRate(smPolicy, &qosData, ul, dl); problemDetail != nil {
						return problemDetail, nil
					}
				}
				util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, nil, &qosData, nil, nil)
				smPolicy.PccRuleIdGenarator++
				maxPrecedence++
			} else {
				// update qos
				var qosData models.QosData
				for _, qosId := range pccRule.RefQosData {
					qosData = smPolicy.PolicyDecision.QosDecs[qosId]
					if qosData.Var5qi == var5qi && qosData.Var5qi <= 4 {
						var ul, dl bool
						qosData, ul, dl = updateQos_Comp(smPolicy.PolicyDecision.QosDecs[qosId], medComp)
						if problemDetail := modifyRemainBitRate(smPolicy, &qosData, ul, dl); problemDetail != nil {
							return problemDetail, nil
						}
						smPolicy.PolicyDecision.QosDecs[qosData.QosId] = qosData
					}
				}
			}
			key := fmt.Sprintf("%d", medComp.MedCompN)
			relatedPccRuleIds[key] = pccRule.PccRuleId
			// Modify provisioning of traffic routing information
			if traffRoutSupp {
				pccRule = provisioningOfTrafficRoutingInfo(smPolicy, appId, routeReq, medComp.FStatus)
				_ = pccRule // pccRule unused
			}
			updateSMpolicy = true
		}
	}

	// Merge Original PccRuleId and new
	for key, pccRuleId := range appSession.RelatedPccRuleIds {
		relatedPccRuleIds[key] = pccRuleId
	}

	if appSessionContextUpdateData.EvSubsc != nil {
		for _, subs := range appSessionContextUpdateData.EvSubsc.Events {
			if subs.NotifMethod == "" {
				// default value "EVENT_DETECTION"
				subs.NotifMethod = models.AfNotifMethod_EVENT_DETECTION
			}
			eventSubs[subs.Event] = subs.NotifMethod
			var trig models.PolicyControlRequestTrigger
			switch subs.Event {
			case models.AfEvent_ACCESS_TYPE_CHANGE:
				trig = models.PolicyControlRequestTrigger_AC_TY_CH
			// case models.AfEvent_FAILED_RESOURCES_ALLOCATION:
			// 	// Subscription to Service Data Flow Deactivation
			// 	trig = models.PolicyControlRequestTrigger_SUCC_RES_ALLO
			case models.AfEvent_PLMN_CHG:
				trig = models.PolicyControlRequestTrigger_PLMN_CH
			case models.AfEvent_QOS_NOTIF:
				// Subscriptions to Service Data Flow QoS notification control
				for _, pccRuleId := range relatedPccRuleIds {
					pccRule := smPolicy.PolicyDecision.PccRules[pccRuleId]
					for _, qosId := range pccRule.RefQosData {
						qosData := smPolicy.PolicyDecision.QosDecs[qosId]
						qosData.Qnc = true
						smPolicy.PolicyDecision.QosDecs[qosId] = qosData
					}
				}
				trig = models.PolicyControlRequestTrigger_QOS_NOTIF
			case models.AfEvent_SUCCESSFUL_RESOURCES_ALLOCATION:
				// Subscription to resources allocation outcome
				trig = models.PolicyControlRequestTrigger_SUCC_RES_ALLO
			case models.AfEvent_USAGE_REPORT:
				trig = models.PolicyControlRequestTrigger_US_RE
			default:
				logger.PolicyAuthorizationlog.Warn("AF Event is unknown")
				continue
			}
			if !util.CheckPolicyControlReqTrig(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig) {
				smPolicy.PolicyDecision.PolicyCtrlReqTriggers =
					append(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig)
				updateSMpolicy = true
			}
		}
		// update Context
		if appContext.AscReqData.EvSubsc == nil {
			appContext.AscReqData.EvSubsc = new(models.EventsSubscReqData)
		}
		appContext.AscReqData.EvSubsc.Events = appSessionContextUpdateData.EvSubsc.Events
		if appSessionContextUpdateData.EvSubsc.NotifUri != "" {
			appContext.AscReqData.EvSubsc.NotifUri = appSessionContextUpdateData.EvSubsc.NotifUri
			appSession.EventUri = appSessionContextUpdateData.EvSubsc.NotifUri
		}
		if appSessionContextUpdateData.EvSubsc.UsgThres != nil {
			appContext.AscReqData.EvSubsc.UsgThres = threshRmToThresh(appSessionContextUpdateData.EvSubsc.UsgThres)
		}
	} else {
		// remove eventSubs
		appSession.Events = nil
		appSession.EventUri = ""
		appContext.AscReqData.EvSubsc = nil
	}

	// Moification provisioning of sponsored connectivity information
	if appSessionContextUpdateData.AspId != "" && appSessionContextUpdateData.SponId != "" {
		umId := util.GetUmId(appSessionContextUpdateData.AspId, appSessionContextUpdateData.SponId)
		var umData *models.UsageMonitoringData
		if tempUmData, err := extractUmData(umId, eventSubs,
			threshRmToThresh(appSessionContextUpdateData.EvSubsc.UsgThres)); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			return &problemDetail, nil
		} else {
			umData = tempUmData
		}
		if err := handleSponsoredConnectivityInformation(smPolicy, relatedPccRuleIds, appSessionContextUpdateData.AspId,
			appSessionContextUpdateData.SponId, appSessionContextUpdateData.SponStatus, umData, &updateSMpolicy); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			return &problemDetail, nil
		}
	}

	if len(relatedPccRuleIds) > 0 {
		appSession.RelatedPccRuleIds = relatedPccRuleIds
		appSession.PccRuleIdMapToCompId = reverseStringMap(relatedPccRuleIds)

	}
	appContext.EvsNotif = &models.EventsNotification{}
	// Set Event Subsciption related Data
	if len(eventSubs) > 0 {
		appSession.Events = eventSubs
		if _, exist := eventSubs[models.AfEvent_PLMN_CHG]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_PLMN_CHG,
			}
			appContext.EvsNotif.EvNotifs = append(appContext.EvsNotif.EvNotifs, afNotif)
			plmnId := smPolicy.PolicyContext.ServingNetwork
			if plmnId != nil {
				appContext.EvsNotif.PlmnId = &models.PlmnId{
					Mcc: plmnId.Mcc,
					Mnc: plmnId.Mnc,
				}
			}
		}
		if _, exist := eventSubs[models.AfEvent_ACCESS_TYPE_CHANGE]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_ACCESS_TYPE_CHANGE,
			}
			appContext.EvsNotif.EvNotifs = append(appContext.EvsNotif.EvNotifs, afNotif)
			appContext.EvsNotif.AccessType = smPolicy.PolicyContext.AccessType
			appContext.EvsNotif.RatType = smPolicy.PolicyContext.RatType
		}
	}
	if appContext.EvsNotif.EvNotifs == nil {
		appContext.EvsNotif = nil
	}

	// TODO: MPS Sevice
	logger.PolicyAuthorizationlog.Tracef("App Session Id[%s] Updated", appSessionId)

	smPolicy.ArrangeExistEventSubscription()

	// Send Notification to SMF
	if updateSMpolicy {
		smPolicyId := fmt.Sprintf("%s-%d", smPolicy.PcfUe.Supi, smPolicy.PolicyContext.PduSessionId)
		notification := models.SmPolicyNotification{
			ResourceUri:      util.GetResourceUri(models.ServiceName_NPCF_SMPOLICYCONTROL, smPolicyId),
			SmPolicyDecision: smPolicy.PolicyDecision,
		}
		SendSMPolicyUpdateNotification(smPolicy.PcfUe, smPolicyId, notification)
		logger.PolicyAuthorizationlog.Tracef("Send SM Policy[%s] Update Notification", smPolicyId)
	}
	return nil, appContext
}

// HandleDeleteEventsSubsc - deletes the Events Subscription subresource
func HandleDeleteEventsSubscContext(request *http_wrapper.Request) *http_wrapper.Response {
	appSessionId := request.Params["appSessionId"]
	logger.PolicyAuthorizationlog.Tracef("Handle Del AppSessions Events Subsc, AppSessionId[%s]", appSessionId)

	problemDetails := DeleteEventsSubscContextProcedure(appSessionId)
	if problemDetails == nil {
		return http_wrapper.NewResponse(http.StatusNoContent, nil, nil)
	} else {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
}

func DeleteEventsSubscContextProcedure(appSessionId string) *models.ProblemDetails {
	pcfSelf := pcf_context.PCF_Self()
	var appSession *pcf_context.AppSessionData
	if val, ok := pcfSelf.AppSessionPool.Load(appSessionId); ok {
		appSession = val.(*pcf_context.AppSessionData)
	}
	if appSession == nil {
		problemDetail := util.GetProblemDetail("can't find app session", util.APPLICATION_SESSION_CONTEXT_NOT_FOUND)
		return &problemDetail
	}
	appSession.Events = nil
	appSession.EventUri = ""
	appSession.AppSessionContext.EvsNotif = nil
	appSession.AppSessionContext.AscReqData.EvSubsc = nil

	// changed := appSession.SmPolicyData.ArrangeExistEventSubscription()

	logger.PolicyAuthorizationlog.Tracef("App Session Id[%s] Del Events Subsc success", appSessionId)

	smPolicy := appSession.SmPolicyData
	// Send Notification to SMF
	if changed := appSession.SmPolicyData.ArrangeExistEventSubscription(); changed {
		smPolicyId := fmt.Sprintf("%s-%d", smPolicy.PcfUe.Supi, smPolicy.PolicyContext.PduSessionId)
		notification := models.SmPolicyNotification{
			ResourceUri:      util.GetResourceUri(models.ServiceName_NPCF_SMPOLICYCONTROL, smPolicyId),
			SmPolicyDecision: smPolicy.PolicyDecision,
		}
		SendSMPolicyUpdateNotification(smPolicy.PcfUe, smPolicyId, notification)
		logger.PolicyAuthorizationlog.Tracef("Send SM Policy[%s] Update Notification", smPolicyId)
	}
	return nil
}

// HandleUpdateEventsSubsc - creates or modifies an Events Subscription subresource
func HandleUpdateEventsSubscContext(request *http_wrapper.Request) *http_wrapper.Response {
	EventsSubscReqData := request.Body.(models.EventsSubscReqData)
	appSessionId := request.Params["appSessionId"]
	logger.PolicyAuthorizationlog.Tracef("Handle Put AppSessions Events Subsc, AppSessionId[%s]", appSessionId)

	response, locationHeader, status, problemDetails := UpdateEventsSubscContextProcedure(appSessionId, EventsSubscReqData)
	if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else if status == http.StatusCreated {
		headers := http.Header{
			"Location": {locationHeader},
		}
		return http_wrapper.NewResponse(http.StatusCreated, headers, response)
	} else if status == http.StatusOK {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if status == http.StatusNoContent {
		return http_wrapper.NewResponse(http.StatusNoContent, nil, response)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
}

func SendAppSessionEventNotification(appSession *pcf_context.AppSessionData, request models.EventsNotification) {
	logger.PolicyAuthorizationlog.Tracef("Send App Session Event Notification")
	if appSession == nil {
		logger.PolicyAuthorizationlog.Warnln("Send App Session Event Notification Error[appSession is nil]")
		return
	}
	uri := appSession.EventUri
	if uri != "" {
		request.EvSubsUri = fmt.Sprintf("%s/events-subscription",
			util.GetResourceUri(models.ServiceName_NPCF_POLICYAUTHORIZATION, appSession.AppSessionId))
		client := util.GetNpcfPolicyAuthorizationCallbackClient()
		httpResponse, err := client.PolicyAuthorizationEventNotificationApi.PolicyAuthorizationEventNotification(
			context.Background(), uri, request)
		if err != nil {
			if httpResponse != nil {
				logger.PolicyAuthorizationlog.Warnf("Send App Session Event Notification Error[%s]", httpResponse.Status)
			} else {
				logger.PolicyAuthorizationlog.Warnf("Send App Session Event Notification Failed[%s]", err.Error())
			}
			return
		} else if httpResponse == nil {
			logger.PolicyAuthorizationlog.Warnln("Send App Session Event Notification Failed[HTTP Response is nil]")
			return
		}
		if httpResponse.StatusCode != http.StatusOK && httpResponse.StatusCode != http.StatusNoContent {
			logger.PolicyAuthorizationlog.Warnf("Send App Session Event Notification Failed")
		} else {
			logger.PolicyAuthorizationlog.Tracef("Send App Session Event Notification Success")
		}
	}
}

func UpdateEventsSubscContextProcedure(appSessionId string, eventsSubscReqData models.EventsSubscReqData) (
	*models.UpdateEventsSubscResponse, string, int, *models.ProblemDetails) {
	pcfSelf := pcf_context.PCF_Self()

	var appSession *pcf_context.AppSessionData
	if val, ok := pcfSelf.AppSessionPool.Load(appSessionId); ok {
		appSession = val.(*pcf_context.AppSessionData)
	}
	if appSession == nil {
		problemDetail := util.GetProblemDetail("can't find app session", util.APPLICATION_SESSION_CONTEXT_NOT_FOUND)
		return nil, "", int(problemDetail.Status), &problemDetail
	}
	smPolicy := appSession.SmPolicyData
	eventSubs := make(map[models.AfEvent]models.AfNotifMethod)

	updataSmPolicy := false
	created := false
	if appSession.Events == nil {
		created = true
	}

	for _, subs := range eventsSubscReqData.Events {
		if subs.NotifMethod == "" {
			// default value "EVENT_DETECTION"
			subs.NotifMethod = models.AfNotifMethod_EVENT_DETECTION
		}
		eventSubs[subs.Event] = subs.NotifMethod
		var trig models.PolicyControlRequestTrigger
		switch subs.Event {
		case models.AfEvent_ACCESS_TYPE_CHANGE:
			trig = models.PolicyControlRequestTrigger_AC_TY_CH
		// case models.AfEvent_FAILED_RESOURCES_ALLOCATION:
		// 	// Subscription to Service Data Flow Deactivation
		// 	trig = models.PolicyControlRequestTrigger_SUCC_RES_ALLO
		case models.AfEvent_PLMN_CHG:
			trig = models.PolicyControlRequestTrigger_PLMN_CH
		case models.AfEvent_QOS_NOTIF:
			// Subscriptions to Service Data Flow QoS notification control
			for _, pccRuleId := range appSession.RelatedPccRuleIds {
				pccRule := smPolicy.PolicyDecision.PccRules[pccRuleId]
				for _, qosId := range pccRule.RefQosData {
					qosData := smPolicy.PolicyDecision.QosDecs[qosId]
					qosData.Qnc = true
					smPolicy.PolicyDecision.QosDecs[qosId] = qosData
				}
			}
			trig = models.PolicyControlRequestTrigger_QOS_NOTIF
		case models.AfEvent_SUCCESSFUL_RESOURCES_ALLOCATION:
			// Subscription to resources allocation outcome
			trig = models.PolicyControlRequestTrigger_SUCC_RES_ALLO
		case models.AfEvent_USAGE_REPORT:
			trig = models.PolicyControlRequestTrigger_US_RE
		default:
			logger.PolicyAuthorizationlog.Warn("AF Event is unknown")
			continue
		}
		if !util.CheckPolicyControlReqTrig(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig) {
			smPolicy.PolicyDecision.PolicyCtrlReqTriggers =
				append(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig)
			updataSmPolicy = true
		}

	}
	appContext := appSession.AppSessionContext
	// update Context
	if appContext.AscReqData.EvSubsc == nil {
		appContext.AscReqData.EvSubsc = new(models.EventsSubscReqData)
	}
	appContext.AscReqData.EvSubsc.Events = eventsSubscReqData.Events
	appContext.AscReqData.EvSubsc.UsgThres = eventsSubscReqData.UsgThres
	appContext.AscReqData.EvSubsc.NotifUri = eventsSubscReqData.NotifUri
	appContext.EvsNotif = nil
	// update app Session
	appSession.EventUri = eventsSubscReqData.NotifUri
	appSession.Events = eventSubs

	resp := models.UpdateEventsSubscResponse{
		EvSubsc: eventsSubscReqData,
	}
	appContext.EvsNotif = &models.EventsNotification{
		EvSubsUri: eventsSubscReqData.NotifUri,
	}
	// Set Event Subsciption related Data
	if len(eventSubs) > 0 {
		if _, exist := eventSubs[models.AfEvent_PLMN_CHG]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_PLMN_CHG,
			}
			appContext.EvsNotif.EvNotifs = append(appContext.EvsNotif.EvNotifs, afNotif)
			plmnId := smPolicy.PolicyContext.ServingNetwork
			if plmnId != nil {
				appContext.EvsNotif.PlmnId = &models.PlmnId{
					Mcc: plmnId.Mcc,
					Mnc: plmnId.Mnc,
				}
			}
		}
		if _, exist := eventSubs[models.AfEvent_ACCESS_TYPE_CHANGE]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_ACCESS_TYPE_CHANGE,
			}
			appContext.EvsNotif.EvNotifs = append(appContext.EvsNotif.EvNotifs, afNotif)
			appContext.EvsNotif.AccessType = smPolicy.PolicyContext.AccessType
			appContext.EvsNotif.RatType = smPolicy.PolicyContext.RatType
		}
	}
	if appContext.EvsNotif.EvNotifs == nil {
		appContext.EvsNotif = nil
	}

	resp.EvsNotif = appContext.EvsNotif

	changed := appSession.SmPolicyData.ArrangeExistEventSubscription()

	// Send Notification to SMF
	if updataSmPolicy || changed {
		smPolicyId := fmt.Sprintf("%s-%d", smPolicy.PcfUe.Supi, smPolicy.PolicyContext.PduSessionId)
		notification := models.SmPolicyNotification{
			ResourceUri:      util.GetResourceUri(models.ServiceName_NPCF_SMPOLICYCONTROL, smPolicyId),
			SmPolicyDecision: smPolicy.PolicyDecision,
		}
		SendSMPolicyUpdateNotification(smPolicy.PcfUe, smPolicyId, notification)
		logger.PolicyAuthorizationlog.Tracef("Send SM Policy[%s] Update Notification", smPolicyId)
	}
	if created {
		locationHeader := fmt.Sprintf("%s/events-subscription",
			util.GetResourceUri(models.ServiceName_NPCF_POLICYAUTHORIZATION, appSessionId))
		logger.PolicyAuthorizationlog.Tracef("App Session Id[%s] Create Subscription", appSessionId)
		return &resp, locationHeader, http.StatusCreated, nil
	} else if resp.EvsNotif != nil {
		logger.PolicyAuthorizationlog.Tracef("App Session Id[%s] Modify Subscription", appSessionId)
		return &resp, "", http.StatusOK, nil
	} else {
		logger.PolicyAuthorizationlog.Tracef("App Session Id[%s] Modify Subscription", appSessionId)
		return &resp, "", http.StatusNoContent, nil
	}
}

func SendAppSessionTermination(appSession *pcf_context.AppSessionData, request models.TerminationInfo) {
	logger.PolicyAuthorizationlog.Tracef("Send App Session Termination")
	if appSession == nil {
		logger.PolicyAuthorizationlog.Warnln("Send App Session Termination Error[appSession is nil]")
		return
	}
	uri := appSession.AppSessionContext.AscReqData.NotifUri
	if uri != "" {
		request.ResUri = util.GetResourceUri(models.ServiceName_NPCF_POLICYAUTHORIZATION, appSession.AppSessionId)
		client := util.GetNpcfPolicyAuthorizationCallbackClient()
		httpResponse, err := client.PolicyAuthorizationTerminateRequestApi.PolicyAuthorizationTerminateRequest(
			context.Background(), uri, request)
		if err != nil {
			if httpResponse != nil {
				logger.PolicyAuthorizationlog.Warnf("Send App Session Termination Error[%s]", httpResponse.Status)
			} else {
				logger.PolicyAuthorizationlog.Warnf("Send App Session Termination Failed[%s]", err.Error())
			}
			return
		} else if httpResponse == nil {
			logger.PolicyAuthorizationlog.Warnln("Send App Session Termination Failed[HTTP Response is nil]")
			return
		}
		if httpResponse.StatusCode != http.StatusOK && httpResponse.StatusCode != http.StatusNoContent {
			logger.PolicyAuthorizationlog.Warnf("Send App Session Termination Failed")
		} else {
			logger.PolicyAuthorizationlog.Tracef("Send App Session Termination Success")
		}
	}
}

// Handle Create/ Modify  Background Data Transfer Policy Indication
func handleBackgroundDataTransferPolicyIndication(pcfSelf *pcf_context.PCFContext,
	appContext *models.AppSessionContext) (err error) {
	req := appContext.AscReqData

	var requestSuppFeat openapi.SupportedFeature
	if tempRequestSuppFeat, err := openapi.NewSupportedFeature(req.SuppFeat); err != nil {
		logger.PolicyAuthorizationlog.Errorf("Sponsored Connectivity is disabled by AF")
	} else {
		requestSuppFeat = tempRequestSuppFeat
	}
	respData := models.AppSessionContextRespData{
		ServAuthInfo: models.ServAuthInfo_NOT_KNOWN,
		SuppFeat: pcfSelf.PcfSuppFeats[models.ServiceName_NPCF_POLICYAUTHORIZATION].NegotiateWith(
			requestSuppFeat).String(),
	}
	client := util.GetNudrClient(getDefaultUdrUri(pcfSelf))
	bdtData, resp, err1 := client.DefaultApi.PolicyDataBdtDataBdtReferenceIdGet(context.Background(), req.BdtRefId)
	if err1 != nil {
		return fmt.Errorf("UDR Get BdtDate error[%s]", err1.Error())
	} else if resp == nil || resp.StatusCode != http.StatusOK {
		return fmt.Errorf("UDR Get BdtDate error")
	} else {
		startTime, err1 := time.Parse(util.TimeFormat, bdtData.TransPolicy.RecTimeInt.StartTime)
		if err1 != nil {
			return err1
		}
		stopTime, err1 := time.Parse(util.TimeFormat, bdtData.TransPolicy.RecTimeInt.StopTime)
		if err1 != nil {
			return err1
		}
		if startTime.After(time.Now()) {
			respData.ServAuthInfo = models.ServAuthInfo_NOT_YET_OCURRED
		} else if stopTime.Before(time.Now()) {
			respData.ServAuthInfo = models.ServAuthInfo_EXPIRED
		}
	}
	appContext.AscRespData = &respData
	return nil
}

// provisioning of sponsored connectivity information
func handleSponsoredConnectivityInformation(smPolicy *pcf_context.UeSmPolicyData, relatedPccRuleIds map[string]string,
	aspId, sponId string, sponStatus models.SponsoringStatus, umData *models.UsageMonitoringData,
	updateSMpolicy *bool) error {
	if sponStatus == models.SponsoringStatus_DISABLED {
		logger.PolicyAuthorizationlog.Debugf("Sponsored Connectivity is disabled by AF")
		umId := util.GetUmId(aspId, sponId)
		for _, pccRuleId := range relatedPccRuleIds {
			pccRule := smPolicy.PolicyDecision.PccRules[pccRuleId]
			for _, chgId := range pccRule.RefChgData {
				// disables sponsoring a service
				chgData := smPolicy.PolicyDecision.ChgDecs[chgId]
				if chgData.AppSvcProvId == aspId && chgData.SponsorId == sponId {
					chgData.SponsorId = ""
					chgData.AppSvcProvId = ""
					chgData.ReportingLevel = models.ReportingLevel_SER_ID_LEVEL
					smPolicy.PolicyDecision.ChgDecs[chgId] = chgData
					*updateSMpolicy = true
				}
			}
			if pccRule.RefUmData != nil {
				pccRule.RefUmData = nil
				smPolicy.PolicyDecision.PccRules[pccRuleId] = pccRule
			}
			// disable the usage monitoring
			// TODO: As a result, PCF gets the accumulated usage of the sponsored data connectivity
			delete(smPolicy.PolicyDecision.UmDecs, umId)
		}
	} else {

		if umData != nil {
			supp := util.CheckSuppFeat(smPolicy.PolicyDecision.SuppFeat, 5) // UMC support = 5 in 29512
			if !supp {
				err := fmt.Errorf("Usage Monitor Control is not supported in SMF")
				return err
			}
		}
		chgIdUsed := false
		chgId := util.GetChgId(smPolicy.ChargingIdGenarator)
		for _, pccRuleId := range relatedPccRuleIds {
			pccRule := smPolicy.PolicyDecision.PccRules[pccRuleId]
			chgData := models.ChargingData{
				ChgId: chgId,
			}
			if pccRule.RefChgData != nil {
				chgId := pccRule.RefChgData[0]
				chgData = smPolicy.PolicyDecision.ChgDecs[chgId]
			} else {
				chgIdUsed = true
			}
			// TODO: PCF, based on operator policies, shall check whether it is required to
			// validate the sponsored connectivity data.
			// If it is required, it shall perform the authorizations based on sponsored data connectivity profiles.
			// If the authorization fails, the PCF shall send HTTP "403 Forbidden" with the "cause" attribute set to
			// "UNAUTHORIZED_SPONSORED_DATA_CONNECTIVITY"
			pccRule.RefChgData = []string{chgData.ChgId}
			chgData.ReportingLevel = models.ReportingLevel_SPON_CON_LEVEL
			chgData.SponsorId = sponId
			chgData.AppSvcProvId = aspId
			if umData != nil {
				pccRule.RefUmData = []string{umData.UmId}
			}
			util.SetPccRuleRelatedData(smPolicy.PolicyDecision, &pccRule, nil, nil, &chgData, umData)
			*updateSMpolicy = true
		}
		if chgIdUsed {
			smPolicy.ChargingIdGenarator++
		}
		// TODO: handling UE is roaming in VPLMN case
	}
	return nil
}

func getMaxPrecedence(pccRules map[string]models.PccRule) (maxVaule int32) {
	maxVaule = 0
	for _, rule := range pccRules {
		if rule.Precedence > maxVaule {
			maxVaule = rule.Precedence
		}
	}
	return
}

/*
func getFlowInfos(comp models.MediaComponent) (flows []models.FlowInformation, err error) {
	for _, subComp := range comp.MedSubComps {
		if subComp.EthfDescs != nil {
			return nil, fmt.Errorf("Flow Description with Mac Address does not support")
		}
		fStatus := subComp.FStatus
		if subComp.FlowUsage == models.FlowUsage_RTCP {
			fStatus = models.FlowStatus_ENABLED
		} else if fStatus == "" {
			fStatus = comp.FStatus
		}
		if fStatus == models.FlowStatus_REMOVED {
			continue
		}
		// gate control
		statusUsage := map[models.FlowDirection]bool{
			models.FlowDirection_UPLINK:   true,
			models.FlowDirection_DOWNLINK: true,
		}
		switch fStatus {
		case models.FlowStatus_ENABLED_UPLINK:
			statusUsage[models.FlowDirection_DOWNLINK] = false
		case models.FlowStatus_ENABLED_DOWNLINK:
			statusUsage[models.FlowDirection_UPLINK] = false
		case models.FlowStatus_DISABLED:
			statusUsage[models.FlowDirection_DOWNLINK] = false
			statusUsage[models.FlowDirection_UPLINK] = false
		}
		for _, desc := range subComp.FDescs {
			flowDesc, flowDir, err := flowDescriptionFromN5toN7(desc)
			if err != nil {
				return nil, err
			}
			flowInfo := models.FlowInformation{
				FlowDescription:   flowDesc,
				FlowDirection:     models.FlowDirectionRm(flowDir),
				PacketFilterUsage: statusUsage[flowDir],
				TosTrafficClass:   subComp.TosTrCl,
			}
			flows = append(flows, flowInfo)
		}
	}
	return
}
*/

func getFlowInfos(subComp *models.MediaSubComponent) ([]models.FlowInformation, error) {
	var flows []models.FlowInformation
	if subComp.EthfDescs != nil {
		return nil, fmt.Errorf("Flow Description with Mac Address does not support")
	}
	fStatus := subComp.FStatus
	if subComp.FlowUsage == models.FlowUsage_RTCP {
		fStatus = models.FlowStatus_ENABLED
	}
	if fStatus == models.FlowStatus_REMOVED {
		return nil, nil
	}
	// gate control
	statusUsage := map[models.FlowDirection]bool{
		models.FlowDirection_UPLINK:   true,
		models.FlowDirection_DOWNLINK: true,
	}
	switch fStatus {
	case models.FlowStatus_ENABLED_UPLINK:
		statusUsage[models.FlowDirection_DOWNLINK] = false
	case models.FlowStatus_ENABLED_DOWNLINK:
		statusUsage[models.FlowDirection_UPLINK] = false
	case models.FlowStatus_DISABLED:
		statusUsage[models.FlowDirection_DOWNLINK] = false
		statusUsage[models.FlowDirection_UPLINK] = false
	}
	for _, desc := range subComp.FDescs {
		flowDesc, flowDir, err := flowDescriptionFromN5toN7(desc)
		if err != nil {
			return nil, err
		}
		flowInfo := models.FlowInformation{
			FlowDescription:   flowDesc,
			FlowDirection:     models.FlowDirectionRm(flowDir),
			PacketFilterUsage: statusUsage[flowDir],
			TosTrafficClass:   subComp.TosTrCl,
		}
		flows = append(flows, flowInfo)
	}
	return flows, nil
}

func flowDescriptionFromN5toN7(n5Flow string) (n7Flow string, direction models.FlowDirection, err error) {
	if strings.HasPrefix(n5Flow, "permit out") {
		n7Flow = n5Flow
		direction = models.FlowDirection_DOWNLINK
	} else if strings.HasPrefix(n5Flow, "permit in") {
		n7Flow = strings.Replace(n5Flow, "permit in", "permit out", -1)
		direction = models.FlowDirection_UPLINK
	} else if strings.HasPrefix(n5Flow, "permit inout") {
		n7Flow = strings.Replace(n5Flow, "permit inout", "permit out", -1)
		direction = models.FlowDirection_BIDIRECTIONAL
	} else {
		err = fmt.Errorf("Invaild flow Description[%s]", n5Flow)
	}
	return
}
func updateQos_Comp(qosData models.QosData, comp *models.MediaComponent) (models.QosData,
	bool, bool) {
	var dlExist bool
	var ulExist bool
	updatedQosData := qosData
	if comp.FStatus == models.FlowStatus_REMOVED {
		updatedQosData.MaxbrDl = ""
		updatedQosData.MaxbrUl = ""
		return updatedQosData, ulExist, dlExist
	}
	maxBwUl := 0.0
	maxBwDl := 0.0
	minBwUl := 0.0
	minBwDl := 0.0
	for _, subsComp := range comp.MedSubComps {
		for _, flow := range subsComp.FDescs {
			_, dir, err := flowDescriptionFromN5toN7(flow)
			if err != nil {
				logger.PolicyAuthorizationlog.Errorf(
					"flowDescriptionFromN5toN7 error in updateQos_Comp: %+v", err)
			}
			both := false
			if dir == models.FlowDirection_BIDIRECTIONAL {
				both = true
			}
			if subsComp.FlowUsage != models.FlowUsage_RTCP {
				// not RTCP
				if both || dir == models.FlowDirection_UPLINK {
					ulExist = true
					if comp.MarBwUl != "" {
						bwUl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwUl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQos_Comp: %+v", err)
						}
						maxBwUl += bwUl
					}
					if comp.MirBwUl != "" {
						bwUl, err := pcf_context.ConvertBitRateToKbps(comp.MirBwUl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQos_Comp: %+v", err)
						}
						minBwUl += bwUl
					}
				}
				if both || dir == models.FlowDirection_DOWNLINK {
					dlExist = true
					if comp.MarBwDl != "" {
						bwDl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwDl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQos_Comp: %+v", err)
						}
						maxBwDl += bwDl
					}
					if comp.MirBwDl != "" {
						bwDl, err := pcf_context.ConvertBitRateToKbps(comp.MirBwDl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQos_Comp: %+v", err)
						}
						minBwDl += bwDl
					}
				}
			} else {
				if both || dir == models.FlowDirection_UPLINK {
					ulExist = true
					if subsComp.MarBwUl != "" {
						bwUl, err := pcf_context.ConvertBitRateToKbps(subsComp.MarBwUl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQos_Comp: %+v", err)
						}
						maxBwUl += bwUl
					} else if comp.MarBwUl != "" {
						bwUl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwUl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQos_Comp: %+v", err)
						}
						maxBwUl += (0.05 * bwUl)
					}
				}
				if both || dir == models.FlowDirection_DOWNLINK {
					dlExist = true
					if subsComp.MarBwDl != "" {
						bwDl, err := pcf_context.ConvertBitRateToKbps(subsComp.MarBwDl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQos_Comp: %+v", err)
						}
						maxBwDl += bwDl
					} else if comp.MarBwDl != "" {
						bwDl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwDl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQos_Comp: %+v", err)
						}
						maxBwDl += (0.05 * bwDl)
					}
				}
			}
		}
	}
	// update Downlink MBR
	if maxBwDl == 0.0 {
		updatedQosData.MaxbrDl = comp.MarBwDl
	} else {
		updatedQosData.MaxbrDl = pcf_context.ConvertBitRateToString(maxBwDl)
	}
	// update Uplink MBR
	if maxBwUl == 0.0 {
		updatedQosData.MaxbrUl = comp.MarBwUl
	} else {
		updatedQosData.MaxbrUl = pcf_context.ConvertBitRateToString(maxBwUl)
	}
	// if gbr == 0 then assign gbr = mbr

	// update Downlink GBR
	if minBwDl != 0.0 {
		updatedQosData.GbrDl = pcf_context.ConvertBitRateToString(minBwDl)
	}
	// update Uplink GBR
	if minBwUl != 0.0 {
		updatedQosData.GbrUl = pcf_context.ConvertBitRateToString(minBwUl)
	}
	return updatedQosData, ulExist, dlExist
}

func updateQos_subComp(qosData models.QosData, comp *models.MediaComponent,
	subsComp *models.MediaSubComponent) (updatedQosData models.QosData, ulExist, dlExist bool) {
	updatedQosData = qosData
	if comp.FStatus == models.FlowStatus_REMOVED {
		updatedQosData.MaxbrDl = ""
		updatedQosData.MaxbrUl = ""
		return
	}
	maxBwUl := 0.0
	maxBwDl := 0.0
	minBwUl := 0.0
	minBwDl := 0.0
	for _, flow := range subsComp.FDescs {
		_, dir, err := flowDescriptionFromN5toN7(flow)
		if err != nil {
			logger.PolicyAuthorizationlog.Errorf(
				"flowDescriptionFromN5toN7 error in updateQos_subComp: %+v", err)
		}
		both := false
		if dir == models.FlowDirection_BIDIRECTIONAL {
			both = true
		}
		if subsComp.FlowUsage != models.FlowUsage_RTCP {
			// not RTCP
			if both || dir == models.FlowDirection_UPLINK {
				ulExist = true
				if comp.MarBwUl != "" {
					bwUl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwUl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQos_subComp: %+v", err)
					}
					maxBwUl += bwUl
				}
				if comp.MirBwUl != "" {
					bwUl, err := pcf_context.ConvertBitRateToKbps(comp.MirBwUl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQos_subComp: %+v", err)
					}
					minBwUl += bwUl
				}
			}
			if both || dir == models.FlowDirection_DOWNLINK {
				dlExist = true
				if comp.MarBwDl != "" {
					bwDl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwDl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQos_subComp: %+v", err)
					}
					maxBwDl += bwDl
				}
				if comp.MirBwDl != "" {
					bwDl, err := pcf_context.ConvertBitRateToKbps(comp.MirBwDl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQos_subComp: %+v", err)
					}
					minBwDl += bwDl
				}
			}
		} else {
			if both || dir == models.FlowDirection_UPLINK {
				ulExist = true
				if subsComp.MarBwUl != "" {
					bwUl, err := pcf_context.ConvertBitRateToKbps(subsComp.MarBwUl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQos_subComp: %+v", err)
					}
					maxBwUl += bwUl
				} else if comp.MarBwUl != "" {
					bwUl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwUl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQos_subComp: %+v", err)
					}
					maxBwUl += (0.05 * bwUl)
				}
			}
			if both || dir == models.FlowDirection_DOWNLINK {
				dlExist = true
				if subsComp.MarBwDl != "" {
					bwDl, err := pcf_context.ConvertBitRateToKbps(subsComp.MarBwDl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQos_subComp: %+v", err)
					}
					maxBwDl += bwDl
				} else if comp.MarBwDl != "" {
					bwDl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwDl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQos_subComp: %+v", err)
					}
					maxBwDl += (0.05 * bwDl)
				}
			}
		}
	}

	// update Downlink MBR
	if maxBwDl == 0.0 {
		updatedQosData.MaxbrDl = comp.MarBwDl
	} else {
		updatedQosData.MaxbrDl = pcf_context.ConvertBitRateToString(maxBwDl)
	}
	// update Uplink MBR
	if maxBwUl == 0.0 {
		updatedQosData.MaxbrUl = comp.MarBwUl
	} else {
		updatedQosData.MaxbrUl = pcf_context.ConvertBitRateToString(maxBwUl)
	}
	// if gbr == 0 then assign gbr = mbr
	// update Downlink GBR
	if minBwDl != 0.0 {
		updatedQosData.GbrDl = pcf_context.ConvertBitRateToString(minBwDl)
	}
	// update Uplink GBR
	if minBwUl != 0.0 {
		updatedQosData.GbrUl = pcf_context.ConvertBitRateToString(minBwUl)
	}
	return updatedQosData, ulExist, dlExist
}

func removeMediaComp(appSession *pcf_context.AppSessionData, compN string) {
	idMaps := appSession.RelatedPccRuleIds
	smPolicy := appSession.SmPolicyData
	if idMaps != nil {
		if appSession.AppSessionContext.AscReqData.MedComponents == nil {
			return
		}
		comp, exist := appSession.AppSessionContext.AscReqData.MedComponents[compN]
		if !exist {
			return
		}
		if comp.MedSubComps != nil {
			for fNum := range comp.MedSubComps {
				key := fmt.Sprintf("%s-%s", compN, fNum)
				pccRuleId := idMaps[key]
				err := smPolicy.RemovePccRule(pccRuleId)
				if err != nil {
					logger.PolicyAuthorizationlog.Warnf(err.Error())
				}
				delete(appSession.RelatedPccRuleIds, key)
				delete(appSession.PccRuleIdMapToCompId, pccRuleId)
			}
		} else {
			pccRuleId := idMaps[compN]
			err := smPolicy.RemovePccRule(pccRuleId)
			if err != nil {
				logger.PolicyAuthorizationlog.Warnf(err.Error())
			}
			delete(appSession.RelatedPccRuleIds, compN)
			delete(appSession.PccRuleIdMapToCompId, pccRuleId)
		}
		delete(appSession.AppSessionContext.AscReqData.MedComponents, compN)
	}
}

// func removeMediaSubComp(appSession *pcf_context.AppSessionData, compN, fNum string) {
// 	key := fmt.Sprintf("%s-%s", compN, fNum)
// 	idMaps := appSession.RelatedPccRuleIds
// 	smPolicy := appSession.SmPolicyData
// 	if idMaps != nil {
// 		if appSession.AppSessionContext.AscReqData.MedComponents == nil {
// 			return
// 		}
// 		if comp, exist := appSession.AppSessionContext.AscReqData.MedComponents[compN]; exist {
// 			pccRuleId := idMaps[key]
// 			smPolicy.RemovePccRule(pccRuleId)
// 			delete(appSession.RelatedPccRuleIds, key)
// 			delete(comp.MedSubComps, fNum)
// 			appSession.AppSessionContext.AscReqData.MedComponents[compN] = comp
// 		}
// 	}
// 	return
// }

func threshRmToThresh(threshrm *models.UsageThresholdRm) *models.UsageThreshold {
	if threshrm == nil {
		return nil
	}
	return &models.UsageThreshold{
		Duration:       threshrm.Duration,
		TotalVolume:    threshrm.TotalVolume,
		DownlinkVolume: threshrm.DownlinkVolume,
		UplinkVolume:   threshrm.UplinkVolume,
	}
}

func extractUmData(umId string, eventSubs map[models.AfEvent]models.AfNotifMethod,
	threshold *models.UsageThreshold) (umData *models.UsageMonitoringData, err error) {
	if _, umExist := eventSubs[models.AfEvent_USAGE_REPORT]; umExist {
		if threshold == nil {
			return nil, fmt.Errorf("UsageThreshold is nil in USAGE REPORT Subscription")

		} else {
			tmp := util.CreateUmData(umId, *threshold)
			umData = &tmp
		}
	}
	return
}

func modifyRemainBitRate(smPolicy *pcf_context.UeSmPolicyData, qosData *models.QosData,
	ulExist, dlExist bool) *models.ProblemDetails {
	// if request GBR == 0, qos GBR = MBR
	// if request GBR > remain GBR, qos GBR = remain GBR
	if ulExist {
		if qosData.GbrUl == "" {
			// err = pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrUL, qosData.MaxbrUl)
			if err := pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrUL, qosData.MaxbrUl); err != nil {
				qosData.GbrUl = pcf_context.DecreaseRamainBitRateToZero(smPolicy.RemainGbrUL)
			} else {
				qosData.GbrUl = qosData.MaxbrUl
			}
		} else {
			// err = pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrUL, qosData.GbrUl)
			if err := pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrUL, qosData.GbrUl); err != nil {
				problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				// sendProblemDetail(httpChannel, err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				return &problemDetail
			}
		}
	}
	if dlExist {
		if qosData.GbrDl == "" {
			// err = pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrDL, qosData.MaxbrDl)
			if err := pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrDL, qosData.MaxbrDl); err != nil {
				qosData.GbrDl = pcf_context.DecreaseRamainBitRateToZero(smPolicy.RemainGbrDL)
			} else {
				qosData.GbrDl = qosData.MaxbrDl
			}
		} else {
			// err = pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrDL, qosData.GbrDl)
			if err := pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrDL, qosData.GbrDl); err != nil {
				// if Policy failed, revert remain GBR to original GBR
				pcf_context.IncreaseRamainBitRate(smPolicy.RemainGbrUL, qosData.GbrUl)
				problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				// sendProblemDetail(httpChannel, err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				return &problemDetail
			}
		}
	}
	return nil
}

func provisioningOfTrafficRoutingInfo(smPolicy *pcf_context.UeSmPolicyData, appId string,
	routeReq *models.AfRoutingRequirement, fStatus models.FlowStatus) *models.PccRule {
	createdTcData := util.CreateTcData(smPolicy.PccRuleIdGenarator, fStatus)
	createdTcData.RouteToLocs = routeReq.RouteToLocs
	createdTcData.UpPathChgEvent = routeReq.UpPathChgSub

	//TODO : handle temporal or spatial validity
	pccRule := util.GetPccRuleByAfAppId(smPolicy.PolicyDecision.PccRules, appId)
	if pccRule != nil {
		createdTcData.TcId = strings.ReplaceAll(pccRule.PccRuleId, "PccRule", "Tc")
		pccRule.RefTcData = []string{createdTcData.TcId}
		pccRule.AppReloc = routeReq.AppReloc
		util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, &createdTcData, nil, nil, nil)
		logger.PolicyAuthorizationlog.Infof("Modify PCC rule[%s] with new Traffic Control Data[%s]",
			pccRule.PccRuleId, createdTcData.TcId)
	} else {
		// Create a Pcc Rule if afappId dose not match any pcc rule
		maxPrecedence := getMaxPrecedence(smPolicy.PolicyDecision.PccRules)
		pccRule = util.CreatePccRule(smPolicy.PccRuleIdGenarator, maxPrecedence+1, nil, appId, false)
		qosData := models.QosData{
			QosId:                util.GetQosId(smPolicy.PccRuleIdGenarator),
			DefQosFlowIndication: true,
		}
		pccRule.RefTcData = []string{createdTcData.TcId}
		pccRule.RefQosData = []string{qosData.QosId}
		util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, &createdTcData, &qosData, nil, nil)
		smPolicy.PccRuleIdGenarator++
		logger.PolicyAuthorizationlog.Infof("Create PCC rule[%s] with new Traffic Control Data[%s]",
			pccRule.PccRuleId, createdTcData.TcId)
	}
	return pccRule
}

func reverseStringMap(srcMap map[string]string) map[string]string {
	if srcMap == nil {
		return nil
	}
	reverseMap := make(map[string]string)
	for key, value := range srcMap {
		reverseMap[value] = key
	}
	return reverseMap
}
