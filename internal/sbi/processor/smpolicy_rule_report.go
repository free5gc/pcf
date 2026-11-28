package processor

import (
	"errors"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/pcf/SMPolCtrl"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/util"
)

// PCC Rule Error Report, TS 29.512 clauses 4.2.3.2 and 4.2.4.15.

// splitRuleReports returns the reports of PCC rules successfully installed, modified or activated,
// and of the PCC rules that failed (TS 29.512 clause 4.2.4.15): those reported INACTIVE (not
// installed, or no longer enforced) and those reported ACTIVE with a failureCode (their modification
// failed and the SMF retains their previous definition).
func splitRuleReports(ruleReports []models.Pcf_SMPolCtrl_RuleReport,
) (successRules, failRules []models.Pcf_SMPolCtrl_RuleReport) {
	for _, rule := range ruleReports {
		if rule.RuleStatus == models.Pcf_SMPolCtrl_RuleStatus_ACTIVE && rule.FailureCode == "" {
			successRules = append(successRules, rule)
		} else {
			failRules = append(failRules, rule)
		}
	}
	return successRules, failRules
}

// resourcesStatus returns the status of the resources of a failed PCC rule: INACTIVE, or ACTIVE
// when the SMF retains its previous definition.
func resourcesStatus(rule models.Pcf_SMPolCtrl_RuleReport) models.Pcf_PolAuth_MediaComponentResourcesStatus {
	if rule.RuleStatus == models.Pcf_SMPolCtrl_RuleStatus_ACTIVE {
		return models.Pcf_PolAuth_MediaComponentResourcesStatus_ACTIVE
	}
	return models.Pcf_PolAuth_MediaComponentResourcesStatus_INACTIVE
}

// failedResourcesAllocationReports returns the failedResourcAllocReports of appSession for the
// failed PCC rules (TS 29.514 clause 4.2.5.8), one per status of their resources (mcResourcStatus).
// The PCC rules that are no longer active are released from appSession.
func failedResourcesAllocationReports(appSession *pcf_context.AppSessionData,
	failRules []models.Pcf_SMPolCtrl_RuleReport,
) []models.Pcf_PolAuth_ResourcesAllocationInfo {
	var reports []models.Pcf_PolAuth_ResourcesAllocationInfo
	for _, status := range []models.Pcf_PolAuth_MediaComponentResourcesStatus{
		models.Pcf_PolAuth_MediaComponentResourcesStatus_INACTIVE,
		models.Pcf_PolAuth_MediaComponentResourcesStatus_ACTIVE,
	} {
		report := models.Pcf_PolAuth_ResourcesAllocationInfo{McResourcStatus: status}
		subFlows := make(map[int32]models.Pcf_PolAuth_Flows)
		for _, rule := range failRules {
			if resourcesStatus(rule) != status {
				continue
			}
			for _, pccRuleID := range rule.PccRuleIds {
				key, exist := appSession.PccRuleIdMapToCompId[pccRuleID]
				if !exist {
					continue
				}
				if status == models.Pcf_PolAuth_MediaComponentResourcesStatus_INACTIVE {
					// Release related resource
					delete(appSession.PccRuleIdMapToCompId, pccRuleID)
					delete(appSession.RelatedPccRuleIds, key)
				}
				items := strings.Split(key, "-")
				if items[0] == "appId" {
					continue
				}
				compN, err := strconv.Atoi(items[0])
				if err != nil {
					logger.SmPolicyLog.Errorf("strconv Atoi error %+v", err)
				}
				compN32 := int32(compN)
				switch len(items) {
				case 1:
					report.Flows = append(report.Flows, models.Pcf_PolAuth_Flows{MedCompN: compN32})
				case 2:
					fNum, err := strconv.Atoi(items[1])
					if err != nil {
						logger.SmPolicyLog.Errorf("strconv Atoi error %+v", err)
					}
					flow := subFlows[compN32]
					flow.MedCompN = compN32
					flow.FNums = append(flow.FNums, int32(fNum))
					subFlows[compN32] = flow
				}
			}
		}
		for _, compN := range slices.Sorted(maps.Keys(subFlows)) {
			report.Flows = append(report.Flows, subFlows[compN])
		}
		if report.Flows != nil {
			reports = append(reports, report)
		}
	}
	return reports
}

// removeFailedPccRules removes the PCC rules that are no longer active from smPolicy. It is called
// once the AF sessions are notified: the removal also removes the PCC rules from the AF sessions,
// which the notification needs to find their media components.
func removeFailedPccRules(smPolicy *pcf_context.UeSmPolicyData, failRules []models.Pcf_SMPolCtrl_RuleReport) {
	for _, rule := range failRules {
		if rule.RuleStatus == models.Pcf_SMPolCtrl_RuleStatus_ACTIVE {
			continue
		}
		for _, pccRuleID := range rule.PccRuleIds {
			if err := smPolicy.RemovePccRule(pccRuleID, nil); err != nil {
				logger.SmPolicyLog.Warnf(
					"SM Policy Notification about failed installing PccRule[%s]", err.Error())
			}
		}
	}
}

// appSessionTermination is a request to the AF to delete its AF session.
type appSessionTermination struct {
	appSession *pcf_context.AppSessionData
	cause      models.Pcf_PolAuth_TerminationCause
}

// appSessionsWithAllRulesFailed returns the AF sessions of smPolicy all PCC rules of which are no
// longer active, with the cause of their termination (TS 29.514 clause 4.2.5.3): PS_TO_CS_HO if
// IMS_SBI is supported and all of them failed with PS_TO_CS_HAN, ALL_SDF_DEACTIVATION otherwise.
// It is called before the AF sessions are notified, which releases the failed PCC rules from them.
func appSessionsWithAllRulesFailed(pcfSelf *pcf_context.PCFContext, smPolicy *pcf_context.UeSmPolicyData,
	failRules []models.Pcf_SMPolCtrl_RuleReport,
) []appSessionTermination {
	failureCodes := make(map[string]models.Pcf_SMPolCtrl_FailureCode)
	for _, rule := range failRules {
		if rule.RuleStatus == models.Pcf_SMPolCtrl_RuleStatus_ACTIVE {
			continue
		}
		for _, pccRuleID := range rule.PccRuleIds {
			failureCodes[pccRuleID] = rule.FailureCode
		}
	}
	var terminations []appSessionTermination
	for appSessionID := range smPolicy.AppSessions {
		val, exist := pcfSelf.AppSessionPool.Load(appSessionID)
		if !exist {
			continue
		}
		appSession := val.(*pcf_context.AppSessionData)
		if len(appSession.RelatedPccRuleIds) == 0 {
			continue
		}
		allFailed, psToCsHandover := true, imsSbiSupported(appSession)
		for _, pccRuleID := range appSession.RelatedPccRuleIds {
			failureCode, failed := failureCodes[pccRuleID]
			if !failed {
				allFailed = false
				break
			}
			if failureCode != models.Pcf_SMPolCtrl_FailureCode_PS_TO_CS_HAN {
				psToCsHandover = false
			}
		}
		if !allFailed {
			continue
		}
		cause := models.Pcf_PolAuth_TerminationCause_ALL_SDF_DEACTIVATION
		if psToCsHandover {
			cause = models.Pcf_PolAuth_TerminationCause_PS_TO_CS_HO
		}
		terminations = append(terminations, appSessionTermination{appSession: appSession, cause: cause})
	}
	return terminations
}

// imsSbiSupported returns whether the IMS_SBI feature (feature 5, TS 29.514 clause 5.8) is
// negotiated for appSession.
func imsSbiSupported(appSession *pcf_context.AppSessionData) bool {
	ctx := appSession.AppSessionContext
	return ctx != nil && ctx.AscRespData != nil && util.CheckSuppFeat(ctx.AscRespData.SuppFeat, 5)
}

// handleRuleReports handles the PCC rule reports of the SMF (TS 29.512 clause 4.2.4.15): the AF
// sessions subscribed to FAILED_RESOURCES_ALLOCATION are notified of the failed PCC rules, along with
// afEventsNotification if it has events, then the PCC rules that are no longer active are removed.
// The AF sessions all PCC rules of which are no longer active are requested to be deleted
// (TS 29.514 clause 4.2.5.3).
func (p *Processor) handleRuleReports(smPolicy *pcf_context.UeSmPolicyData,
	afEventsNotification models.Pcf_PolAuth_EventsNotification,
	accuUsageReports []models.Pcf_SMPolCtrl_AccuUsageReport, ruleReports []models.Pcf_SMPolCtrl_RuleReport,
) {
	successRules, failRules := splitRuleReports(ruleReports)
	var terminations []appSessionTermination
	if len(failRules) > 0 {
		terminations = appSessionsWithAllRulesFailed(p.Context(), smPolicy, failRules)
		afEventsNotification.EvNotifs = append(afEventsNotification.EvNotifs, models.Pcf_PolAuth_AfEventNotification{
			Event: models.Pcf_PolAuth_AfEvent_FAILED_RESOURCES_ALLOCATION,
		})
	}
	if afEventsNotification.EvNotifs != nil {
		p.sendSmPolicyRelatedAppSessionNotification(
			smPolicy, afEventsNotification, accuUsageReports, successRules, failRules)
	}
	removeFailedPccRules(smPolicy, failRules)
	for _, termination := range terminations {
		appSession := termination.appSession
		if appSession.AppSessionContext == nil || appSession.AppSessionContext.AscReqData == nil {
			continue
		}
		logger.PolicyAuthLog.Infof("App Session Id[%s]: all its PCC rules failed, request its deletion (%s)",
			appSession.AppSessionId, termination.cause)
		p.SendAppSessionTermination(appSession, models.Pcf_PolAuth_TerminationInfo{TermCause: termination.cause})
	}
}

// notificationRuleReports returns the PCC rule reports of the ErrorReport the SMF answered an SM
// policy update notification with (subclause 4.2.3.2 in TS29512), if any.
func notificationRuleReports(err error) []models.Pcf_SMPolCtrl_RuleReport {
	var apiErr openapi.GenericOpenAPIError
	if !errors.As(err, &apiErr) {
		return nil
	}
	notifErr, ok := apiErr.ErrorModel.(SMPolCtrl.CreateSMPolicySmPolicyUpdateNotificationError)
	if !ok || notifErr.Pcf_SMPolCtrl_ErrorReport == nil {
		return nil
	}
	return notifErr.Pcf_SMPolCtrl_ErrorReport.RuleReports
}

// handleNotificationRuleReports handles the PCC rules the SMF could not install for an SM policy
// update notification of the SM policy resourceUri, as for a PCC rule report received in an SM
// policy update, see handleRuleReports.
func (p *Processor) handleNotificationRuleReports(
	resourceUri string, ruleReports []models.Pcf_SMPolCtrl_RuleReport,
) {
	smPolicyID := path.Base(resourceUri)
	smPolicy := p.Context().PCFUeFindByPolicyId(smPolicyID).LoadSmPolicy(smPolicyID)
	if smPolicy == nil {
		logger.SmPolicyLog.Warnf("PCC rule reports for unknown SM Policy[%s]", smPolicyID)
		return
	}

	p.handleRuleReports(smPolicy, models.Pcf_PolAuth_EventsNotification{}, nil, ruleReports)
}

// handleNotificationPartialSuccess handles the "200 OK" answer of the SMF to an SM policy update
// notification it could enforce only partially (TS 29.512 clause 4.2.3.2): the PCC rules reported in
// the PartialSuccessReports are handled as in an ErrorReport, then the access network information of
// their UeCampingRep, if any.
func (p *Processor) handleNotificationPartialSuccess(notification *models.Pcf_SMPolCtrl_SmPolicyNotification,
	reports []models.Pcf_SMPolCtrl_PartialSuccessReport,
) {
	var ruleReports []models.Pcf_SMPolCtrl_RuleReport
	for _, report := range reports {
		logger.SmPolicyLog.Warnf("SM Policy Update Notification partially enforced[%s]", report.FailureCause)
		ruleReports = append(ruleReports, report.RuleReports...)
	}
	if len(ruleReports) != 0 {
		p.handleNotificationRuleReports(notification.ResourceUri, ruleReports)
	}
	for _, report := range reports {
		if rep := report.UeCampingRep; rep != nil {
			p.handleNotificationAccessNetworkInfo(notification, &models.CreateSMPolicySmPolicyUpdateNotificationResponse200{
				AccessType:          rep.AccessType,
				RatType:             rep.RatType,
				ServNfId:            rep.ServNfId,
				ServingNetwork:      rep.ServingNetwork,
				UserLocationInfo:    rep.UserLocationInfo,
				UeTimeZone:          rep.UeTimeZone,
				NetLocAccSupp:       rep.NetLocAccSupp,
				SatBackhaulCategory: rep.SatBackhaulCategory,
			})
		}
	}
}
