package processor

import (
	"errors"
	"path"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/pcf/SMPolCtrl"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
)

// PCC Rule Error Report, TS 29.512 clauses 4.2.3.2 and 4.2.4.15.

// splitRuleReports returns the reports of active PCC rules and of PCC rules the SMF reports as not
// installed or no longer enforced (ruleStatus INACTIVE).
func splitRuleReports(ruleReports []models.Pcf_SMPolCtrl_RuleReport,
) (successRules, failRules []models.Pcf_SMPolCtrl_RuleReport) {
	for _, rule := range ruleReports {
		if rule.RuleStatus == models.Pcf_SMPolCtrl_RuleStatus_ACTIVE {
			successRules = append(successRules, rule)
		} else {
			failRules = append(failRules, rule)
		}
	}
	return successRules, failRules
}

// removeFailedPccRules removes the failed PCC rules from smPolicy. It is called once the AF sessions
// are notified: the removal also removes the PCC rules from the AF sessions, which the notification
// needs to find their media components.
func removeFailedPccRules(smPolicy *pcf_context.UeSmPolicyData, failRules []models.Pcf_SMPolCtrl_RuleReport) {
	for _, rule := range failRules {
		for _, pccRuleID := range rule.PccRuleIds {
			if err := smPolicy.RemovePccRule(pccRuleID, nil); err != nil {
				logger.SmPolicyLog.Warnf(
					"SM Policy Notification about failed installing PccRule[%s]", err.Error())
			}
		}
	}
}

// appSessionsWithAllRulesFailed returns the AF sessions of smPolicy all PCC rules of which fail.
// It is called before the AF sessions are notified, which removes the failed PCC rules from them.
func appSessionsWithAllRulesFailed(pcfSelf *pcf_context.PCFContext, smPolicy *pcf_context.UeSmPolicyData,
	failRules []models.Pcf_SMPolCtrl_RuleReport,
) []*pcf_context.AppSessionData {
	failed := make(map[string]bool)
	for _, rule := range failRules {
		for _, pccRuleID := range rule.PccRuleIds {
			failed[pccRuleID] = true
		}
	}
	var appSessions []*pcf_context.AppSessionData
	for appSessionID := range smPolicy.AppSessions {
		val, exist := pcfSelf.AppSessionPool.Load(appSessionID)
		if !exist {
			continue
		}
		appSession := val.(*pcf_context.AppSessionData)
		if len(appSession.RelatedPccRuleIds) == 0 {
			continue
		}
		allFailed := true
		for _, pccRuleID := range appSession.RelatedPccRuleIds {
			if !failed[pccRuleID] {
				allFailed = false
				break
			}
		}
		if allFailed {
			appSessions = append(appSessions, appSession)
		}
	}
	return appSessions
}

// handleRuleReports handles the PCC rule reports of the SMF (TS 29.512 clause 4.2.4.15): the AF
// sessions subscribed to FAILED_RESOURCES_ALLOCATION are notified of the failed PCC rules, along with
// afEventsNotification if it has events, then the failed PCC rules are removed. The AF sessions all
// PCC rules of which fail are requested to be deleted with ALL_SDF_DEACTIVATION (TS 29.514 clause
// 4.2.5.3).
func (p *Processor) handleRuleReports(smPolicy *pcf_context.UeSmPolicyData,
	afEventsNotification models.Pcf_PolAuth_EventsNotification,
	accuUsageReports []models.Pcf_SMPolCtrl_AccuUsageReport, ruleReports []models.Pcf_SMPolCtrl_RuleReport,
) {
	successRules, failRules := splitRuleReports(ruleReports)
	var terminated []*pcf_context.AppSessionData
	if len(failRules) > 0 {
		terminated = appSessionsWithAllRulesFailed(p.Context(), smPolicy, failRules)
		afEventsNotification.EvNotifs = append(afEventsNotification.EvNotifs, models.Pcf_PolAuth_AfEventNotification{
			Event: models.Pcf_PolAuth_AfEvent_FAILED_RESOURCES_ALLOCATION,
		})
	}
	if afEventsNotification.EvNotifs != nil {
		p.sendSmPolicyRelatedAppSessionNotification(
			smPolicy, afEventsNotification, accuUsageReports, successRules, failRules)
	}
	removeFailedPccRules(smPolicy, failRules)
	terminationInfo := models.Pcf_PolAuth_TerminationInfo{
		TermCause: models.Pcf_PolAuth_TerminationCause_ALL_SDF_DEACTIVATION,
	}
	for _, appSession := range terminated {
		if appSession.AppSessionContext == nil || appSession.AppSessionContext.AscReqData == nil {
			continue
		}
		logger.PolicyAuthLog.Infof("App Session Id[%s]: all its PCC rules failed, request its deletion",
			appSession.AppSessionId)
		p.SendAppSessionTermination(appSession, terminationInfo)
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
	ue := p.Context().PCFUeFindByPolicyId(smPolicyID)
	if ue == nil || ue.SmPolicyData[smPolicyID] == nil {
		logger.SmPolicyLog.Warnf("PCC rule reports for unknown SM Policy[%s]", smPolicyID)
		return
	}
	smPolicy := ue.SmPolicyData[smPolicyID]

	p.handleRuleReports(smPolicy, models.Pcf_PolAuth_EventsNotification{}, nil, ruleReports)
}
