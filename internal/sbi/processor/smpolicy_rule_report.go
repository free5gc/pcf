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

// removeFailedPccRules removes from smPolicy the PCC rules the SMF reports as not installed or no
// longer enforced (ruleStatus INACTIVE), and returns the reports of active and failed PCC rules.
func removeFailedPccRules(
	smPolicy *pcf_context.UeSmPolicyData, ruleReports []models.Pcf_SMPolCtrl_RuleReport,
) (successRules, failRules []models.Pcf_SMPolCtrl_RuleReport) {
	for _, rule := range ruleReports {
		if rule.RuleStatus == models.Pcf_SMPolCtrl_RuleStatus_ACTIVE {
			successRules = append(successRules, rule)
			continue
		}
		failRules = append(failRules, rule)
		// release fail pccRules in SmPolicy
		for _, pccRuleID := range rule.PccRuleIds {
			if err := smPolicy.RemovePccRule(pccRuleID, nil); err != nil {
				logger.SmPolicyLog.Warnf(
					"SM Policy Notification about failed installing PccRule[%s]", err.Error())
			}
		}
	}
	return successRules, failRules
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
// update notification of the SM policy resourceUri: they are removed from the SM policy, and the
// AF sessions subscribed to FAILED_RESOURCES_ALLOCATION are notified, as for a PCC rule report
// received in an SM policy update.
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

	successRules, failRules := removeFailedPccRules(smPolicy, ruleReports)
	if len(failRules) == 0 {
		return
	}
	p.sendSmPolicyRelatedAppSessionNotification(smPolicy, models.Pcf_PolAuth_EventsNotification{
		EvNotifs: []models.Pcf_PolAuth_AfEventNotification{{
			Event: models.Pcf_PolAuth_AfEvent_FAILED_RESOURCES_ALLOCATION,
		}},
	}, nil, successRules, failRules)
}
