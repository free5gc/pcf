package context

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi/models"
)

func TestAccessNetworkInfoRequest(t *testing.T) {
	succResAllo := models.Pcf_SMPolCtrl_RequestedRuleData{
		RefPccRuleIds: []string{"PccRuleId-9"},
		ReqData:       []models.Pcf_SMPolCtrl_RequestedRuleDataType{models.Pcf_SMPolCtrl_RequestedRuleDataType_SUCC_RES_ALLO},
	}
	policy := &UeSmPolicyData{PolicyDecision: &models.Pcf_SMPolCtrl_SmPolicyDecision{
		LastReqRuleData: []models.Pcf_SMPolCtrl_RequestedRuleData{succResAllo},
	}}

	policy.AddAccessNetworkInfoRequest(
		[]models.Pcf_SMPolCtrl_RequestedRuleDataType{models.Pcf_SMPolCtrl_RequestedRuleDataType_USER_LOC_INFO},
		[]string{"PccRuleId-1"})
	// A second AF session's request is merged into the same entry.
	policy.AddAccessNetworkInfoRequest(
		[]models.Pcf_SMPolCtrl_RequestedRuleDataType{
			models.Pcf_SMPolCtrl_RequestedRuleDataType_USER_LOC_INFO,
			models.Pcf_SMPolCtrl_RequestedRuleDataType_MS_TIME_ZONE,
		},
		[]string{"PccRuleId-2"})

	decision := policy.PolicyDecision
	require.Equal(t, []models.Pcf_SMPolCtrl_PolicyControlRequestTrigger{
		models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_AN_INFO,
	}, decision.PolicyCtrlReqTriggers)
	require.Equal(t, []models.Pcf_SMPolCtrl_RequestedRuleData{
		succResAllo,
		{
			RefPccRuleIds: []string{"PccRuleId-1", "PccRuleId-2"},
			ReqData: []models.Pcf_SMPolCtrl_RequestedRuleDataType{
				models.Pcf_SMPolCtrl_RequestedRuleDataType_USER_LOC_INFO,
				models.Pcf_SMPolCtrl_RequestedRuleDataType_MS_TIME_ZONE,
			},
		},
	}, decision.LastReqRuleData)

	// Removing the request keeps the rule data requested for other purposes.
	require.True(t, policy.RemoveAccessNetworkInfoRequest())
	require.Equal(t, []models.Pcf_SMPolCtrl_RequestedRuleData{succResAllo}, decision.LastReqRuleData)
	require.False(t, policy.RemoveAccessNetworkInfoRequest())
}

func TestArrangeExistEventSubscriptionWithdrawsAccessNetworkInfoRequest(t *testing.T) {
	policy := &UeSmPolicyData{
		AppSessions:    map[string]bool{},
		PolicyDecision: &models.Pcf_SMPolCtrl_SmPolicyDecision{},
	}
	policy.AddAccessNetworkInfoRequest(
		[]models.Pcf_SMPolCtrl_RequestedRuleDataType{models.Pcf_SMPolCtrl_RequestedRuleDataType_USER_LOC_INFO},
		[]string{"PccRuleId-1"})

	// No AF session subscribes to ANI_REPORT anymore.
	require.True(t, policy.ArrangeExistEventSubscription())
	require.Empty(t, policy.PolicyDecision.PolicyCtrlReqTriggers)
	require.Empty(t, policy.PolicyDecision.LastReqRuleData)
}
