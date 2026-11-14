package context

import (
	"slices"

	"github.com/free5gc/openapi/models"
)

// Access network information (NetLoc) requested from the SMF on behalf of AF ANI_REPORT
// subscriptions, TS 29.512 clause 4.2.6.5.4.

func isAccessNetworkInfoReqData(reqData models.Pcf_SMPolCtrl_RequestedRuleDataType) bool {
	return reqData == models.Pcf_SMPolCtrl_RequestedRuleDataType_USER_LOC_INFO ||
		reqData == models.Pcf_SMPolCtrl_RequestedRuleDataType_MS_TIME_ZONE
}

// AddAccessNetworkInfoRequest asks the SMF to report the given access network information
// for the given PCC rules: it records the request in "lastReqRuleData" and provisions the
// AN_INFO policy control request trigger if not provided yet.
// Requests of several AF sessions are merged into one RequestedRuleData entry.
func (policy *UeSmPolicyData) AddAccessNetworkInfoRequest(
	reqData []models.Pcf_SMPolCtrl_RequestedRuleDataType, refPccRuleIds []string,
) {
	decision := policy.PolicyDecision
	merged := false
	for i := range decision.LastReqRuleData {
		ruleData := &decision.LastReqRuleData[i]
		if !slices.ContainsFunc(ruleData.ReqData, isAccessNetworkInfoReqData) {
			continue
		}
		for _, data := range reqData {
			if !slices.Contains(ruleData.ReqData, data) {
				ruleData.ReqData = append(ruleData.ReqData, data)
			}
		}
		for _, id := range refPccRuleIds {
			if !slices.Contains(ruleData.RefPccRuleIds, id) {
				ruleData.RefPccRuleIds = append(ruleData.RefPccRuleIds, id)
			}
		}
		merged = true
		break
	}
	if !merged {
		decision.LastReqRuleData = append(decision.LastReqRuleData, models.Pcf_SMPolCtrl_RequestedRuleData{
			RefPccRuleIds: slices.Clone(refPccRuleIds),
			ReqData:       slices.Clone(reqData),
		})
	}
	if !slices.Contains(decision.PolicyCtrlReqTriggers, models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_AN_INFO) {
		decision.PolicyCtrlReqTriggers = append(decision.PolicyCtrlReqTriggers,
			models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_AN_INFO)
	}
}

// RemoveAccessNetworkInfoRequest withdraws the access network information request from
// "lastReqRuleData", e.g. once the SMF has reported it. It returns true if anything was removed.
func (policy *UeSmPolicyData) RemoveAccessNetworkInfoRequest() (removed bool) {
	decision := policy.PolicyDecision
	if decision == nil {
		return false
	}
	ruleDataList := decision.LastReqRuleData[:0]
	for _, ruleData := range decision.LastReqRuleData {
		reqData := slices.DeleteFunc(slices.Clone(ruleData.ReqData), isAccessNetworkInfoReqData)
		if len(reqData) != len(ruleData.ReqData) {
			removed = true
		}
		if len(reqData) == 0 {
			continue
		}
		ruleData.ReqData = reqData
		ruleDataList = append(ruleDataList, ruleData)
	}
	if len(ruleDataList) == 0 {
		ruleDataList = nil
	}
	decision.LastReqRuleData = ruleDataList
	return removed
}
