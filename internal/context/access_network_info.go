package context

import (
	"slices"
	"sync"

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

// RemoveAccessNetworkInfoTrigger withdraws the AN_INFO policy control request trigger.
func (policy *UeSmPolicyData) RemoveAccessNetworkInfoTrigger() {
	if decision := policy.PolicyDecision; decision != nil {
		decision.PolicyCtrlReqTriggers = slices.DeleteFunc(decision.PolicyCtrlReqTriggers,
			func(trigger models.Pcf_SMPolCtrl_PolicyControlRequestTrigger) bool {
				return trigger == models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_AN_INFO
			})
	}
}

// appSessionDeletion tracks the deletion of an AF session, which may have to wait for the
// access network information requested at deletion (TS 29.514 clause 4.2.4.6).
type appSessionDeletion struct {
	mu        sync.Mutex
	deleting  bool
	aniReport chan models.Pcf_PolAuth_EventsNotification
}

// MarkDeleting marks the AF session as being deleted: it is no longer accessible to the
// NF service consumer. It returns false if the session is already being deleted.
// With waitAni, the returned channel receives the access network information reported by
// the SMF, see DeliverAccessNetworkInfo.
func (appSession *AppSessionData) MarkDeleting(waitAni bool) (
	aniReport <-chan models.Pcf_PolAuth_EventsNotification, ok bool,
) {
	d := &appSession.deletion
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.deleting {
		return nil, false
	}
	d.deleting = true
	if waitAni {
		d.aniReport = make(chan models.Pcf_PolAuth_EventsNotification, 1)
	}
	return d.aniReport, true
}

// Deleting reports whether the AF session is being deleted.
func (appSession *AppSessionData) Deleting() bool {
	d := &appSession.deletion
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.deleting
}

// DeliverAccessNetworkInfo hands the access network information reported by the SMF to the
// deletion of the AF session waiting for it. It returns false if no deletion is waiting.
func (appSession *AppSessionData) DeliverAccessNetworkInfo(report models.Pcf_PolAuth_EventsNotification) bool {
	d := &appSession.deletion
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.aniReport == nil {
		return false
	}
	d.aniReport <- report // buffered: a deletion waits for one report only
	d.aniReport = nil
	return true
}
