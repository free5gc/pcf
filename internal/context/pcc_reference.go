package context

// Shared policy data must survive until the last referencing rule is removed.
func (policy *UeSmPolicyData) qosReferencedByOtherRule(ruleID, dataID string) bool {
	return policy.dataReferencedByOtherRule(ruleID, dataID, "Qos")
}

func (policy *UeSmPolicyData) dataReferencedByOtherRule(ruleID, dataID, kind string) bool {
	for id, rule := range policy.PolicyDecision.PccRules {
		if id == ruleID || rule == nil {
			continue
		}
		var refs []string
		switch kind {
		case "Qos":
			refs = rule.RefQosData
		case "Chg":
			refs = rule.RefChgData
		case "Tc":
			refs = rule.RefTcData
		case "Um":
			refs = rule.RefUmData
		case "Cond":
			refs = []string{rule.RefCondData}
		}
		for _, ref := range refs {
			if ref == dataID {
				return true
			}
		}
	}
	return false
}
