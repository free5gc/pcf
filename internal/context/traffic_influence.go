package context

import (
	"strings"

	"github.com/free5gc/openapi/models"
)

// TrafficInfluenceState records only TI requests, generated rules and routing
// references overwritten by TI. Service QoS and precedence remain in the policy.
type TrafficInfluenceState struct {
	Requests       []TrafficInfluenceRequest
	RuleSources    map[string]string
	OriginalRoutes map[string][]string
}

type TrafficInfluenceRequest struct {
	ID       string
	Data     models.Udr_DR_TrafficInfluData
	Charging *models.Pcf_SMPolCtrl_ChargingData
	RuleIDs  map[string]string // Source PCC rule ID to generated partial/fallback rule ID.
}

func (policy *UeSmPolicyData) trafficInfluenceRuleSources() map[string]string {
	if policy.TrafficInfluence == nil {
		return nil
	}
	return policy.TrafficInfluence.RuleSources
}

func IsTrafficInfluenceRoute(ruleID, tcID string) bool {
	return tcID == "TI-"+ruleID || strings.HasPrefix(tcID, "TI-"+ruleID+"-")
}
