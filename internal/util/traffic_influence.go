package util

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/mohae/deepcopy"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
)

// SetTrafficInfluencePolicy updates fully covered service rules in place. Only
// partial service matches and default traffic need additional PCC rules.
func SetTrafficInfluencePolicy(policy *pcf_context.UeSmPolicyData, influenceID string,
	data models.Udr_DR_TrafficInfluData, charging *models.Pcf_SMPolCtrl_ChargingData,
) (*models.Pcf_SMPolCtrl_SmPolicyDecision, error) {
	if len(data.TrafficFilters) == 0 || data.AfAppId != "" {
		return nil, fmt.Errorf("TI routing requires explicit IP traffic filters without an application ID")
	}
	state := copyTrafficInfluenceState(policy.TrafficInfluence)
	request := deepcopy.Copy(pcf_context.TrafficInfluenceRequest{
		ID: influenceID, Data: data, Charging: charging,
	}).(pcf_context.TrafficInfluenceRequest)
	found := false
	for i, existing := range state.Requests {
		if existing.ID == influenceID {
			request.RuleIDs = existing.RuleIDs
			state.Requests[i], found = request, true
			break
		}
	}
	if !found {
		state.Requests = append(state.Requests, request)
	}
	return rebuildTrafficInfluence(policy, state)
}

func RemoveTrafficInfluencePolicy(policy *pcf_context.UeSmPolicyData, influenceID string) (
	*models.Pcf_SMPolCtrl_SmPolicyDecision, error,
) {
	state := copyTrafficInfluenceState(policy.TrafficInfluence)
	for i, request := range state.Requests {
		if request.ID == influenceID {
			state.Requests = append(state.Requests[:i], state.Requests[i+1:]...)
			break
		}
	}
	return rebuildTrafficInfluence(policy, state)
}

func copyTrafficInfluenceState(state *pcf_context.TrafficInfluenceState) *pcf_context.TrafficInfluenceState {
	if state == nil {
		return &pcf_context.TrafficInfluenceState{}
	}
	return deepcopy.Copy(state).(*pcf_context.TrafficInfluenceState)
}

// Reapply active requests from the original routing references. This makes route
// updates and out-of-order deletion reversible without restoring stale QoS data.
func rebuildTrafficInfluence(policy *pcf_context.UeSmPolicyData, state *pcf_context.TrafficInfluenceState) (
	*models.Pcf_SMPolCtrl_SmPolicyDecision, error,
) {
	if policy.PolicyDecision == nil || policy.PolicyContext == nil {
		return nil, fmt.Errorf("missing session policy context")
	}
	stage := deepcopy.Copy(policy.PolicyDecision).(*models.Pcf_SMPolCtrl_SmPolicyDecision)
	old := copyTrafficInfluenceState(policy.TrafficInfluence)
	for id, refs := range old.OriginalRoutes {
		if rule := stage.PccRules[id]; rule != nil && len(rule.RefTcData) == 1 &&
			pcf_context.IsTrafficInfluenceRoute(id, rule.RefTcData[0]) {
			previousTC := rule.RefTcData[0]
			if len(refs) != 0 {
				rule.RefTcData = refs
			} else {
				// An omitted refTcData means "unchanged" in an update. Materialize
				// the original implicit route under a different, explicit reference.
				tc := &models.Pcf_SMPolCtrl_TrafficControlData{
					TcId: "TI-original-" + id, FlowStatus: models.Pcf_PolAuth_FlowStatus_ENABLED,
				}
				SetPccRuleRelatedData(stage, rule, tc, nil, nil, nil)
			}
			deleteUnusedTrafficInfluenceRoute(stage, previousTC)
		}
	}
	cleanup := &pcf_context.UeSmPolicyData{PolicyDecision: stage, PolicyContext: policy.PolicyContext}
	for id := range old.RuleSources {
		if stage.PccRules[id] != nil {
			if err := cleanup.RemovePccRule(id, nil); err != nil {
				return nil, err
			}
		}
	}
	state.RuleSources = make(map[string]string)
	state.OriginalRoutes = make(map[string][]string)
	var bases []*models.Pcf_SMPolCtrl_PccRule
	for _, rule := range stage.PccRules {
		if rule != nil {
			bases = append(bases, rule)
		}
	}
	sort.Slice(bases, func(i, j int) bool {
		if bases[i].Precedence == bases[j].Precedence {
			return bases[i].PccRuleId < bases[j].PccRuleId
		}
		return bases[i].Precedence < bases[j].Precedence
	})
	filters := make([][]models.Pcf_SMPolCtrl_FlowInformation, len(state.Requests))
	for i := range state.Requests {
		filters[i] = convertToFlowinfos(&state.Requests[i].Data)
		if len(filters[i]) == 0 {
			return nil, fmt.Errorf("TI request contains no IP flow descriptions")
		}
		for _, filter := range filters[i] {
			if _, err := strictIPFilter(filter.FlowDescription); err != nil {
				return nil, err
			}
		}
	}
	assigned := []string{policy.PolicyContext.Ipv4Address, policy.PolicyContext.Ipv6AddressPrefix}
	generator := policy.PccRuleIdGenerator
	lower := int32(0)
	for _, base := range bases {
		if len(state.Requests) == 0 {
			break
		}
		if len(base.FlowInfos) == 0 {
			return nil, fmt.Errorf("cannot determine TI overlap with PCC rule %s", base.PccRuleId)
		}
		for i := range state.Requests {
			request := &state.Requests[i]
			matches, err := trafficInfluenceIntersections(base.FlowInfos, filters[i], assigned)
			if err != nil {
				return nil, fmt.Errorf("PCC rule %s: %w", base.PccRuleId, err)
			}
			if len(matches) == 0 {
				continue
			}
			if base.Precedence == 255 {
				covered, err := coveredByServices(matches, bases, assigned)
				if err != nil {
					return nil, err
				}
				if covered {
					continue
				}
			} else {
				if len(base.RefQosData) != 1 || stage.QosDecs[base.RefQosData[0]] == nil {
					return nil, fmt.Errorf("PCC rule %s has no authorized QoS reference", base.PccRuleId)
				}
				covered, err := trafficInfluenceCovered(base.FlowInfos, filters[i], assigned)
				if err != nil {
					return nil, err
				}
				if covered {
					state.OriginalRoutes[base.PccRuleId] = append([]string(nil), base.RefTcData...)
					if err := setTrafficInfluenceRoute(stage, base, request.Data); err != nil {
						return nil, err
					}
					break // The first active request covering this traffic retains priority.
				}
				qos := stage.QosDecs[base.RefQosData[0]]
				if qos.GbrUl != "" || qos.GbrDl != "" || (qos.Var5qi >= 1 && qos.Var5qi <= 4) ||
					len(base.RefAltQosParams) != 0 || len(base.RefQosMon) != 0 ||
					base.TscaiInputDl != nil || base.TscaiInputUl != nil {
					return nil, fmt.Errorf("partial coverage of PCC rule %s requires resource/binding handling", base.PccRuleId)
				}
			}
			precedence, err := availableTrafficInfluencePrecedence(stage, lower, base.Precedence)
			if err != nil {
				return nil, err
			}
			if request.RuleIDs == nil {
				request.RuleIDs = make(map[string]string)
			}
			id := request.RuleIDs[base.PccRuleId]
			if id == "" {
				id = GetPccRuleId(generator)
				generator++
				request.RuleIDs[base.PccRuleId] = id
			}
			rule := deepcopy.Copy(base).(*models.Pcf_SMPolCtrl_PccRule)
			rule.PccRuleId, rule.FlowInfos, rule.Precedence = id, matches, precedence
			var qos *models.Pcf_SMPolCtrl_QosData
			var charging *models.Pcf_SMPolCtrl_ChargingData
			if base.Precedence == 255 {
				qos = &models.Pcf_SMPolCtrl_QosData{QosId: "TI-" + id, DefQosFlowIndication: true}
				charging = deepcopy.Copy(request.Charging).(*models.Pcf_SMPolCtrl_ChargingData)
			}
			SetPccRuleRelatedData(stage, rule, nil, qos, charging, nil)
			if err := setTrafficInfluenceRoute(stage, rule, request.Data); err != nil {
				return nil, err
			}
			state.RuleSources[id] = base.PccRuleId
		}
		lower = base.Precedence
	}
	for i := range state.Requests {
		for source, id := range state.Requests[i].RuleIDs {
			if state.RuleSources[id] == "" {
				delete(state.Requests[i].RuleIDs, source)
			}
		}
	}
	notification := TrafficInfluencePolicyChanges(policy.PolicyDecision, stage)
	*policy.PolicyDecision, policy.TrafficInfluence, policy.PccRuleIdGenerator = *stage, state, generator
	return notification, nil
}

func setTrafficInfluenceRoute(decision *models.Pcf_SMPolCtrl_SmPolicyDecision,
	rule *models.Pcf_SMPolCtrl_PccRule, data models.Udr_DR_TrafficInfluData,
) error {
	tc := &models.Pcf_SMPolCtrl_TrafficControlData{FlowStatus: models.Pcf_PolAuth_FlowStatus_ENABLED}
	if len(rule.RefTcData) > 1 {
		return fmt.Errorf("PCC rule %s has multiple traffic control references", rule.PccRuleId)
	}
	if len(rule.RefTcData) == 1 {
		original := decision.TraffContDecs[rule.RefTcData[0]]
		if original == nil {
			return fmt.Errorf("PCC rule %s has missing traffic control data", rule.PccRuleId)
		}
		tc = deepcopy.Copy(original).(*models.Pcf_SMPolCtrl_TrafficControlData)
	}
	tc.TcId = ""
	if len(data.TrafficRoutes) != 0 {
		tc.RouteToLocs = deepcopy.Copy(data.TrafficRoutes).([]models.RouteToLocation)
	}
	if event := convertToTrafficControlData(&data).UpPathChgEvent; event != nil {
		tc.UpPathChgEvent = event
	}
	// A new reference for changed content also clears omitted optional fields.
	// Identical content retains its reference and produces no notification.
	encoded, err := json.Marshal(tc)
	if err != nil {
		return fmt.Errorf("encode TI traffic control data: %w", err)
	}
	digest := sha256.Sum256(encoded)
	tc.TcId = fmt.Sprintf("TI-%s-%x", rule.PccRuleId, digest[:12])
	SetPccRuleRelatedData(decision, rule, tc, nil, nil, nil)
	return nil
}

func availableTrafficInfluencePrecedence(decision *models.Pcf_SMPolCtrl_SmPolicyDecision,
	lower, upper int32,
) (int32, error) {
	used := make(map[int32]bool)
	for _, rule := range decision.PccRules {
		used[rule.Precedence] = true
	}
	for value := lower + 1; value < upper; value++ {
		if !used[value] {
			return value, nil
		}
	}
	return 0, fmt.Errorf("no unused TI precedence between %d and %d; existing priorities were preserved", lower, upper)
}

// TrafficInfluenceNeedsDefault identifies requests requiring a new default-flow
// rule. Existing service rules retain their charging policy when only routing changes.
func TrafficInfluenceNeedsDefault(
	policy *pcf_context.UeSmPolicyData, data models.Udr_DR_TrafficInfluData,
) (bool, error) {
	if policy.PolicyContext == nil || policy.PolicyDecision == nil {
		return false, fmt.Errorf("missing session policy context")
	}
	if len(data.TrafficFilters) == 0 || data.AfAppId != "" {
		return false, fmt.Errorf("TI routing requires explicit IP traffic filters without an application ID")
	}
	filters := convertToFlowinfos(&data)
	if len(filters) == 0 {
		return false, fmt.Errorf("TI request contains no IP flow descriptions")
	}
	assigned := []string{policy.PolicyContext.Ipv4Address, policy.PolicyContext.Ipv6AddressPrefix}
	defaultRule := CreateDefaultPccRules(0)
	matched, err := trafficInfluenceIntersections(defaultRule.FlowInfos, filters, assigned)
	if err != nil {
		return false, err
	}
	if len(matched) == 0 {
		return false, fmt.Errorf("TI filters do not apply to the session UE address")
	}
	var bases []*models.Pcf_SMPolCtrl_PccRule
	for id, rule := range policy.PolicyDecision.PccRules {
		if rule != nil && (policy.TrafficInfluence == nil || policy.TrafficInfluence.RuleSources[id] == "") {
			bases = append(bases, rule)
		}
	}
	covered, err := coveredByServices(matched, bases, assigned)
	return !covered, err
}

func deleteUnusedTrafficInfluenceRoute(decision *models.Pcf_SMPolCtrl_SmPolicyDecision, tcID string) {
	if !trafficInfluenceRouteReferenced(decision, tcID) {
		delete(decision.TraffContDecs, tcID)
	}
}

func trafficInfluenceRouteReferenced(decision *models.Pcf_SMPolCtrl_SmPolicyDecision, tcID string) bool {
	for _, rule := range decision.PccRules {
		if rule != nil {
			for _, ref := range rule.RefTcData {
				if ref == tcID {
					return true
				}
			}
		}
	}
	return false
}

// TrafficInfluencePolicyChanges omits unchanged rules and previously supplied
// policy data. Missing entries are not deletions; removed PCC rules require null.
func TrafficInfluencePolicyChanges(
	before, after *models.Pcf_SMPolCtrl_SmPolicyDecision,
) *models.Pcf_SMPolCtrl_SmPolicyDecision {
	changed := changedTrafficInfluenceData(before.PccRules, after.PccRules)
	for id := range before.PccRules {
		if after.PccRules[id] == nil {
			if changed == nil {
				changed = make(map[string]*models.Pcf_SMPolCtrl_PccRule)
			}
			changed[id] = nil
		}
	}
	result := &models.Pcf_SMPolCtrl_SmPolicyDecision{
		PccRules:      changed,
		QosDecs:       changedTrafficInfluenceData(before.QosDecs, after.QosDecs),
		TraffContDecs: changedTrafficInfluenceData(before.TraffContDecs, after.TraffContDecs),
		ChgDecs:       changedTrafficInfluenceData(before.ChgDecs, after.ChgDecs),
	}
	// Resend the data referenced by a changed rule. In particular, the SMF may
	// have discarded an original route while TI temporarily replaced its reference.
	for _, rule := range changed {
		if rule != nil {
			result.QosDecs = referencedTrafficInfluenceData(result.QosDecs, after.QosDecs, rule.RefQosData)
			result.TraffContDecs = referencedTrafficInfluenceData(result.TraffContDecs, after.TraffContDecs, rule.RefTcData)
			result.ChgDecs = referencedTrafficInfluenceData(result.ChgDecs, after.ChgDecs, rule.RefChgData)
		}
	}
	for id := range result.TraffContDecs {
		if !trafficInfluenceRouteReferenced(after, id) {
			delete(result.TraffContDecs, id)
		}
	}
	return deepcopy.Copy(result).(*models.Pcf_SMPolCtrl_SmPolicyDecision)
}

func changedTrafficInfluenceData[T any](before, after map[string]*T) map[string]*T {
	var changed map[string]*T
	for id, data := range after {
		if !reflect.DeepEqual(before[id], data) {
			if changed == nil {
				changed = make(map[string]*T)
			}
			changed[id] = data
		}
	}
	return changed
}

func referencedTrafficInfluenceData[T any](changed, available map[string]*T, refs []string) map[string]*T {
	for _, ref := range refs {
		if data := available[ref]; data != nil {
			if changed == nil {
				changed = make(map[string]*T)
			}
			changed[ref] = data
		}
	}
	return changed
}
