package util

import (
	"fmt"
	"sort"

	"github.com/mohae/deepcopy"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
)

// SetTrafficInfluencePolicy applies routing to intersections with the currently
// authorized service filters. It does not authorize a new service QoS or choose a QFI.
// Stage the complete update so an unsupported filter cannot partially change policy.
func SetTrafficInfluencePolicy(policy *pcf_context.UeSmPolicyData, influenceID string,
	data models.Udr_DR_TrafficInfluData, charging *models.Pcf_SMPolCtrl_ChargingData,
) (*models.Pcf_SMPolCtrl_SmPolicyDecision, error) {
	if policy.PolicyDecision == nil || policy.PolicyContext == nil {
		return nil, fmt.Errorf("missing session policy context")
	}
	if len(data.TrafficFilters) == 0 || data.AfAppId != "" {
		return nil, fmt.Errorf("TI QoS preservation requires explicit IP traffic filters without an application ID")
	}
	stage := deepcopy.Copy(policy.PolicyDecision).(*models.Pcf_SMPolCtrl_SmPolicyDecision)
	sources := make(map[string]string)
	for ruleID, sourceID := range policy.InfluencePccRuleSources {
		sources[ruleID] = sourceID
	}
	var bases []*models.Pcf_SMPolCtrl_PccRule
	for id, rule := range stage.PccRules {
		if rule != nil && sources[id] == "" {
			bases = append(bases, rule)
		}
	}
	sort.Slice(bases, func(i, j int) bool {
		if bases[i].Precedence == bases[j].Precedence {
			return bases[i].PccRuleId < bases[j].PccRuleId
		}
		return bases[i].Precedence < bases[j].Precedence
	})
	oldIDs := append([]string(nil), policy.InfluenceDataToPccRule[influenceID]...)
	oldBySource := make(map[string]string)
	oldPrecedence := make(map[string]int32)
	for _, id := range oldIDs {
		oldBySource[sources[id]] = id
		oldPrecedence[id] = stage.PccRules[id].Precedence
	}
	// Removal only releases data no longer referenced by another PCC rule.
	stagedPolicy := &pcf_context.UeSmPolicyData{PolicyDecision: stage, PolicyContext: policy.PolicyContext}
	deleted := &models.Pcf_SMPolCtrl_SmPolicyDecision{}
	for _, id := range oldIDs {
		if err := stagedPolicy.RemovePccRule(id, deleted); err != nil {
			return nil, err
		}
		delete(sources, id)
	}
	filterInfos := convertToFlowinfos(&data)
	if len(filterInfos) == 0 {
		return nil, fmt.Errorf("TI request contains no IP flow descriptions")
	}
	for _, filter := range filterInfos {
		if _, err := strictIPFilter(filter.FlowDescription); err != nil {
			return nil, err
		}
	}
	generator := policy.PccRuleIdGenerator
	var ids []string
	defaultFound := false
	for _, base := range bases {
		if len(base.FlowInfos) == 0 {
			return nil, fmt.Errorf("cannot determine TI overlap with PCC rule %s", base.PccRuleId)
		}
		var intersections []models.Pcf_SMPolCtrl_FlowInformation
		for _, baseFilter := range base.FlowInfos {
			for _, filter := range filterInfos {
				flow, matches, err := intersectTIFlow(baseFilter, filter, []string{
					policy.PolicyContext.Ipv4Address, policy.PolicyContext.Ipv6AddressPrefix,
				})
				if err != nil {
					return nil, fmt.Errorf("PCC rule %s: %w", base.PccRuleId, err)
				}
				if matches {
					intersections = append(intersections, flow)
				}
			}
		}
		if len(intersections) == 0 {
			continue
		}
		rule := deepcopy.Copy(base).(*models.Pcf_SMPolCtrl_PccRule)
		id := oldBySource[base.PccRuleId]
		if id == "" {
			id = GetPccRuleId(generator)
			generator++
		}
		rule.PccRuleId, rule.FlowInfos = id, intersections
		if previous, exists := oldPrecedence[id]; exists {
			rule.Precedence = previous
		}
		var qos *models.Pcf_SMPolCtrl_QosData
		if base.Precedence == 255 {
			defaultFound = true
			qos = &models.Pcf_SMPolCtrl_QosData{QosId: "TI-" + id, DefQosFlowIndication: true}
		} else if len(rule.RefQosData) != 1 || stage.QosDecs[rule.RefQosData[0]] == nil {
			return nil, fmt.Errorf("PCC rule %s has no unambiguous authorized QoS reference", base.PccRuleId)
		}
		if base.Precedence != 255 {
			authorized := stage.QosDecs[rule.RefQosData[0]]
			if authorized.GbrUl != "" || authorized.GbrDl != "" ||
				(authorized.Var5qi >= 1 && authorized.Var5qi <= 4) ||
				len(base.RefAltQosParams) != 0 || len(base.RefQosMon) != 0 ||
				base.TscaiInputDl != nil || base.TscaiInputUl != nil {
				return nil, fmt.Errorf("PCC rule %s requires service-specific resource or binding handling", base.PccRuleId)
			}
		}
		tc := convertToTrafficControlData(&data)
		tc.TcId = "TI-" + id
		if len(base.RefTcData) > 1 {
			return nil, fmt.Errorf("PCC rule %s has multiple traffic control references", base.PccRuleId)
		}
		if len(base.RefTcData) == 1 {
			original := stage.TraffContDecs[base.RefTcData[0]]
			if original == nil {
				return nil, fmt.Errorf("PCC rule %s has missing traffic control data", base.PccRuleId)
			}
			preserved := deepcopy.Copy(original).(*models.Pcf_SMPolCtrl_TrafficControlData)
			preserved.TcId, preserved.RouteToLocs = tc.TcId, tc.RouteToLocs
			preserved.UpPathChgEvent = tc.UpPathChgEvent
			tc = preserved
		}
		SetPccRuleRelatedData(stage, rule, tc, qos, charging, nil)
		ids = append(ids, id)
		sources[id] = base.PccRuleId
	}
	if !defaultFound {
		return nil, fmt.Errorf("TI IP filters require an applicable default PCC rule")
	}
	if err := orderTrafficInfluenceRules(stage, bases, sources); err != nil {
		return nil, err
	}
	*policy.PolicyDecision = *stage
	policy.PccRuleIdGenerator = generator
	if policy.InfluenceDataToPccRule == nil {
		policy.InfluenceDataToPccRule = make(map[string][]string)
	}
	policy.InfluenceDataToPccRule[influenceID] = ids
	policy.InfluencePccRuleSources = sources
	return trafficInfluenceNotification(stage, deleted), nil
}

// Keep each overlay just ahead of its original service rule. A broad default-QoS
// TI overlay must never win over a more specific authorized service rule.
func orderTrafficInfluenceRules(decision *models.Pcf_SMPolCtrl_SmPolicyDecision,
	bases []*models.Pcf_SMPolCtrl_PccRule, sources map[string]string,
) error {
	if len(decision.PccRules) > 255 {
		return fmt.Errorf("TI rules exceed the available PCC precedence range")
	}
	precedence := int32(1)
	for _, base := range bases {
		var overlays []string
		for id, source := range sources {
			if source == base.PccRuleId {
				overlays = append(overlays, id)
			}
		}
		// Existing TI order wins when multiple routing requests overlap.
		sort.Slice(overlays, func(i, j int) bool {
			a, b := decision.PccRules[overlays[i]], decision.PccRules[overlays[j]]
			if a.Precedence == b.Precedence {
				return a.PccRuleId < b.PccRuleId
			}
			return a.Precedence < b.Precedence
		})
		for _, id := range overlays {
			decision.PccRules[id].Precedence = precedence
			precedence++
		}
		if base.Precedence != 255 {
			base.Precedence = precedence
			precedence++
		}
	}
	return nil
}

func RemoveTrafficInfluencePolicy(policy *pcf_context.UeSmPolicyData, influenceID string) (
	*models.Pcf_SMPolCtrl_SmPolicyDecision, error,
) {
	deleted := &models.Pcf_SMPolCtrl_SmPolicyDecision{}
	ids := append([]string(nil), policy.InfluenceDataToPccRule[influenceID]...)
	for _, id := range ids {
		if err := policy.RemovePccRule(id, deleted); err != nil {
			return nil, err
		}
	}
	delete(policy.InfluenceDataToPccRule, influenceID)
	return trafficInfluenceNotification(policy.PolicyDecision, deleted), nil
}

func trafficInfluenceNotification(
	decision, deleted *models.Pcf_SMPolCtrl_SmPolicyDecision,
) *models.Pcf_SMPolCtrl_SmPolicyDecision {
	notification := deepcopy.Copy(decision).(*models.Pcf_SMPolCtrl_SmPolicyDecision)
	for id := range deleted.PccRules {
		if notification.PccRules[id] == nil {
			notification.PccRules[id] = nil
		}
	}
	return notification
}
