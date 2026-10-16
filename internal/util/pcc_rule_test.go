package util_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/util"
)

func TestTrafficInfluencePolicyIncludesDefaultQoSBinding(t *testing.T) {
	cases := []struct {
		name     string
		charging *models.Pcf_SMPolCtrl_ChargingData
	}{
		{name: "without charging"},
		{name: "offline charging", charging: &models.Pcf_SMPolCtrl_ChargingData{ChgId: "chg", Offline: true}},
		{name: "online charging", charging: &models.Pcf_SMPolCtrl_ChargingData{ChgId: "chg", Online: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision := &models.Pcf_SMPolCtrl_SmPolicyDecision{}
			rule := util.CreatePccRule(3, 129, nil, "")
			ti := trafficInfluenceData("mec")
			util.SetSmPolicyDecisionByTrafficInfluData(decision, rule, ti, tc.charging)

			// Exercise the notification's JSON contract, not just the in-memory model.
			wire, err := json.Marshal(&models.Pcf_SMPolCtrl_SmPolicyNotification{SmPolicyDecision: decision})
			if err != nil {
				t.Fatal(err)
			}
			var notification models.Pcf_SMPolCtrl_SmPolicyNotification
			if err = json.Unmarshal(wire, &notification); err != nil {
				t.Fatal(err)
			}
			got := notification.SmPolicyDecision
			gotRule := got.PccRules[rule.PccRuleId]
			if gotRule == nil {
				t.Fatal("notification is missing the TI PCC rule")
			}
			qos := referencedTIQoS(t, got, gotRule)
			if !qos.DefQosFlowIndication {
				t.Fatal("TI rule must explicitly bind to the default QoS flow")
			}
			if !reflect.DeepEqual(gotRule.FlowInfos, rule.FlowInfos) {
				t.Fatal("notification changed the traffic filters")
			}
			if len(gotRule.RefTcData) != 1 {
				t.Fatalf("traffic control references = %v, want one", gotRule.RefTcData)
			}
			tcData := got.TraffContDecs[gotRule.RefTcData[0]]
			if tcData == nil || !reflect.DeepEqual(tcData.RouteToLocs, ti.TrafficRoutes) {
				t.Fatal("TI routing data was not preserved")
			}
			if tc.charging != nil {
				if len(gotRule.RefChgData) != 1 || gotRule.RefChgData[0] != tc.charging.ChgId {
					t.Fatalf("charging references = %v", gotRule.RefChgData)
				}
				if !reflect.DeepEqual(got.ChgDecs[tc.charging.ChgId], tc.charging) {
					t.Fatal("TI charging data was not preserved")
				}
			} else if len(gotRule.RefChgData) != 0 {
				t.Fatalf("unexpected charging references: %v", gotRule.RefChgData)
			}
		})
	}
}

func TestTrafficInfluenceQoSLifecycle(t *testing.T) {
	existingQoS := &models.Pcf_SMPolCtrl_QosData{QosId: "1", Var5qi: 8, Arp: &models.Arp{PriorityLevel: 8}}
	decision := &models.Pcf_SMPolCtrl_SmPolicyDecision{
		QosDecs: map[string]*models.Pcf_SMPolCtrl_QosData{existingQoS.QosId: existingQoS},
	}
	first := util.CreatePccRule(3, 129, nil, "")
	second := util.CreatePccRule(4, 130, nil, "")
	util.SetSmPolicyDecisionByTrafficInfluData(decision, first, trafficInfluenceData("mec"), nil)
	util.SetSmPolicyDecisionByTrafficInfluData(decision, second, trafficInfluenceData("mec"), nil)
	firstQoS := referencedTIQoS(t, decision, first)
	secondQoS := referencedTIQoS(t, decision, second)
	if firstQoS.QosId == secondQoS.QosId || firstQoS.QosId == existingQoS.QosId {
		t.Fatal("TI rules must own their QoS data independently of other rules")
	}
	if !firstQoS.DefQosFlowIndication || !secondQoS.DefQosFlowIndication {
		t.Fatal("both TI rules must bind to the default QoS flow")
	}

	// Route updates must retain the binding and avoid orphaned QoS decisions.
	util.SetSmPolicyDecisionByTrafficInfluData(decision, first, trafficInfluenceData("other-mec"), nil)
	updatedQoS := referencedTIQoS(t, decision, first)
	if updatedQoS.QosId != firstQoS.QosId || !updatedQoS.DefQosFlowIndication || len(decision.QosDecs) != 3 {
		t.Fatalf("route update changed QoS ownership: %+v", decision.QosDecs)
	}
	tcData := decision.TraffContDecs[first.RefTcData[0]]
	if len(tcData.RouteToLocs) != 1 || tcData.RouteToLocs[0].Dnai != "other-mec" {
		t.Fatal("TI route was not updated")
	}

	// Use the real policy cleanup path to verify removal cannot delete another rule's QoS.
	policy := &pcf_context.UeSmPolicyData{PolicyDecision: decision}
	deleted := &models.Pcf_SMPolCtrl_SmPolicyDecision{}
	if err := policy.RemovePccRule(first.PccRuleId, deleted); err != nil {
		t.Fatal(err)
	}
	if _, exists := decision.PccRules[first.PccRuleId]; exists {
		t.Fatal("removed TI PCC rule remains in the policy")
	}
	if _, exists := decision.QosDecs[firstQoS.QosId]; exists {
		t.Fatal("removed TI rule's QoS data remains in the policy")
	}
	if decision.QosDecs[secondQoS.QosId] != secondQoS || decision.QosDecs[existingQoS.QosId] != existingQoS {
		t.Fatal("removing one TI rule changed another rule's QoS data")
	}
	if value, exists := deleted.PccRules[first.PccRuleId]; !exists || value != nil {
		t.Fatal("removal notification does not contain the PCC deletion marker")
	}
}

func trafficInfluenceData(dnai string) models.Udr_DR_TrafficInfluData {
	return models.Udr_DR_TrafficInfluData{
		Dnn:    "internet",
		Snssai: &models.Snssai{Sst: 1},
		TrafficFilters: []models.Nef_FlowInfo{{
			FlowId:           1,
			FlowDescriptions: []string{"permit out ip from 10.100.0.0/16 to 10.60.0.0/16"},
		}},
		TrafficRoutes: []models.RouteToLocation{{Dnai: dnai}},
	}
}

func referencedTIQoS(t *testing.T, decision *models.Pcf_SMPolCtrl_SmPolicyDecision,
	rule *models.Pcf_SMPolCtrl_PccRule,
) *models.Pcf_SMPolCtrl_QosData {
	t.Helper()
	if len(rule.RefQosData) != 1 {
		t.Fatalf("TI rule %s QoS references = %v, want one", rule.PccRuleId, rule.RefQosData)
	}
	qos := decision.QosDecs[rule.RefQosData[0]]
	if qos == nil || qos.QosId != rule.RefQosData[0] {
		t.Fatalf("TI rule %s refers to missing or inconsistent QoS data", rule.PccRuleId)
	}
	return qos
}
