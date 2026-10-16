package util_test

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"sort"
	"testing"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/util"
	"github.com/free5gc/util/flowdesc"
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
			policy := trafficInfluencePolicy()
			ti := trafficInfluenceData("mec")
			decision, err := util.SetTrafficInfluencePolicy(policy, "ti", ti, tc.charging)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(&models.Pcf_SMPolCtrl_SmPolicyNotification{SmPolicyDecision: decision})
			if err != nil {
				t.Fatal(err)
			}
			var notification models.Pcf_SMPolCtrl_SmPolicyNotification
			if err = json.Unmarshal(wire, &notification); err != nil {
				t.Fatal(err)
			}
			got := notification.SmPolicyDecision
			rule := got.PccRules[policy.InfluenceDataToPccRule["ti"][0]]
			if !referencedTIQoS(t, got, rule).DefQosFlowIndication {
				t.Fatal("default service traffic must retain default-flow binding")
			}
			if len(rule.RefTcData) != 1 ||
				!reflect.DeepEqual(got.TraffContDecs[rule.RefTcData[0]].RouteToLocs, ti.TrafficRoutes) {
				t.Fatal("TI routing data was not preserved")
			}
			if tc.charging != nil {
				if len(rule.RefChgData) != 1 || !reflect.DeepEqual(got.ChgDecs[rule.RefChgData[0]], tc.charging) {
					t.Fatal("TI charging data was not preserved")
				}
			}
		})
	}
}

func TestTrafficInfluencePreservesOverlappingServiceQoS(t *testing.T) {
	policy := trafficInfluencePolicy()
	qos := &models.Pcf_SMPolCtrl_QosData{QosId: "service", Var5qi: 8, Arp: &models.Arp{PriorityLevel: 8}}
	policy.PolicyDecision.QosDecs = map[string]*models.Pcf_SMPolCtrl_QosData{qos.QosId: qos}
	service := util.CreatePccRule(2, 128, []models.Pcf_SMPolCtrl_FlowInformation{{
		FlowDescription: "permit out 6 from 10.100.1.0/24 80-90 to assigned",
		FlowDirection:   models.Pcf_SMPolCtrl_FlowDirectionRm_DOWNLINK,
		PackFiltId:      "service-filter",
	}}, "")
	service.RefQosData = []string{qos.QosId}
	policy.PolicyDecision.PccRules[service.PccRuleId] = service
	policy.PackFiltMapToPccRuleId = map[string]string{"service-filter": service.PccRuleId}
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", trafficInfluenceData("mec"), nil); err != nil {
		t.Fatal(err)
	}
	if len(policy.InfluenceDataToPccRule["ti"]) != 2 {
		t.Fatal("a broad TI request must retain separate service and default QoS rules")
	}
	cases := []struct {
		name, source, direction, qos, route string
		protocol                            uint8
		port                                uint16
	}{
		{"dedicated overlap", "10.100.1.2", "DOWNLINK", "service", "mec", 6, 85},
		{"default overlap", "10.100.2.2", "DOWNLINK", "default", "mec", 6, 85},
		{"different protocol", "10.100.1.2", "DOWNLINK", "default", "mec", 17, 85},
		{"different port", "10.100.1.2", "DOWNLINK", "default", "mec", 6, 443},
		{"different direction", "10.100.1.2", "UPLINK", "default", "mec", 6, 85},
		{"outside TI", "1.1.1.1", "DOWNLINK", "default", "", 6, 85},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := matchingRule(t, policy.PolicyDecision, tc.source, tc.protocol, tc.port, tc.direction)
			if tc.route != "" && (len(rule.RefTcData) != 1 ||
				policy.PolicyDecision.TraffContDecs[rule.RefTcData[0]].RouteToLocs[0].Dnai != tc.route) {
				t.Fatalf("packet did not receive TI routing: %+v", rule)
			}
			if tc.route == "" && len(rule.RefTcData) != 0 {
				t.Fatal("TI routing escaped the requested traffic filter")
			}
			if tc.qos == "service" {
				if !reflect.DeepEqual(rule.RefQosData, []string{qos.QosId}) {
					t.Fatalf("dedicated service QoS changed: %v", rule.RefQosData)
				}
			} else if len(rule.RefQosData) != 0 && !referencedTIQoS(t, policy.PolicyDecision, rule).DefQosFlowIndication {
				t.Fatal("default service received dedicated QoS")
			}
		})
	}
	before := append([]string(nil), policy.InfluenceDataToPccRule["ti"]...)
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", trafficInfluenceData("other-mec"), nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, policy.InfluenceDataToPccRule["ti"]) {
		t.Fatal("route updates must keep stable PCC IDs for unchanged service intersections")
	}
	deleted, err := util.RemoveTrafficInfluencePolicy(policy, "ti")
	if err != nil {
		t.Fatal(err)
	}
	if policy.PolicyDecision.QosDecs[qos.QosId] == nil || len(policy.PolicyDecision.QosDecs) != 1 {
		t.Fatal("TI removal must retain service QoS and release its own default QoS")
	}
	if policy.PackFiltMapToPccRuleId["service-filter"] != service.PccRuleId {
		t.Fatal("TI removal deleted the original service's packet-filter mapping")
	}
	for _, id := range before {
		if value, exists := deleted.PccRules[id]; !exists || value != nil {
			t.Fatal("TI deletion notification is missing a derived rule deletion")
		}
	}
}

func TestTrafficInfluenceQoSLifecycle(t *testing.T) {
	policy := trafficInfluencePolicy()
	for _, id := range []string{"first", "second"} {
		if _, err := util.SetTrafficInfluencePolicy(policy, id, trafficInfluenceData("mec"), nil); err != nil {
			t.Fatal(err)
		}
	}
	first := policy.InfluenceDataToPccRule["first"][0]
	if _, err := util.SetTrafficInfluencePolicy(policy, "first", trafficInfluenceData("updated-mec"), nil); err != nil {
		t.Fatal(err)
	}
	winner := matchingRule(t, policy.PolicyDecision, "10.100.2.1", 6, 80, "DOWNLINK")
	if winner.PccRuleId != first {
		t.Fatal("updating a TI route changed the priority between overlapping TI requests")
	}
	second := policy.InfluenceDataToPccRule["second"][0]
	secondQoS := referencedTIQoS(t, policy.PolicyDecision, policy.PolicyDecision.PccRules[second]).QosId
	if _, err := util.RemoveTrafficInfluencePolicy(policy, "first"); err != nil {
		t.Fatal(err)
	}
	if len(policy.PolicyDecision.QosDecs) != 1 || policy.PolicyDecision.QosDecs[secondQoS] == nil {
		t.Fatal("removing one TI request changed another request's default binding")
	}
	if _, err := util.RemoveTrafficInfluencePolicy(policy, "second"); err != nil {
		t.Fatal(err)
	}
	if len(policy.PolicyDecision.QosDecs) != 0 || len(policy.PolicyDecision.PccRules) != 1 {
		t.Fatal("TI removal left orphaned rules or QoS data")
	}
}

func TestTrafficInfluenceRejectsAmbiguousFiltersWithoutChangingPolicy(t *testing.T) {
	for _, description := range []string{
		"permit out ip from 10.100.0.0/16 to assigned established",
		"permit out 999 from any to assigned",
		"permit out 6 from any 90-80 to assigned",
		"permit out ip from !10.100.0.0/16 to assigned",
	} {
		t.Run(description, func(t *testing.T) {
			policy := trafficInfluencePolicy()
			if _, err := util.SetTrafficInfluencePolicy(policy, "ti", trafficInfluenceData("mec"), nil); err != nil {
				t.Fatal(err)
			}
			before, err := json.Marshal(policy.PolicyDecision)
			if err != nil {
				t.Fatal(err)
			}
			beforeID := policy.PccRuleIdGenerator
			data := trafficInfluenceData("other-mec")
			data.TrafficFilters[0].FlowDescriptions = []string{description}
			if _, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil); err == nil {
				t.Fatal("unsupported filters must not be silently broadened")
			}
			after, err := json.Marshal(policy.PolicyDecision)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) || beforeID != policy.PccRuleIdGenerator {
				t.Fatal("failed TI update modified the existing policy")
			}
		})
	}
}

func trafficInfluencePolicy() *pcf_context.UeSmPolicyData {
	rule := util.CreateDefaultPccRules(1)
	return &pcf_context.UeSmPolicyData{
		PolicyContext: &models.Pcf_SMPolCtrl_SmPolicyContextData{Ipv4Address: "10.60.0.1"},
		PolicyDecision: &models.Pcf_SMPolCtrl_SmPolicyDecision{
			PccRules: map[string]*models.Pcf_SMPolCtrl_PccRule{rule.PccRuleId: rule},
		},
		PccRuleIdGenerator: 3,
	}
}

func trafficInfluenceData(dnai string) models.Udr_DR_TrafficInfluData {
	return models.Udr_DR_TrafficInfluData{
		Dnn: "internet", Snssai: &models.Snssai{Sst: 1},
		TrafficFilters: []models.Nef_FlowInfo{{
			FlowId: 1, FlowDescriptions: []string{"permit out ip from 10.100.0.0/16 to 10.60.0.0/16"},
		}},
		TrafficRoutes: []models.RouteToLocation{{Dnai: dnai}},
	}
}

func referencedTIQoS(t *testing.T, decision *models.Pcf_SMPolCtrl_SmPolicyDecision,
	rule *models.Pcf_SMPolCtrl_PccRule,
) *models.Pcf_SMPolCtrl_QosData {
	t.Helper()
	if rule == nil || len(rule.RefQosData) != 1 {
		t.Fatalf("TI rule must have exactly one QoS reference: %+v", rule)
	}
	qos := decision.QosDecs[rule.RefQosData[0]]
	if qos == nil || qos.QosId != rule.RefQosData[0] {
		t.Fatalf("TI rule %s refers to missing or inconsistent QoS data", rule.PccRuleId)
	}
	return qos
}

// Classify sample packets in precedence order to check policy behavior, including
// the case where a broad default TI filter overlaps a narrower dedicated service.
func matchingRule(t *testing.T, decision *models.Pcf_SMPolCtrl_SmPolicyDecision,
	source string, protocol uint8, port uint16, direction string,
) *models.Pcf_SMPolCtrl_PccRule {
	t.Helper()
	var rules []*models.Pcf_SMPolCtrl_PccRule
	for _, rule := range decision.PccRules {
		if rule != nil {
			rules = append(rules, rule)
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Precedence < rules[j].Precedence })
	address := netip.MustParseAddr(source)
	for _, rule := range rules {
		for _, info := range rule.FlowInfos {
			if info.FlowDirection != "" && string(info.FlowDirection) != direction &&
				info.FlowDirection != models.Pcf_SMPolCtrl_FlowDirectionRm_BIDIRECTIONAL {
				continue
			}
			filter, err := flowdesc.Decode(info.FlowDescription)
			if err != nil {
				t.Fatal(err)
			}
			if filter.Proto != flowdesc.ProtocolNumberAny && filter.Proto != protocol {
				continue
			}
			if filter.Src != "any" {
				prefix, err := netip.ParsePrefix(filter.Src)
				if err != nil || !prefix.Contains(address) {
					continue
				}
			}
			portMatch := len(filter.SrcPorts) == 0
			for _, ports := range filter.SrcPorts {
				portMatch = portMatch || port >= ports.Start && port <= ports.End
			}
			if portMatch {
				return rule
			}
		}
	}
	t.Fatal("no PCC rule matches the test packet")
	return nil
}

func TestTrafficInfluenceFilterUpdateRemovesObsoleteServiceOverlay(t *testing.T) {
	policy := trafficInfluencePolicy()
	service := util.CreatePccRule(2, 128, []models.Pcf_SMPolCtrl_FlowInformation{{
		FlowDescription: "permit out ip from 10.100.1.0/24 to assigned",
	}}, "")
	service.RefQosData = []string{"service"}
	policy.PolicyDecision.PccRules[service.PccRuleId] = service
	policy.PolicyDecision.QosDecs = map[string]*models.Pcf_SMPolCtrl_QosData{
		"service": {QosId: "service", Var5qi: 8, Arp: &models.Arp{PriorityLevel: 8}},
	}
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", trafficInfluenceData("mec"), nil); err != nil {
		t.Fatal(err)
	}
	var dedicatedID string
	for id, source := range policy.InfluencePccRuleSources {
		if source == service.PccRuleId {
			dedicatedID = id
		}
	}
	data := trafficInfluenceData("new-mec")
	data.TrafficFilters[0].FlowDescriptions = []string{"permit out ip from 10.200.0.0/16 to assigned"}
	notification, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if value, exists := notification.PccRules[dedicatedID]; !exists || value != nil {
		t.Fatal("filter update must explicitly remove obsolete dedicated TI rules at SMF")
	}
	if len(policy.InfluenceDataToPccRule["ti"]) != 1 || policy.PolicyDecision.PccRules[dedicatedID] != nil ||
		policy.PolicyDecision.QosDecs["service"] == nil {
		t.Fatal("filter update did not retain source QoS and remove obsolete TI ownership")
	}
}

func TestTrafficInfluenceSourceRemovalCleansUpDerivedRules(t *testing.T) {
	policy := trafficInfluencePolicy()
	service := util.CreatePccRule(2, 128, []models.Pcf_SMPolCtrl_FlowInformation{{
		FlowDescription: "permit out ip from 10.100.1.0/24 to assigned",
	}}, "")
	service.RefQosData, service.RefCondData = []string{"service"}, "condition"
	service.RefChgData, service.RefUmData = []string{"charging"}, []string{"usage"}
	policy.PolicyDecision.PccRules[service.PccRuleId] = service
	policy.PolicyDecision.QosDecs = map[string]*models.Pcf_SMPolCtrl_QosData{
		"service": {QosId: "service", Var5qi: 8, Arp: &models.Arp{PriorityLevel: 8}},
	}
	policy.PolicyDecision.Conds = map[string]*models.Pcf_SMPolCtrl_ConditionData{"condition": {CondId: "condition"}}
	policy.PolicyDecision.ChgDecs = map[string]*models.Pcf_SMPolCtrl_ChargingData{"charging": {ChgId: "charging"}}
	policy.PolicyDecision.UmDecs = map[string]*models.Pcf_SMPolCtrl_UsageMonitoringData{"usage": {UmId: "usage"}}
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", trafficInfluenceData("mec"), nil); err != nil {
		t.Fatal(err)
	}
	var derived string
	for id, source := range policy.InfluencePccRuleSources {
		if source == service.PccRuleId {
			derived = id
		}
	}
	if _, err := util.RemoveTrafficInfluencePolicy(policy, "ti"); err != nil {
		t.Fatal(err)
	}
	if policy.PolicyDecision.QosDecs["service"] == nil || len(policy.PolicyDecision.Conds) != 1 ||
		len(policy.PolicyDecision.ChgDecs) != 1 || len(policy.PolicyDecision.UmDecs) != 1 {
		t.Fatal("removing TI deleted data still owned by the authorized service")
	}
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", trafficInfluenceData("mec"), nil); err != nil {
		t.Fatal(err)
	}
	for id, source := range policy.InfluencePccRuleSources {
		if source == service.PccRuleId {
			derived = id
		}
	}
	deleted := &models.Pcf_SMPolCtrl_SmPolicyDecision{}
	if err := policy.RemovePccRule(service.PccRuleId, deleted); err != nil {
		t.Fatal(err)
	}
	if value, exists := deleted.PccRules[derived]; !exists || value != nil {
		t.Fatal("removing service authorization left its derived TI rule installed")
	}
	if policy.PolicyDecision.QosDecs["service"] != nil || len(policy.PolicyDecision.Conds) != 0 ||
		len(policy.PolicyDecision.ChgDecs) != 0 || len(policy.PolicyDecision.UmDecs) != 0 {
		t.Fatal("last-reference cleanup left service policy data behind")
	}
	if len(policy.InfluenceDataToPccRule["ti"]) != 1 {
		t.Fatal("removing a dedicated service also removed the default TI overlay")
	}
}

func TestTrafficInfluenceRefusesGBROverlayWithoutAuthorizingExtraResources(t *testing.T) {
	policy := trafficInfluencePolicy()
	service := util.CreatePccRule(2, 128, []models.Pcf_SMPolCtrl_FlowInformation{{
		FlowDescription: "permit out ip from 10.100.1.0/24 to assigned",
	}}, "")
	service.RefQosData = []string{"gbr"}
	policy.PolicyDecision.PccRules[service.PccRuleId] = service
	policy.PolicyDecision.QosDecs = map[string]*models.Pcf_SMPolCtrl_QosData{
		"gbr": {QosId: "gbr", Var5qi: 1, GbrUl: "1 Mbps", GbrDl: "1 Mbps"},
	}
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", trafficInfluenceData("mec"), nil); err == nil {
		t.Fatal("GBR needs explicit resource sharing handling, not duplicated authorization")
	}
	if len(policy.PolicyDecision.PccRules) != 2 || len(policy.InfluenceDataToPccRule) != 0 {
		t.Fatal("refused GBR overlay modified the authorized service policy")
	}
}

func TestTrafficInfluenceIPv6AssignedIntersection(t *testing.T) {
	policy := trafficInfluencePolicy()
	policy.PolicyContext.Ipv6AddressPrefix = "2001:db8:60::/64"
	data := trafficInfluenceData("mec")
	data.TrafficFilters[0].FlowDescriptions = []string{
		"permit out ip from 2001:db8:100::/64 to 2001:db8:60::/48",
	}
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil); err != nil {
		t.Fatal(err)
	}
	id := policy.InfluenceDataToPccRule["ti"][0]
	filter, err := flowdesc.Decode(policy.PolicyDecision.PccRules[id].FlowInfos[0].FlowDescription)
	if err != nil {
		t.Fatal(err)
	}
	if filter.Dst != "assigned" || filter.Src != "2001:db8:100::/64" {
		t.Fatalf("TI intersection lost IPv6 UE/address restrictions: %+v", filter)
	}
}

func TestTrafficInfluenceIntersectsBothFiltersPortsAndAddresses(t *testing.T) {
	policy := trafficInfluencePolicy()
	service := util.CreatePccRule(2, 128, []models.Pcf_SMPolCtrl_FlowInformation{{
		FlowDescription: "permit out 6 from 10.100.0.0/16 80-100 to assigned 1000-2000",
	}}, "")
	service.RefQosData = []string{"service"}
	policy.PolicyDecision.PccRules[service.PccRuleId] = service
	policy.PolicyDecision.QosDecs = map[string]*models.Pcf_SMPolCtrl_QosData{
		"service": {QosId: "service", Var5qi: 8, Arp: &models.Arp{PriorityLevel: 8}},
	}
	data := trafficInfluenceData("mec")
	data.TrafficFilters[0].FlowDescriptions = []string{
		"permit out 6 from 10.100.1.0/24 90-110 to 10.60.0.0/16 1500-2500",
	}
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil); err != nil {
		t.Fatal(err)
	}
	for id, source := range policy.InfluencePccRuleSources {
		if source != service.PccRuleId {
			continue
		}
		got := policy.PolicyDecision.PccRules[id].FlowInfos[0].FlowDescription
		want := "permit out 6 from 10.100.1.0/24 90-100 to assigned 1500-2000"
		if got != want {
			t.Fatalf("intersection filter = %s, want %s", got, want)
		}
		return
	}
	t.Fatal("no TI rule retained the authorized service QoS")
}
