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

func TestTrafficInfluenceWithoutOverlapPreservesExistingPolicy(t *testing.T) {
	for _, charging := range []*models.Pcf_SMPolCtrl_ChargingData{
		nil, {ChgId: "offline", Offline: true}, {ChgId: "online", Online: true},
	} {
		policy := tiPolicy()
		service := tiService(policy, "permit out ip from 1.1.1.1/32 to assigned")
		// The CI configuration includes GBR fields with 5QI 8. A disjoint TI
		// must not inspect or modify that unrelated service's QoS.
		policy.PolicyDecision.QosDecs["service"].GbrUl = "108 Mbps"
		before := tiJSON(t, service)
		decision, err := util.SetTrafficInfluencePolicy(policy, "ti", tiData("mec", "10.100.0.0/16"), charging)
		if err != nil {
			t.Fatal(err)
		}
		wire := tiJSON(t, &models.Pcf_SMPolCtrl_SmPolicyNotification{SmPolicyDecision: decision})
		var notification models.Pcf_SMPolCtrl_SmPolicyNotification
		if err := json.Unmarshal([]byte(wire), &notification); err != nil {
			t.Fatal(err)
		}
		got := notification.SmPolicyDecision
		if got.PccRules[service.PccRuleId] != nil ||
			tiJSON(t, policy.PolicyDecision.PccRules[service.PccRuleId]) != before {
			t.Fatal("disjoint TI changed the existing service rule")
		}
		ids := tiGeneratedIDs(policy, "ti")
		if len(ids) != 1 {
			t.Fatalf("disjoint TI generated %d rules, want one", len(ids))
		}
		rule := got.PccRules[ids[0]]
		if len(rule.RefQosData) != 1 || !got.QosDecs[rule.RefQosData[0]].DefQosFlowIndication {
			t.Fatal("disjoint TI has no explicit default-flow QoS reference")
		}
		if rule.Precedence <= service.Precedence || rule.Precedence >= 255 {
			t.Fatal("default TI must follow existing service rules and precede the default rule")
		}
		if tiRoute(got, rule) != "mec" {
			t.Fatal("TI route was not serialized")
		}
		if charging != nil && (len(rule.RefChgData) != 1 ||
			!reflect.DeepEqual(got.ChgDecs[rule.RefChgData[0]], charging)) {
			t.Fatal("default TI charging data was not preserved")
		}
	}
}

func TestTrafficInfluenceFullCoverageUpdatesOriginalRule(t *testing.T) {
	for _, gbr := range []bool{false, true} {
		policy := tiPolicy()
		service := tiService(policy, "permit out ip from 10.100.1.0/24 to assigned")
		if gbr {
			policy.PolicyDecision.QosDecs["service"].Var5qi = 1
			policy.PolicyDecision.QosDecs["service"].GbrUl = "1 Mbps"
		}
		policy.PolicyDecision.TraffContDecs["original"].UpPathChgEvent = &models.Pcf_SMPolCtrl_UpPathChgEvent{
			NotificationUri: "http://original-policy/up-path",
		}
		beforeQoS := tiJSON(t, policy.PolicyDecision.QosDecs)
		beforeRule := *service
		decision, err := util.SetTrafficInfluencePolicy(policy, "ti", tiData("mec", "10.100.1.0/24"), nil)
		if err != nil {
			t.Fatal(err)
		}
		got := decision.PccRules[service.PccRuleId]
		if len(decision.PccRules) != 1 || len(tiGeneratedIDs(policy, "ti")) != 0 {
			t.Fatal("full coverage must modify the service without generating a parallel PCC rule")
		}
		if got.Precedence != beforeRule.Precedence || !reflect.DeepEqual(got.FlowInfos, beforeRule.FlowInfos) ||
			!reflect.DeepEqual(got.RefQosData, beforeRule.RefQosData) ||
			!reflect.DeepEqual(got.RefChgData, beforeRule.RefChgData) {
			t.Fatal("routing update changed the original service's filters, QoS, charging or priority")
		}
		if tiJSON(t, policy.PolicyDecision.QosDecs) != beforeQoS ||
			tiRoute(decision, got) != "mec" {
			t.Fatal("full coverage must change routing while preserving QoS data")
		}
		if decision.TraffContDecs[got.RefTcData[0]].FlowStatus != models.Pcf_PolAuth_FlowStatus_ENABLED ||
			decision.TraffContDecs[got.RefTcData[0]].UpPathChgEvent == nil {
			t.Fatal("routing update dropped the source traffic-control attributes")
		}
		if _, err := util.RemoveTrafficInfluencePolicy(policy, "ti"); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(policy.PolicyDecision.PccRules[service.PccRuleId], &beforeRule) ||
			len(policy.PolicyDecision.TraffContDecs) != 1 {
			t.Fatal("removing full-coverage TI did not restore the original routing references")
		}
	}
}

func TestTrafficInfluenceWiderCoverageDoesNotRenumberExistingRules(t *testing.T) {
	policy := tiPolicy()
	service := tiService(policy, "permit out ip from 10.100.1.0/24 to assigned")
	// Both services share the original TC data; only the affected rule may change.
	other := util.CreatePccRule(3, 200, []models.Pcf_SMPolCtrl_FlowInformation{{
		FlowDescription: "permit out ip from 1.1.1.1/32 to assigned",
	}}, "")
	other.RefQosData, other.RefTcData = []string{"service"}, []string{"original"}
	policy.PolicyDecision.PccRules[other.PccRuleId] = other
	policy.PccRuleIdGenerator = 4
	beforeOther := tiJSON(t, other)
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", tiData("mec", "10.100.0.0/16"), nil); err != nil {
		t.Fatal(err)
	}
	decision := policy.PolicyDecision
	if decision.PccRules[service.PccRuleId].Precedence != 128 ||
		tiJSON(t, decision.PccRules[other.PccRuleId]) != beforeOther || decision.PccRules["PccRuleId-1"].Precedence != 255 {
		t.Fatal("wider TI changed an existing precedence or an unrelated rule")
	}
	if tiRoute(decision, decision.PccRules[service.PccRuleId]) != "mec" ||
		tiRoute(decision, decision.PccRules[other.PccRuleId]) != "original" {
		t.Fatal("full-coverage route modification leaked through shared TC data")
	}
	for _, packet := range []struct{ source, qos string }{
		{"10.100.1.2", "service"}, {"10.100.2.2", "default"},
	} {
		rule := tiMatchingRule(t, decision, packet.source, 6, 80)
		if tiRoute(decision, rule) != "mec" {
			t.Fatal("wider TI did not route all requested traffic to MEC")
		}
		qos := decision.QosDecs[rule.RefQosData[0]]
		if packet.qos == "service" && qos.QosId != "service" || packet.qos == "default" && !qos.DefQosFlowIndication {
			t.Fatal("wider TI changed the selected traffic's QoS")
		}
	}
}

func TestTrafficInfluencePartialCoverageOnlyAddsNarrowRule(t *testing.T) {
	policy := tiPolicy()
	service := tiService(policy, "permit out ip from 10.100.0.0/16 to assigned")
	before := tiJSON(t, service)
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", tiData("mec", "10.100.1.0/24"), nil); err != nil {
		t.Fatal(err)
	}
	if tiJSON(t, policy.PolicyDecision.PccRules[service.PccRuleId]) != before {
		t.Fatal("partial TI modified the original service rule")
	}
	ids := tiGeneratedIDs(policy, "ti")
	if len(ids) != 1 {
		t.Fatal("TI wholly inside a dedicated service needs only one narrow rule")
	}
	narrow := policy.PolicyDecision.PccRules[ids[0]]
	if !reflect.DeepEqual(narrow.RefQosData, service.RefQosData) || narrow.Precedence >= 128 {
		t.Fatal("partial TI must retain authorized QoS and precede its source rule")
	}
	inside := tiMatchingRule(t, policy.PolicyDecision, "10.100.1.2", 6, 80)
	outside := tiMatchingRule(t, policy.PolicyDecision, "10.100.2.2", 6, 80)
	if tiRoute(policy.PolicyDecision, inside) != "mec" || tiRoute(policy.PolicyDecision, outside) != "original" {
		t.Fatal("partial TI changed routing outside its requested filter")
	}
	deleted, err := util.RemoveTrafficInfluencePolicy(policy, "ti")
	if err != nil {
		t.Fatal(err)
	}
	if value, exists := deleted.PccRules[ids[0]]; !exists || value != nil || len(policy.PolicyDecision.QosDecs) != 1 {
		t.Fatal("partial TI removal lost its deletion marker or removed shared service QoS")
	}
}

func TestTrafficInfluenceCoverageUsesUnionOfRequestFilters(t *testing.T) {
	for _, descriptions := range [][]string{
		{"permit out 6 from 10.100.1.0/25 80-90 to assigned", "permit out 6 from 10.100.1.128/25 80-90 to assigned"},
		{"permit out 6 from 10.100.1.0/24 80-85 to assigned", "permit out 6 from 10.100.1.0/24 86-90 to assigned"},
	} {
		policy := tiPolicy()
		service := tiService(policy, "permit out 6 from 10.100.1.0/24 80-90 to assigned")
		data := tiData("mec", "10.100.1.0/24")
		data.TrafficFilters[0].FlowDescriptions = descriptions
		if _, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil); err != nil {
			t.Fatal(err)
		}
		if len(tiGeneratedIDs(policy, "ti")) != 0 ||
			tiRoute(policy.PolicyDecision, policy.PolicyDecision.PccRules[service.PccRuleId]) != "mec" {
			t.Fatal("filters collectively covering a service must update that service in place")
		}
	}
}

func TestTrafficInfluenceUpdateChangesCoverageAndRestoresRouting(t *testing.T) {
	policy := tiPolicy()
	service := tiService(policy, "permit out ip from 10.100.0.0/16 to assigned")
	before := tiJSON(t, policy.PolicyDecision)
	for _, source := range []string{"10.100.0.0/16", "10.100.1.0/24", "10.200.0.0/16"} {
		if _, err := util.SetTrafficInfluencePolicy(policy, "ti", tiData("mec", source), nil); err != nil {
			t.Fatal(err)
		}
		if policy.PolicyDecision.PccRules[service.PccRuleId].Precedence != 128 {
			t.Fatal("changing TI coverage renumbered the source service")
		}
	}
	if tiRoute(policy.PolicyDecision, policy.PolicyDecision.PccRules[service.PccRuleId]) != "original" {
		t.Fatal("changing TI to disjoint traffic did not restore the service route")
	}
	if _, err := util.RemoveTrafficInfluencePolicy(policy, "ti"); err != nil {
		t.Fatal(err)
	}
	if tiJSON(t, policy.PolicyDecision) != before {
		t.Fatal("TI lifecycle left policy data, filters or priorities changed")
	}
}

func TestTrafficInfluenceRequestsRestoreCorrectRouteWhenDeletedOutOfOrder(t *testing.T) {
	for _, firstFull := range []bool{false, true} {
		policy := tiPolicy()
		service := tiService(policy, "permit out ip from 10.100.0.0/16 to assigned")
		first, second := "10.100.1.0/24", "10.100.0.0/16"
		if firstFull {
			first, second = second, first
		}
		for _, request := range []struct{ id, source string }{{"first", first}, {"second", second}} {
			data := tiData(request.id, request.source)
			if _, err := util.SetTrafficInfluencePolicy(policy, request.id, data, nil); err != nil {
				t.Fatal(err)
			}
		}
		winner := tiMatchingRule(t, policy.PolicyDecision, "10.100.1.2", 6, 80)
		if tiRoute(policy.PolicyDecision, winner) != "first" {
			t.Fatal("overlapping requests did not retain first-active-request priority")
		}
		if _, err := util.RemoveTrafficInfluencePolicy(policy, "first"); err != nil {
			t.Fatal(err)
		}
		winner = tiMatchingRule(t, policy.PolicyDecision, "10.100.1.2", 6, 80)
		if tiRoute(policy.PolicyDecision, winner) != "second" {
			t.Fatal("deleting the first request did not expose the remaining request")
		}
		if _, err := util.RemoveTrafficInfluencePolicy(policy, "second"); err != nil {
			t.Fatal(err)
		}
		if tiRoute(policy.PolicyDecision, policy.PolicyDecision.PccRules[service.PccRuleId]) != "original" {
			t.Fatal("deleting all requests did not restore original service routing")
		}
	}
}

func TestTrafficInfluenceFailureDoesNotChangePolicy(t *testing.T) {
	for _, scenario := range []string{"no precedence slot", "partial GBR", "invalid filter"} {
		policy := tiPolicy()
		service := tiService(policy, "permit out ip from 10.100.0.0/16 to assigned")
		data := tiData("mec", "10.100.1.0/24")
		switch scenario {
		case "no precedence slot":
			service.Precedence = 1
		case "partial GBR":
			policy.PolicyDecision.QosDecs["service"].GbrUl = "1 Mbps"
		case "invalid filter":
			data.TrafficFilters[0].FlowDescriptions[0] += " established"
		}
		before, generator := tiJSON(t, policy.PolicyDecision), policy.PccRuleIdGenerator
		if _, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil); err == nil {
			t.Fatalf("%s unexpectedly succeeded", scenario)
		}
		if tiJSON(t, policy.PolicyDecision) != before || policy.TrafficInfluence != nil ||
			policy.PccRuleIdGenerator != generator {
			t.Fatalf("%s left a partial policy update", scenario)
		}
	}
}

func TestTrafficInfluenceSourceRemovalDoesNotResurrectRules(t *testing.T) {
	for _, full := range []bool{false, true} {
		policy := tiPolicy()
		service := tiService(policy, "permit out ip from 10.100.0.0/16 to assigned")
		source := "10.100.1.0/24"
		if full {
			source = "10.100.0.0/16"
		}
		if _, err := util.SetTrafficInfluencePolicy(policy, "ti", tiData("mec", source), nil); err != nil {
			t.Fatal(err)
		}
		if err := policy.RemovePccRule(service.PccRuleId, &models.Pcf_SMPolCtrl_SmPolicyDecision{}); err != nil {
			t.Fatal(err)
		}
		if _, err := util.RemoveTrafficInfluencePolicy(policy, "ti"); err != nil {
			t.Fatal(err)
		}
		if len(policy.PolicyDecision.PccRules) != 1 || len(policy.PolicyDecision.QosDecs) != 0 ||
			len(policy.PolicyDecision.TraffContDecs) != 0 {
			t.Fatal("removing TI resurrected deleted service data or left orphaned routing data")
		}
	}
}

func TestTrafficInfluenceIPv6Coverage(t *testing.T) {
	policy := tiPolicy()
	policy.PolicyContext.Ipv6AddressPrefix = "2001:db8:60::/64"
	service := tiService(policy, "permit out ip from 2001:db8:100::/64 to assigned")
	data := tiData("mec", "2001:db8:100::/64")
	data.TrafficFilters[0].FlowDescriptions[0] = "permit out ip from 2001:db8:100::/64 to 2001:db8:60::/48"
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil); err != nil {
		t.Fatal(err)
	}
	if tiRoute(policy.PolicyDecision, policy.PolicyDecision.PccRules[service.PccRuleId]) != "mec" ||
		len(tiGeneratedIDs(policy, "ti")) != 0 {
		t.Fatal("IPv6 full coverage did not update the original service")
	}
}

func tiPolicy() *pcf_context.UeSmPolicyData {
	base := util.CreateDefaultPccRules(1)
	return &pcf_context.UeSmPolicyData{
		PolicyContext: &models.Pcf_SMPolCtrl_SmPolicyContextData{Ipv4Address: "10.60.0.1"},
		PolicyDecision: &models.Pcf_SMPolCtrl_SmPolicyDecision{
			PccRules: map[string]*models.Pcf_SMPolCtrl_PccRule{base.PccRuleId: base},
		}, PccRuleIdGenerator: 3,
	}
}

func tiService(policy *pcf_context.UeSmPolicyData, description string) *models.Pcf_SMPolCtrl_PccRule {
	service := util.CreatePccRule(2, 128, []models.Pcf_SMPolCtrl_FlowInformation{{FlowDescription: description}}, "")
	service.RefQosData, service.RefTcData = []string{"service"}, []string{"original"}
	service.RefChgData = []string{"charge"}
	policy.PolicyDecision.PccRules[service.PccRuleId] = service
	policy.PolicyDecision.QosDecs = map[string]*models.Pcf_SMPolCtrl_QosData{
		"service": {QosId: "service", Var5qi: 8, Arp: &models.Arp{PriorityLevel: 8}},
	}
	policy.PolicyDecision.TraffContDecs = map[string]*models.Pcf_SMPolCtrl_TrafficControlData{
		"original": {
			TcId: "original", FlowStatus: models.Pcf_PolAuth_FlowStatus_ENABLED,
			RouteToLocs: []models.RouteToLocation{{Dnai: "original"}},
		},
	}
	policy.PolicyDecision.ChgDecs = map[string]*models.Pcf_SMPolCtrl_ChargingData{
		"charge": {ChgId: "charge", Offline: true},
	}
	return service
}

func tiData(dnai, source string) models.Udr_DR_TrafficInfluData {
	return models.Udr_DR_TrafficInfluData{
		Snssai: &models.Snssai{Sst: 1}, Dnn: "internet",
		TrafficFilters: []models.Nef_FlowInfo{{
			FlowId:           1,
			FlowDescriptions: []string{"permit out ip from " + source + " to assigned"},
		}},
		TrafficRoutes: []models.RouteToLocation{{Dnai: dnai}},
	}
}

func tiGeneratedIDs(policy *pcf_context.UeSmPolicyData, influenceID string) []string {
	var ids []string
	if policy.TrafficInfluence != nil {
		for _, request := range policy.TrafficInfluence.Requests {
			if request.ID == influenceID {
				for _, id := range request.RuleIDs {
					ids = append(ids, id)
				}
			}
		}
	}
	sort.Strings(ids)
	return ids
}

func tiRoute(decision *models.Pcf_SMPolCtrl_SmPolicyDecision, rule *models.Pcf_SMPolCtrl_PccRule) string {
	if len(rule.RefTcData) == 0 {
		return ""
	}
	data := decision.TraffContDecs[rule.RefTcData[0]]
	if data == nil || len(data.RouteToLocs) == 0 {
		return ""
	}
	return data.RouteToLocs[0].Dnai
}

func tiJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func tiMatchingRule(t *testing.T, decision *models.Pcf_SMPolCtrl_SmPolicyDecision,
	source string, protocol uint8, port uint16,
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
			filter, err := flowdesc.Decode(info.FlowDescription)
			if err != nil {
				t.Fatal(err)
			}
			if filter.Proto != flowdesc.ProtocolNumberAny && filter.Proto != protocol {
				continue
			}
			if filter.Src != "any" {
				prefix, err := netip.ParsePrefix(filter.Src)
				if err != nil {
					if single, err := netip.ParseAddr(filter.Src); err == nil {
						prefix = netip.PrefixFrom(single, single.BitLen())
					}
				}
				if !prefix.IsValid() || !prefix.Contains(address) {
					continue
				}
			}
			portMatches := len(filter.SrcPorts) == 0
			for _, ports := range filter.SrcPorts {
				portMatches = portMatches || port >= ports.Start && port <= ports.End
			}
			if portMatches {
				return rule
			}
		}
	}
	t.Fatal("no rule matches the sample packet")
	return nil
}

func TestTrafficInfluenceReapplyRetainsUpdatedServiceAuthorization(t *testing.T) {
	policy := tiPolicy()
	service := tiService(policy, "permit out ip from 10.100.0.0/16 to assigned")
	data := tiData("mec", "10.100.0.0/16")
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil); err != nil {
		t.Fatal(err)
	}
	// A later service-policy update changes QoS and its original routing reference.
	policy.PolicyDecision.QosDecs["service"].Var5qi = 7
	policy.PolicyDecision.TraffContDecs["new-original"] = &models.Pcf_SMPolCtrl_TrafficControlData{
		TcId: "new-original", RouteToLocs: []models.RouteToLocation{{Dnai: "new-original"}},
	}
	policy.PolicyDecision.PccRules[service.PccRuleId].RefTcData = []string{"new-original"}
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := util.RemoveTrafficInfluencePolicy(policy, "ti"); err != nil {
		t.Fatal(err)
	}
	if policy.PolicyDecision.QosDecs["service"].Var5qi != 7 ||
		tiRoute(policy.PolicyDecision, policy.PolicyDecision.PccRules[service.PccRuleId]) != "new-original" {
		t.Fatal("TI removal restored stale service QoS or routing")
	}
}

func TestTrafficInfluencePartialRulePreservesHigherPriorityService(t *testing.T) {
	policy := tiPolicy()
	service := tiService(policy, "permit out ip from 10.100.0.0/16 to assigned")
	higher := util.CreatePccRule(3, 23, []models.Pcf_SMPolCtrl_FlowInformation{{
		FlowDescription: "permit out ip from 10.100.1.0/25 to assigned",
	}}, "")
	higher.RefQosData, higher.RefTcData = []string{"higher"}, []string{"original"}
	policy.PolicyDecision.PccRules[higher.PccRuleId] = higher
	policy.PolicyDecision.QosDecs["higher"] = &models.Pcf_SMPolCtrl_QosData{QosId: "higher", Var5qi: 7}
	policy.PccRuleIdGenerator = 4
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", tiData("mec", "10.100.1.0/24"), nil); err != nil {
		t.Fatal(err)
	}
	rule := tiMatchingRule(t, policy.PolicyDecision, "10.100.1.2", 6, 80)
	if rule.PccRuleId != higher.PccRuleId || rule.RefQosData[0] != "higher" ||
		tiRoute(policy.PolicyDecision, rule) != "mec" {
		t.Fatal("the broad service's partial TI rule superseded an existing higher-priority service")
	}
	ids := tiGeneratedIDs(policy, "ti")
	if len(ids) != 1 {
		t.Fatal("only the broad service needs a partial-coverage rule")
	}
	partial := policy.PolicyDecision.PccRules[ids[0]]
	if partial.Precedence <= 23 || partial.Precedence >= 128 ||
		policy.PolicyDecision.PccRules[service.PccRuleId].Precedence != 128 {
		t.Fatal("partial TI did not fit its priority between existing service rules")
	}
}

func TestTrafficInfluenceRetainsOriginalSharedRouteUntilWithdrawal(t *testing.T) {
	policy := tiPolicy()
	service := tiService(policy, "permit out ip from 10.100.0.0/16 to assigned")
	other := util.CreatePccRule(3, 200, []models.Pcf_SMPolCtrl_FlowInformation{{
		FlowDescription: "permit out ip from 1.1.1.1/32 to assigned",
	}}, "")
	other.RefQosData, other.RefTcData = []string{"service"}, []string{"original"}
	policy.PolicyDecision.PccRules[other.PccRuleId] = other
	policy.PccRuleIdGenerator = 4
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", tiData("mec", "10.100.0.0/16"), nil); err != nil {
		t.Fatal(err)
	}
	if err := policy.RemovePccRule(other.PccRuleId, nil); err != nil {
		t.Fatal(err)
	}
	if policy.PolicyDecision.TraffContDecs["original"] == nil {
		t.Fatal("removing a rule deleted TC data still needed to withdraw another rule's TI")
	}
	if _, err := util.RemoveTrafficInfluencePolicy(policy, "ti"); err != nil {
		t.Fatal(err)
	}
	if tiRoute(policy.PolicyDecision, policy.PolicyDecision.PccRules[service.PccRuleId]) != "original" {
		t.Fatal("TI withdrawal restored a dangling routing reference")
	}
}

func TestTrafficInfluenceFiltersCoverUnionOfServices(t *testing.T) {
	policy := tiPolicy()
	tiService(policy, "permit out ip from 10.100.1.0/25 to assigned")
	other := util.CreatePccRule(3, 200, []models.Pcf_SMPolCtrl_FlowInformation{{
		FlowDescription: "permit out ip from 10.100.1.128/25 to assigned",
	}}, "")
	other.RefQosData, other.RefTcData = []string{"other"}, []string{"original"}
	policy.PolicyDecision.PccRules[other.PccRuleId] = other
	policy.PolicyDecision.QosDecs["other"] = &models.Pcf_SMPolCtrl_QosData{QosId: "other", Var5qi: 7}
	policy.PccRuleIdGenerator = 4
	data := tiData("mec", "10.100.1.0/24")
	needsDefault, err := util.TrafficInfluenceNeedsDefault(policy, data)
	if err != nil || needsDefault {
		t.Fatalf("TI covered by the union of services should not need default QoS: %v", err)
	}
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil); err != nil {
		t.Fatal(err)
	}
	if len(tiGeneratedIDs(policy, "ti")) != 0 {
		t.Fatal("fully covered service union generated an unnecessary default rule")
	}
	for source, want := range map[string]string{"10.100.1.2": "service", "10.100.1.200": "other"} {
		rule := tiMatchingRule(t, policy.PolicyDecision, source, 6, 80)
		if rule.RefQosData[0] != want || tiRoute(policy.PolicyDecision, rule) != "mec" {
			t.Fatal("TI changed service QoS while modifying the covered services' routing")
		}
	}
}

func TestTrafficInfluenceCoverageDoesNotFillFilterGaps(t *testing.T) {
	policy := tiPolicy()
	service := tiService(policy, "permit out ip from 10.100.1.0/24 to assigned")
	data := tiData("mec", "10.100.1.0/24")
	data.TrafficFilters[0].FlowDescriptions = []string{
		"permit out ip from 10.100.1.0/25 to assigned",
		"permit out ip from 10.100.1.128/26 to assigned",
	}
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil); err != nil {
		t.Fatal(err)
	}
	outside := tiMatchingRule(t, policy.PolicyDecision, "10.100.1.200", 6, 80)
	if outside.PccRuleId != service.PccRuleId || tiRoute(policy.PolicyDecision, outside) != "original" {
		t.Fatal("coverage check incorrectly treated gaps between TI filters as covered")
	}
}

func TestTrafficInfluenceRejectsProtocolWildcardAlias(t *testing.T) {
	policy := tiPolicy()
	data := tiData("mec", "10.100.1.0/24")
	// flowdesc reserves numeric protocol 252 to represent "ip" internally.
	data.TrafficFilters[0].FlowDescriptions[0] = "permit out 252 from 10.100.1.0/24 to assigned"
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil); err == nil {
		t.Fatal("numeric protocol 252 was silently widened to all IP protocols")
	}
}

func TestTrafficInfluenceWithdrawalEncodesOriginallyImplicitRoute(t *testing.T) {
	policy := tiPolicy()
	service := tiService(policy, "permit out ip from 10.100.0.0/16 to assigned")
	service.RefTcData = nil // Existing subscription-generated PCC rules can omit TC data.
	policy.PolicyDecision.TraffContDecs = nil
	data := tiData("mec", "10.100.0.0/16")
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil); err != nil {
		t.Fatal(err)
	}
	data.TrafficRoutes[0].Dnai = "mec-2"
	update, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(update.PccRules) != 1 || len(update.TraffContDecs) != 1 {
		t.Fatal("route-only update sent unrelated PCC rules or unused backup TC data")
	}
	withdrawal, err := util.RemoveTrafficInfluencePolicy(policy, "ti")
	if err != nil {
		t.Fatal(err)
	}
	var decoded models.Pcf_SMPolCtrl_SmPolicyDecision
	if err := json.Unmarshal([]byte(tiJSON(t, withdrawal)), &decoded); err != nil {
		t.Fatal(err)
	}
	rule := decoded.PccRules[service.PccRuleId]
	if rule == nil || len(rule.RefTcData) != 1 || rule.RefTcData[0] == "TI-"+service.PccRuleId {
		t.Fatal("withdrawal omitted refTcData, which would leave the previous TI routing reference valid")
	}
	restored := decoded.TraffContDecs[rule.RefTcData[0]]
	if restored == nil || len(restored.RouteToLocs) != 0 || rule.Precedence != 128 || rule.RefQosData[0] != "service" {
		t.Fatal("withdrawal did not explicitly restore the implicit original route with the same QoS and priority")
	}
}

func TestTrafficInfluenceOwnsRequestDataAndSendsRouteOnlyChanges(t *testing.T) {
	policy := tiPolicy()
	service := tiService(policy, "permit out ip from 10.100.0.0/16 to assigned")
	data := tiData("mec", "10.100.0.0/16")
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil); err != nil {
		t.Fatal(err)
	}
	data.TrafficRoutes[0].Dnai = "mec-2"
	if tiRoute(policy.PolicyDecision, policy.PolicyDecision.PccRules[service.PccRuleId]) != "mec" ||
		policy.TrafficInfluence.Requests[0].Data.TrafficRoutes[0].Dnai != "mec" {
		t.Fatal("editing the caller's request changed cached routing before policy processing")
	}
	update, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	ref := policy.PolicyDecision.PccRules[service.PccRuleId].RefTcData[0]
	if len(update.PccRules) != 1 || len(update.TraffContDecs) != 1 ||
		update.TraffContDecs[ref].RouteToLocs[0].Dnai != "mec-2" {
		t.Fatal("same-filter route update must only change the affected PCC routing reference and TC data")
	}
	update.TraffContDecs[ref].RouteToLocs[0].Dnai = "modified-notification"
	if tiRoute(policy.PolicyDecision, policy.PolicyDecision.PccRules[service.PccRuleId]) != "mec-2" {
		t.Fatal("notification data aliases the cached policy")
	}
	unchanged, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(unchanged.PccRules) != 0 || len(unchanged.TraffContDecs) != 0 || len(unchanged.QosDecs) != 0 {
		t.Fatal("identical TI update sent unchanged policy data")
	}
}

func TestTrafficInfluenceUpdateClearsOldRoutingWithoutOmittedFieldSemantics(t *testing.T) {
	policy := tiPolicy()
	service := tiService(policy, "permit out ip from 10.100.0.0/16 to assigned")
	service.RefTcData = nil
	policy.PolicyDecision.TraffContDecs = nil
	data := tiData("mec", "10.100.0.0/16")
	if _, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil); err != nil {
		t.Fatal(err)
	}
	oldRef := policy.PolicyDecision.PccRules[service.PccRuleId].RefTcData[0]
	data.TrafficRoutes = nil
	update, err := util.SetTrafficInfluencePolicy(policy, "ti", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	var decoded models.Pcf_SMPolCtrl_SmPolicyDecision
	if err := json.Unmarshal([]byte(tiJSON(t, update)), &decoded); err != nil {
		t.Fatal(err)
	}
	rule := decoded.PccRules[service.PccRuleId]
	if rule == nil || len(rule.RefTcData) != 1 || rule.RefTcData[0] == oldRef {
		t.Fatal("clearing routing must use a different TC reference instead of omitting fields on old MEC data")
	}
	route := decoded.TraffContDecs[rule.RefTcData[0]]
	if route == nil || len(route.RouteToLocs) != 0 || rule.Precedence != 128 {
		t.Fatal("new TC data did not clear the previous MEC routing while retaining service priority")
	}
}
