package util

import (
	"strings"
	"testing"

	"github.com/free5gc/openapi/models"
)

func TestGetSMPolicyDnnDataSnssaiIdentity(t *testing.T) {
	for _, tc := range []struct {
		key, sd string
		sst     int32
	}{
		{"1-010203", "010203", 1}, {"01010203", "010203", 1},
		{"10-010203", "010203", 10}, {"10010203", "010203", 10}, {"0a010203", "010203", 10},
		{"222-00007b", "00007B", 222}, {"22200007b", "00007b", 222}, {"de00007b", "00007b", 222},
		{"1", "", 1}, {"01", "", 1},
	} {
		t.Run(tc.key, func(t *testing.T) {
			requested := &models.Snssai{Sst: tc.sst, Sd: strings.ToLower(tc.sd)}
			data := models.Udr_DR_SmPolicyData{SmPolicySnssaiData: map[string]models.Udr_DR_SmPolicySnssaiData{
				tc.key: {Snssai: &models.Snssai{Sst: tc.sst, Sd: tc.sd}, SmPolicyDnnData: map[string]models.Udr_DR_SmPolicyDnnData{
					"default": {Dnn: "default", GbrDl: "100 Mbps", GbrUl: "50 Mbps"},
				}},
			}}
			got := GetSMPolicyDnnData(data, requested, "default")
			if got == nil || got.GbrDl != "100 Mbps" || got.GbrUl != "50 Mbps" {
				t.Fatalf("lost subscription: %+v", got)
			}
			if GetSMPolicyDnnData(data, requested, "other") != nil {
				t.Fatal("matched wrong DNN")
			}
			if GetSMPolicyDnnData(data, &models.Snssai{Sst: 99, Sd: tc.sd}, "default") != nil {
				t.Fatal("matched wrong SST")
			}
			if GetSMPolicyDnnData(data, &models.Snssai{Sst: tc.sst, Sd: "abcdef"}, "default") != nil {
				t.Fatal("matched wrong SD")
			}
			data.SmPolicySnssaiData["duplicate"] = data.SmPolicySnssaiData[tc.key]
			if GetSMPolicyDnnData(data, requested, "default") != nil {
				t.Fatal("selected ambiguous policy")
			}
		})
	}
	data := models.Udr_DR_SmPolicyData{SmPolicySnssaiData: map[string]models.Udr_DR_SmPolicySnssaiData{
		"01010203": {SmPolicyDnnData: map[string]models.Udr_DR_SmPolicyDnnData{"default": {Dnn: "default"}}},
	}}
	if GetSMPolicyDnnData(data, &models.Snssai{Sst: 1, Sd: "010203"}, "default") != nil {
		t.Fatal("accepted missing snssai")
	}
}
