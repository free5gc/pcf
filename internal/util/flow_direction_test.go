package util_test

import (
	"testing"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pcf/internal/util"
)

func TestConfiguredFlowDirection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   interface{}
		want    models.Pcf_SMPolCtrl_FlowDirectionRm
		invalid bool
	}{
		{name: "old record", want: models.Pcf_SMPolCtrl_FlowDirectionRm_BIDIRECTIONAL},
		{name: "empty field", value: "", want: models.Pcf_SMPolCtrl_FlowDirectionRm_BIDIRECTIONAL},
		{name: "downlink", value: "DOWNLINK", want: models.Pcf_SMPolCtrl_FlowDirectionRm_DOWNLINK},
		{name: "uplink", value: "UPLINK", want: models.Pcf_SMPolCtrl_FlowDirectionRm_UPLINK},
		{name: "both", value: "BIDIRECTIONAL", want: models.Pcf_SMPolCtrl_FlowDirectionRm_BIDIRECTIONAL},
		{name: "unsupported", value: "UNSPECIFIED", invalid: true},
		{name: "typo", value: "BOTH", invalid: true},
		{name: "non-string", value: 1, invalid: true},
		{name: "object", value: map[string]string{"value": "UPLINK"}, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := util.ConfiguredFlowDirection(tc.value)
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid direction accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
