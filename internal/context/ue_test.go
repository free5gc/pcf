package context

import (
	"testing"

	"github.com/free5gc/openapi/models"
)

func TestFindAMPolicy(t *testing.T) {
	plmn := &models.PlmnIdNid{Mcc: "208", Mnc: "93"}
	otherPlmn := &models.PlmnIdNid{Mcc: "001", Mnc: "01"}
	policy3GPP := &UeAMPolicyData{
		AccessType:  models.AccessType__3_GPP_ACCESS,
		ServingPlmn: plmn,
	}
	tests := []struct {
		name       string
		ue         *UeContext
		accessType models.AccessType
		plmn       *models.PlmnIdNid
		want       *UeAMPolicyData
	}{
		{
			name: "exact match",
			ue: &UeContext{AMPolicyData: map[string]*UeAMPolicyData{
				"3gpp": policy3GPP,
			}},
			accessType: models.AccessType__3_GPP_ACCESS,
			plmn:       plmn,
			want:       policy3GPP,
		},
		{
			name: "missing access type does not panic",
			ue: &UeContext{AMPolicyData: map[string]*UeAMPolicyData{
				"3gpp": policy3GPP,
			}},
			plmn: plmn,
		},
		{
			name: "missing serving network does not panic",
			ue: &UeContext{AMPolicyData: map[string]*UeAMPolicyData{
				"3gpp": policy3GPP,
			}},
			accessType: models.AccessType__3_GPP_ACCESS,
		},
		{
			name: "nil policy entries do not panic",
			ue: &UeContext{AMPolicyData: map[string]*UeAMPolicyData{
				"nil": nil,
			}},
			plmn: plmn,
		},
		{
			name: "nil serving PLMN does not panic",
			ue: &UeContext{AMPolicyData: map[string]*UeAMPolicyData{
				"incomplete": {AccessType: models.AccessType__3_GPP_ACCESS},
			}},
			accessType: models.AccessType__3_GPP_ACCESS,
			plmn:       plmn,
		},
		{
			name: "different PLMN does not match",
			ue: &UeContext{AMPolicyData: map[string]*UeAMPolicyData{
				"3gpp": policy3GPP,
			}},
			plmn: otherPlmn,
		},
		{
			name: "nil UE does not panic",
			plmn: plmn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ue.FindAMPolicy(tt.accessType, tt.plmn)
			if got != tt.want {
				t.Fatalf("FindAMPolicy() = %p, want %p", got, tt.want)
			}
		})
	}
}
