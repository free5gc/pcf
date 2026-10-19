package context

import (
	tlsContext "context"
	tlsX509 "crypto/x509"
	tlsErrors "errors"
	tlsIO "io"
	tlsLog "log"
	tlsHTTP "net/http"
	tlsServer "net/http/httptest"
	tlsAtomic "sync/atomic"
	"testing"

	tlsOpenAPI "github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	tlsNFM "github.com/free5gc/openapi/nrf/NFMgmt"
	tlsFactory "github.com/free5gc/pcf/pkg/factory"
	tlsYAML "gopkg.in/yaml.v2"
)

func TestFindAMPolicy(t *testing.T) {
	plmn := &models.PlmnIdNid{Mcc: "208", Mnc: "93"}
	otherPlmn := &models.PlmnIdNid{Mcc: "001", Mnc: "01"}
	policy3GPP := &UeAMPolicyData{
		AccessType:  models.AccessType_3_GPP_ACCESS,
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
			accessType: models.AccessType_3_GPP_ACCESS,
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
			accessType: models.AccessType_3_GPP_ACCESS,
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
				"incomplete": {AccessType: models.AccessType_3_GPP_ACCESS},
			}},
			accessType: models.AccessType_3_GPP_ACCESS,
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

// Exercise parsed NF config through the same startup configuration API and
// generated NRF client used in production. No deployment files are modified.
func TestSBIConfigTLSVerification(t *testing.T) {
	t.Cleanup(func() {
		_ = tlsOpenAPI.ConfigureHTTP2Clients(tlsOpenAPI.TransportReadIdleTimeout, tlsOpenAPI.TransportPingTimeout, false)
	})
	var requests tlsAtomic.Int32
	server := tlsServer.NewUnstartedServer(tlsHTTP.HandlerFunc(func(w tlsHTTP.ResponseWriter, r *tlsHTTP.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = tlsIO.WriteString(w, `{}`)
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = tlsLog.New(tlsIO.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	for _, value := range []string{"", "false", "true"} {
		t.Run("verify="+value, func(t *testing.T) {
			data := "configuration:\n  sbi:\n    scheme: https\n"
			if value != "" {
				data += "    tls:\n      verify: " + value + "\n"
			}
			var cfg tlsFactory.Config
			if err := tlsYAML.Unmarshal([]byte(data), &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.GetTLSVerify() != (value == "true") {
				t.Fatal("verify parsing mismatch")
			}
			if err := tlsOpenAPI.ConfigureHTTP2Clients(cfg.GetReadIdleTimeout(), cfg.GetPingTimeout(), cfg.GetTLSVerify()); err != nil {
				t.Fatal(err)
			}
			apiCfg := tlsNFM.NewConfiguration()
			apiCfg.SetBasePath(server.URL)
			client := tlsNFM.NewAPIClient(apiCfg)
			req := &tlsNFM.GetNFInstanceRequest{}
			req.SetNfInstanceID("tls-test")
			before := requests.Load()
			_, err := client.NFInstanceIDDocumentApi.GetNFInstance(tlsContext.Background(), req)
			if value == "true" {
				var unknown tlsX509.UnknownAuthorityError
				if !tlsErrors.As(err, &unknown) {
					t.Fatalf("expected unknown authority, got %v", err)
				}
				if requests.Load() != before {
					t.Fatal("HTTP handler reached despite rejected certificate")
				}
			} else if err != nil {
				t.Fatal(err)
			} else if requests.Load() != before+1 {
				t.Fatal("request not received")
			}
		})
	}
}
