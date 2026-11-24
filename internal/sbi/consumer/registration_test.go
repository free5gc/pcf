package consumer

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/h2non/gock"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/pkg/factory"
)

func TestConfiguredDnnsReachNFProfile(t *testing.T) {
	base, err := os.ReadFile("../../../pkg/factory/testdata/pcfcfg.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, custom := range []bool{false, true} {
		name, input := "legacy default", string(base)
		want := []string{"free5gc", "internet"}
		if custom {
			name = "configured DNNs"
			want = []string{"corp", "ims"}
			input = strings.Replace(input, "  pcfName: PCF", "  dnnList: [corp, ims]\n  pcfName: PCF", 1)
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pcfcfg.yaml")
			if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := factory.ReadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx := &pcf_context.PCFContext{NfId: testNfId, NrfUri: testNrfUri}
			c, err := NewConsumer(&testPcf{cfg: cfg, ctx: ctx})
			if err != nil {
				t.Fatal(err)
			}
			profile, err := c.BuildNFInstance(ctx)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			var registered models.Nrf_NFMgmt_NFProfile
			if err = json.Unmarshal(wire, &registered); err != nil {
				t.Fatal(err)
			}
			if registered.PcfInfo == nil || !slices.Equal(registered.PcfInfo.DnnList, want) {
				t.Fatalf("registration PcfInfo = %+v, want DNNs %v", registered.PcfInfo, want)
			}
			profile.PcfInfo.DnnList[0] = "changed"
			again, err := c.BuildNFInstance(ctx)
			if err != nil || !slices.Equal(again.PcfInfo.DnnList, want) {
				t.Fatalf("profile aliases configuration: profile=%+v, error=%v", again, err)
			}
			openapi.InterceptInnerHttp2Client(t, false)
			t.Cleanup(gock.OffAll)
			gock.New(testNrfUri).Put(testNfIdPath).JSON(again).
				Reply(http.StatusCreated).JSON(nfProfileJSON(15, nil))
			if err = c.SendRegisterNFInstance(testCtx(t), false); err != nil {
				t.Fatal(err)
			}
			if !gock.IsDone() {
				t.Fatal("NRF did not receive the configured registration profile")
			}
		})
	}
}
