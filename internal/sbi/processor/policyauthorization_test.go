package processor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
)

type modAppSessionTestPCF struct {
	PCF
	ctx *pcf_context.PCFContext
}

func (a *modAppSessionTestPCF) Context() *pcf_context.PCFContext { return a.ctx }

func TestTransferMedCompRmToMedComp(t *testing.T) {
	t.Run("nil media component", func(t *testing.T) {
		if got := transferMedCompRmToMedComp(nil); got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("nil media subcomponent is skipped", func(t *testing.T) {
		medCompRm := &models.Pcf_PolAuth_MediaComponentRm{
			MedCompN: 1,
			MedSubComps: map[string]*models.Pcf_PolAuth_MediaSubComponentRm{
				"1": nil,
				"2": {FNum: 2},
			},
		}
		got := transferMedCompRmToMedComp(medCompRm)
		if got == nil {
			t.Fatal("expected non-nil media component")
		}
		if len(got.MedSubComps) != 1 {
			t.Fatalf("expected 1 media subcomponent, got %d", len(got.MedSubComps))
		}
		if _, ok := got.MedSubComps["2"]; !ok {
			t.Errorf("expected media subcomponent \"2\" to be kept")
		}
	})

	t.Run("non-nil media component is converted", func(t *testing.T) {
		got := transferMedCompRmToMedComp(&models.Pcf_PolAuth_MediaComponentRm{MedCompN: 1, AfAppId: "app"})
		if got == nil || got.MedCompN != 1 || got.AfAppId != "app" {
			t.Errorf("unexpected conversion result: %+v", got)
		}
	})
}

// A null media component in a PATCH removes it (JSON Merge Patch, RFC 7396)
// instead of panicking (issue #1236).
func TestHandleModAppSessionContextNullMediaComponent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var appSessCtx models.Pcf_PolAuth_AppSessionContext
	ascJSON := `{"ascReqData":{"medComponents":{"1":{"medCompN":1,"afAppId":"app-test"}}},` +
		`"ascRespData":{"suppFeat":"01"}}`
	if err := json.Unmarshal([]byte(ascJSON), &appSessCtx); err != nil {
		t.Fatal(err)
	}

	var update models.Pcf_PolAuth_AppSessionContextUpdateData
	if err := json.Unmarshal([]byte(`{"medComponents":{"1":null}}`), &update); err != nil {
		t.Fatal(err)
	}
	if v, ok := update.MedComponents["1"]; !ok || v != nil {
		t.Fatal("expected a null media component entry in the update data")
	}

	const appSessionID = "imsi-208930000000001-1"
	appSession := &pcf_context.AppSessionData{
		AppSessionId:      appSessionID,
		AppSessionContext: &appSessCtx,
		RelatedPccRuleIds: map[string]string{"1": "pccRule-1"},
		SmPolicyData: &pcf_context.UeSmPolicyData{
			PolicyContext:  &models.Pcf_SMPolCtrl_SmPolicyContextData{PduSessionId: 1},
			PolicyDecision: &models.Pcf_SMPolCtrl_SmPolicyDecision{SuppFeat: "01"},
		},
	}
	pcfCtx := &pcf_context.PCFContext{}
	pcfCtx.AppSessionPool.Store(appSessionID, appSession)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	p := &Processor{PCF: &modAppSessionTestPCF{ctx: pcfCtx}}
	p.HandleModAppSessionContext(c, appSessionID, update)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
	if _, ok := appSession.AppSessionContext.AscReqData.MedComponents["1"]; ok {
		t.Error("expected media component \"1\" to be removed")
	}
	if _, ok := appSession.RelatedPccRuleIds["1"]; ok {
		t.Error("expected the related PCC rule id of media component \"1\" to be removed")
	}
}
