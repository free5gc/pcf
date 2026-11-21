package processor

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
)

const (
	ruleReportSmfURL    = "http://smf.example"
	ruleReportAfURL     = "http://af.example"
	ruleReportSupi      = "imsi-208930000001241"
	ruleReportPolicyID  = ruleReportSupi + "-1"
	ruleReportAppSessID = ruleReportSupi + "-1"
	ruleReportPccRule   = "PccRule-2"
)

// newRuleReportTestPCF returns a PCF with an SM policy holding ruleReportPccRule, installed
// for media component 1 of an AF session subscribed to FAILED_RESOURCES_ALLOCATION.
func newRuleReportTestPCF(t *testing.T) (*Processor, *pcf_context.UeSmPolicyData, *pcf_context.AppSessionData) {
	t.Helper()
	pcfCtx := &pcf_context.PCFContext{}
	ue, err := pcfCtx.NewPCFUe(ruleReportSupi)
	require.NoError(t, err)
	smPolicy := &pcf_context.UeSmPolicyData{
		PolicyContext: &models.Pcf_SMPolCtrl_SmPolicyContextData{
			Supi: ruleReportSupi, PduSessionId: 1, NotificationUri: ruleReportSmfURL + "/notify",
		},
		PolicyDecision: &models.Pcf_SMPolCtrl_SmPolicyDecision{
			PccRules: map[string]*models.Pcf_SMPolCtrl_PccRule{
				ruleReportPccRule: {PccRuleId: ruleReportPccRule},
			},
		},
		AppSessions: map[string]bool{ruleReportAppSessID: true},
	}
	ue.SmPolicyData[ruleReportPolicyID] = smPolicy
	appSession := &pcf_context.AppSessionData{
		AppSessionId:         ruleReportAppSessID,
		SmPolicyData:         smPolicy,
		RelatedPccRuleIds:    map[string]string{"1": ruleReportPccRule},
		PccRuleIdMapToCompId: map[string]string{ruleReportPccRule: "1"},
		Events: map[models.Pcf_PolAuth_AfEvent]models.Pcf_PolAuth_AfNotifMethod{
			models.Pcf_PolAuth_AfEvent_FAILED_RESOURCES_ALLOCATION: models.Pcf_PolAuth_AfNotifMethod_EVENT_DETECTION,
		},
		EventUri: ruleReportAfURL + "/notify",
	}
	pcfCtx.AppSessionPool.Store(ruleReportAppSessID, appSession)
	return &Processor{PCF: &modAppSessionTestPCF{ctx: pcfCtx}}, smPolicy, appSession
}

// interceptAfNotification captures the event notification the AF receives.
func interceptAfNotification(notif *models.Pcf_PolAuth_EventsNotification) {
	gock.New(ruleReportAfURL).Post("/notify/notify").
		AddMatcher(func(req *http.Request, _ *gock.Request) (bool, error) {
			raw, err := io.ReadAll(req.Body)
			if err != nil {
				return false, err
			}
			return true, json.Unmarshal(raw, notif)
		}).Reply(http.StatusNoContent)
}

func ruleReportNotification() *models.Pcf_SMPolCtrl_SmPolicyNotification {
	return &models.Pcf_SMPolCtrl_SmPolicyNotification{
		ResourceUri: "http://pcf.example/npcf-smpolicycontrol/v1/sm-policies/" + ruleReportPolicyID,
	}
}

// The SMF rejects an SM policy update notification whose PCC rules cannot be installed with an
// ErrorReport (TS 29.512 clause 4.2.3.2): the PCF removes them and notifies the AF.
func TestSMPolicyNotificationErrorReportNotifiesAF(t *testing.T) {
	openapi.InterceptInnerHttp2Client(t, false)
	t.Cleanup(gock.Off)
	p, smPolicy, appSession := newRuleReportTestPCF(t)

	gock.New(ruleReportSmfURL).Post("/notify/update").Reply(http.StatusBadRequest).
		JSON(models.Pcf_SMPolCtrl_ErrorReport{
			Error: &models.ProblemDetails{Status: http.StatusBadRequest, Cause: "PCC_RULE_EVENT"},
			RuleReports: []models.Pcf_SMPolCtrl_RuleReport{{
				PccRuleIds:  []string{ruleReportPccRule},
				RuleStatus:  models.Pcf_SMPolCtrl_RuleStatus_INACTIVE,
				FailureCode: models.Pcf_SMPolCtrl_FailureCode_RES_ALLO_FAIL,
			}},
		})
	var notif models.Pcf_PolAuth_EventsNotification
	interceptAfNotification(&notif)

	p.SendSMPolicyUpdateNotification(ruleReportSmfURL+"/notify", ruleReportNotification())

	require.True(t, gock.IsDone(), "expected the AF to be notified")
	require.Equal(t, []models.Pcf_PolAuth_AfEventNotification{{
		Event: models.Pcf_PolAuth_AfEvent_FAILED_RESOURCES_ALLOCATION,
	}}, notif.EvNotifs)
	require.Equal(t, []models.Pcf_PolAuth_ResourcesAllocationInfo{{
		McResourcStatus: models.Pcf_PolAuth_MediaComponentResourcesStatus_INACTIVE,
		Flows:           []models.Pcf_PolAuth_Flows{{MedCompN: 1}},
	}}, notif.FailedResourcAllocReports)
	require.NotContains(t, smPolicy.PolicyDecision.PccRules, ruleReportPccRule)
	require.Empty(t, appSession.PccRuleIdMapToCompId)
}

// A PCC rule reported ACTIVE (its previous definition is kept) is neither removed nor reported
// to the AF as failed.
func TestSMPolicyNotificationErrorReportKeepsActiveRules(t *testing.T) {
	openapi.InterceptInnerHttp2Client(t, false)
	t.Cleanup(gock.Off)
	p, smPolicy, _ := newRuleReportTestPCF(t)

	gock.New(ruleReportSmfURL).Post("/notify/update").Reply(http.StatusBadRequest).
		JSON(models.Pcf_SMPolCtrl_ErrorReport{
			RuleReports: []models.Pcf_SMPolCtrl_RuleReport{{
				PccRuleIds:  []string{ruleReportPccRule},
				RuleStatus:  models.Pcf_SMPolCtrl_RuleStatus_ACTIVE,
				FailureCode: models.Pcf_SMPolCtrl_FailureCode_RES_ALLO_FAIL,
			}},
		})

	p.SendSMPolicyUpdateNotification(ruleReportSmfURL+"/notify", ruleReportNotification())

	require.True(t, gock.IsDone())
	require.Contains(t, smPolicy.PolicyDecision.PccRules, ruleReportPccRule)
}

// Other notification failures are only logged.
func TestSMPolicyNotificationErrorWithoutRuleReports(t *testing.T) {
	openapi.InterceptInnerHttp2Client(t, false)
	t.Cleanup(gock.Off)
	p, smPolicy, _ := newRuleReportTestPCF(t)

	gock.New(ruleReportSmfURL).Post("/notify/update").Reply(http.StatusBadRequest).
		JSON(models.Pcf_SMPolCtrl_ErrorReport{
			Error: &models.ProblemDetails{Status: http.StatusBadRequest, Cause: "MANDATORY_IE_INCORRECT"},
		})

	p.SendSMPolicyUpdateNotification(ruleReportSmfURL+"/notify", ruleReportNotification())

	require.True(t, gock.IsDone())
	require.Contains(t, smPolicy.PolicyDecision.PccRules, ruleReportPccRule)
}
