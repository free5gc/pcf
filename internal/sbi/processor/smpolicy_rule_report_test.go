package processor

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
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

// newRuleReportTestPCF returns a PCF with an SM policy holding the PCC rules pccRuleIds, installed for
// the media components 1, 2, ... of an AF session subscribed to FAILED_RESOURCES_ALLOCATION. They are
// stored in the PCF context of the process: the PCC rule removal cleans up the AF sessions it finds
// there.
func newRuleReportTestPCF(t *testing.T, pccRuleIds ...string,
) (*Processor, *pcf_context.UeSmPolicyData, *pcf_context.AppSessionData) {
	t.Helper()
	if len(pccRuleIds) == 0 {
		pccRuleIds = []string{ruleReportPccRule}
	}
	pcfCtx := pcf_context.GetSelf()
	ue, err := pcfCtx.NewPCFUe(ruleReportSupi)
	require.NoError(t, err)
	t.Cleanup(func() {
		pcfCtx.UePool.Delete(ruleReportSupi)
		pcfCtx.AppSessionPool.Delete(ruleReportAppSessID)
	})
	smPolicy := &pcf_context.UeSmPolicyData{
		PcfUe: ue,
		PolicyContext: &models.Pcf_SMPolCtrl_SmPolicyContextData{
			Supi: ruleReportSupi, PduSessionId: 1, NotificationUri: ruleReportSmfURL + "/notify",
		},
		PolicyDecision: &models.Pcf_SMPolCtrl_SmPolicyDecision{
			PccRules: make(map[string]*models.Pcf_SMPolCtrl_PccRule),
		},
		AppSessions: map[string]bool{ruleReportAppSessID: true},
	}
	ue.SmPolicyData[ruleReportPolicyID] = smPolicy
	appSession := &pcf_context.AppSessionData{
		AppSessionId: ruleReportAppSessID,
		AppSessionContext: &models.Pcf_PolAuth_AppSessionContext{
			AscReqData: &models.Pcf_PolAuth_AppSessionContextReqData{NotifUri: ruleReportAfURL},
		},
		SmPolicyData:         smPolicy,
		RelatedPccRuleIds:    make(map[string]string),
		PccRuleIdMapToCompId: make(map[string]string),
		Events: map[models.Pcf_PolAuth_AfEvent]models.Pcf_PolAuth_AfNotifMethod{
			models.Pcf_PolAuth_AfEvent_FAILED_RESOURCES_ALLOCATION: models.Pcf_PolAuth_AfNotifMethod_EVENT_DETECTION,
		},
		EventUri: ruleReportAfURL + "/notify",
	}
	for i, pccRuleID := range pccRuleIds {
		compN := strconv.Itoa(i + 1)
		smPolicy.PolicyDecision.PccRules[pccRuleID] = &models.Pcf_SMPolCtrl_PccRule{PccRuleId: pccRuleID}
		appSession.RelatedPccRuleIds[compN] = pccRuleID
		appSession.PccRuleIdMapToCompId[pccRuleID] = compN
	}
	pcfCtx.AppSessionPool.Store(ruleReportAppSessID, appSession)
	return &Processor{PCF: &modAppSessionTestPCF{ctx: pcfCtx}}, smPolicy, appSession
}

// afRequests records the requests the AF receives: event notifications ("/notify/notify") and
// requests to delete the AF session ("/terminate").
type afRequests struct {
	mu           sync.Mutex
	paths        []string
	notification models.Pcf_PolAuth_EventsNotification
	termination  models.Pcf_PolAuth_TerminationInfo
}

func interceptAfRequests(t *testing.T) *afRequests {
	t.Helper()
	af := &afRequests{}
	gock.New(ruleReportAfURL).Post("/.*").Persist().
		AddMatcher(func(req *http.Request, _ *gock.Request) (bool, error) {
			raw, err := io.ReadAll(req.Body)
			if err != nil {
				return false, err
			}
			af.mu.Lock()
			defer af.mu.Unlock()
			af.paths = append(af.paths, req.URL.Path)
			if req.URL.Path == "/terminate" {
				return true, json.Unmarshal(raw, &af.termination)
			}
			return true, json.Unmarshal(raw, &af.notification)
		}).Reply(http.StatusNoContent)
	return af
}

func (af *afRequests) received() []string {
	af.mu.Lock()
	defer af.mu.Unlock()
	return slices.Clone(af.paths)
}

func ruleReportNotification() *models.Pcf_SMPolCtrl_SmPolicyNotification {
	return &models.Pcf_SMPolCtrl_SmPolicyNotification{
		ResourceUri: "http://pcf.example/npcf-smpolicycontrol/v1/sm-policies/" + ruleReportPolicyID,
	}
}

func inactiveRuleReport(pccRuleIds ...string) models.Pcf_SMPolCtrl_RuleReport {
	return models.Pcf_SMPolCtrl_RuleReport{
		PccRuleIds:  pccRuleIds,
		RuleStatus:  models.Pcf_SMPolCtrl_RuleStatus_INACTIVE,
		FailureCode: models.Pcf_SMPolCtrl_FailureCode_RES_ALLO_FAIL,
	}
}

func replyErrorReport(ruleReports ...models.Pcf_SMPolCtrl_RuleReport) {
	gock.New(ruleReportSmfURL).Post("/notify/update").Reply(http.StatusBadRequest).
		JSON(models.Pcf_SMPolCtrl_ErrorReport{
			Error:       &models.ProblemDetails{Status: http.StatusBadRequest, Cause: "PCC_RULE_EVENT"},
			RuleReports: ruleReports,
		})
}

// The SMF rejects an SM policy update notification whose PCC rules cannot be installed with an
// ErrorReport (TS 29.512 clause 4.2.3.2): the PCF notifies the AF and removes them. As all the PCC
// rules of the AF session fail, the AF is requested to delete it (TS 29.514 clause 4.2.5.3).
func TestSMPolicyNotificationErrorReportNotifiesAF(t *testing.T) {
	openapi.InterceptInnerHttp2Client(t, false)
	gock.Flush()
	t.Cleanup(gock.Off)
	p, smPolicy, appSession := newRuleReportTestPCF(t)
	replyErrorReport(inactiveRuleReport(ruleReportPccRule))
	af := interceptAfRequests(t)

	p.SendSMPolicyUpdateNotification(ruleReportSmfURL+"/notify", ruleReportNotification())

	require.Equal(t, []string{"/notify/notify", "/terminate"}, af.received())
	require.Equal(t, []models.Pcf_PolAuth_AfEventNotification{{
		Event: models.Pcf_PolAuth_AfEvent_FAILED_RESOURCES_ALLOCATION,
	}}, af.notification.EvNotifs)
	require.Equal(t, []models.Pcf_PolAuth_ResourcesAllocationInfo{{
		McResourcStatus: models.Pcf_PolAuth_MediaComponentResourcesStatus_INACTIVE,
		Flows:           []models.Pcf_PolAuth_Flows{{MedCompN: 1}},
	}}, af.notification.FailedResourcAllocReports)
	require.Equal(t, models.Pcf_PolAuth_TerminationCause_ALL_SDF_DEACTIVATION, af.termination.TermCause)
	require.NotContains(t, smPolicy.PolicyDecision.PccRules, ruleReportPccRule)
	require.Empty(t, appSession.PccRuleIdMapToCompId)
}

// When only some PCC rules of the AF session fail, the AF is notified of them and the AF session is
// kept with the other PCC rules.
func TestSMPolicyNotificationErrorReportSomeRulesFail(t *testing.T) {
	openapi.InterceptInnerHttp2Client(t, false)
	gock.Flush()
	t.Cleanup(gock.Off)
	p, smPolicy, appSession := newRuleReportTestPCF(t, ruleReportPccRule, "PccRule-3")
	replyErrorReport(inactiveRuleReport("PccRule-3"))
	af := interceptAfRequests(t)

	p.SendSMPolicyUpdateNotification(ruleReportSmfURL+"/notify", ruleReportNotification())

	require.Equal(t, []string{"/notify/notify"}, af.received())
	require.Equal(t, []models.Pcf_PolAuth_ResourcesAllocationInfo{{
		McResourcStatus: models.Pcf_PolAuth_MediaComponentResourcesStatus_INACTIVE,
		Flows:           []models.Pcf_PolAuth_Flows{{MedCompN: 2}},
	}}, af.notification.FailedResourcAllocReports)
	require.Contains(t, smPolicy.PolicyDecision.PccRules, ruleReportPccRule)
	require.NotContains(t, smPolicy.PolicyDecision.PccRules, "PccRule-3")
	require.Equal(t, map[string]string{ruleReportPccRule: "1"}, appSession.PccRuleIdMapToCompId)
}

// A PCC rule reported ACTIVE (its previous definition is kept) is neither removed nor reported
// to the AF as failed.
func TestSMPolicyNotificationErrorReportKeepsActiveRules(t *testing.T) {
	openapi.InterceptInnerHttp2Client(t, false)
	gock.Flush()
	t.Cleanup(gock.Off)
	p, smPolicy, _ := newRuleReportTestPCF(t)
	activeReport := inactiveRuleReport(ruleReportPccRule)
	activeReport.RuleStatus = models.Pcf_SMPolCtrl_RuleStatus_ACTIVE
	replyErrorReport(activeReport)
	af := interceptAfRequests(t)

	p.SendSMPolicyUpdateNotification(ruleReportSmfURL+"/notify", ruleReportNotification())

	require.Empty(t, af.received())
	require.Contains(t, smPolicy.PolicyDecision.PccRules, ruleReportPccRule)
}

// Other notification failures are only logged.
func TestSMPolicyNotificationErrorWithoutRuleReports(t *testing.T) {
	openapi.InterceptInnerHttp2Client(t, false)
	gock.Flush()
	t.Cleanup(gock.Off)
	p, smPolicy, _ := newRuleReportTestPCF(t)
	gock.New(ruleReportSmfURL).Post("/notify/update").Reply(http.StatusBadRequest).
		JSON(models.Pcf_SMPolCtrl_ErrorReport{
			Error: &models.ProblemDetails{Status: http.StatusBadRequest, Cause: "MANDATORY_IE_INCORRECT"},
		})
	af := interceptAfRequests(t)

	p.SendSMPolicyUpdateNotification(ruleReportSmfURL+"/notify", ruleReportNotification())

	require.Empty(t, af.received())
	require.Contains(t, smPolicy.PolicyDecision.PccRules, ruleReportPccRule)
}

// A PCC rule report in an SM policy update (TS 29.512 clause 4.2.4.15) is handled the same way.
func TestSMPolicyUpdateRuleReportNotifiesAF(t *testing.T) {
	openapi.InterceptInnerHttp2Client(t, false)
	gock.Flush()
	t.Cleanup(gock.Off)
	p, smPolicy, appSession := newRuleReportTestPCF(t)
	af := interceptAfRequests(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	p.HandleUpdateSmPolicyContextRequest(c, ruleReportPolicyID, models.Pcf_SMPolCtrl_SmPolicyUpdateContextData{
		RuleReports: []models.Pcf_SMPolCtrl_RuleReport{inactiveRuleReport(ruleReportPccRule)},
	})

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, []string{"/notify/notify", "/terminate"}, af.received())
	require.Equal(t, []models.Pcf_PolAuth_ResourcesAllocationInfo{{
		McResourcStatus: models.Pcf_PolAuth_MediaComponentResourcesStatus_INACTIVE,
		Flows:           []models.Pcf_PolAuth_Flows{{MedCompN: 1}},
	}}, af.notification.FailedResourcAllocReports)
	require.Equal(t, models.Pcf_PolAuth_TerminationCause_ALL_SDF_DEACTIVATION, af.termination.TermCause)
	require.NotContains(t, smPolicy.PolicyDecision.PccRules, ruleReportPccRule)
	require.Empty(t, appSession.PccRuleIdMapToCompId)
}
