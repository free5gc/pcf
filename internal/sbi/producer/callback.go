package producer

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/util"
	"github.com/free5gc/util/httpwrapper"
)

func HandleAmfStatusChangeNotify(request *httpwrapper.Request) *httpwrapper.Response {
	logger.CallbackLog.Warnf("[PCF] Handle Amf Status Change Notify is not implemented.")

	notification := request.Body.(models.AmfStatusChangeNotification)

	AmfStatusChangeNotifyProcedure(notification)

	return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
}

// TODO: handle AMF Status Change Notify
func AmfStatusChangeNotifyProcedure(notification models.AmfStatusChangeNotification) {
	logger.CallbackLog.Debugf("receive AMF status change notification[%+v]", notification)
}

func HandlePolicyDataChangeNotify(request *httpwrapper.Request) *httpwrapper.Response {
	logger.CallbackLog.Warnf("[PCF] Handle Policy Data Change Notify is not implemented.")

	notification := request.Body.(models.PolicyDataChangeNotification)
	supi := request.Params["supi"]

	PolicyDataChangeNotifyProcedure(supi, notification)

	return httpwrapper.NewResponse(http.StatusNotImplemented, nil, nil)
}

// TODO: handle Policy Data Change Notify
func PolicyDataChangeNotifyProcedure(supi string, notification models.PolicyDataChangeNotification) {
}

func HandleInfluenceDataUpdateNotify(request *httpwrapper.Request) *httpwrapper.Response {
	logger.CallbackLog.Infof("[PCF] Handle Influence Data Update Notify")

	notifications := request.Body.([]models.TrafficInfluDataNotif)
	supi := request.Params["supi"]
	pduSessionId := request.Params["pduSessionId"]

	if problemDetails := InfluenceDataUpdateNotifyProcedure(supi, pduSessionId, notifications); problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}

func InfluenceDataUpdateNotifyProcedure(supi, pduSessionId string,
	notifications []models.TrafficInfluDataNotif,
) *models.ProblemDetails {
	smPolicyID := fmt.Sprintf("%s-%s", supi, pduSessionId)
	ue := pcf_context.GetSelf().PCFUeFindByPolicyId(smPolicyID)
	if ue == nil || ue.SmPolicyData[smPolicyID] == nil {
		problemDetail := util.GetProblemDetail("smPolicyID not found in PCF", util.CONTEXT_NOT_FOUND)
		logger.CallbackLog.Errorf(problemDetail.Detail)
		return &problemDetail
	}
	smPolicy := ue.SmPolicyData[smPolicyID]
	decision := smPolicy.PolicyDecision
	influenceDataToPccRule := smPolicy.InfluenceDataToPccRule
	precedence := getAvailablePrecedence(smPolicy.PolicyDecision.PccRules)
	for _, notification := range notifications {
		influenceID := getInfluenceID(notification.ResUri)
		if influenceID == "" {
			continue
		}
		// notifying deletion
		if notification.TrafficInfluData == nil {
			pccRuleID := influenceDataToPccRule[influenceID]
			decision = &models.SmPolicyDecision{}
			if err := smPolicy.RemovePccRule(pccRuleID, decision); err != nil {
				logger.CallbackLog.Errorf("Remove PCC rule error: %+v", err)
			}
			delete(influenceDataToPccRule, influenceID)
		} else {
			trafficInfluData := *notification.TrafficInfluData
			if pccRuleID, ok := influenceDataToPccRule[influenceID]; ok {
				// notifying Individual Influence Data update
				pccRule := decision.PccRules[pccRuleID]
				util.SetSmPolicyDecisionByTrafficInfluData(decision, pccRule, trafficInfluData)
			} else {
				// notifying Individual Influence Data creation

				pccRule := util.CreatePccRule(smPolicy.PccRuleIdGenerator, precedence, nil, trafficInfluData.AfAppId)
				util.SetSmPolicyDecisionByTrafficInfluData(decision, pccRule, trafficInfluData)
				influenceDataToPccRule[influenceID] = pccRule.PccRuleId
				smPolicy.PccRuleIdGenerator++
				if precedence < Precedence_Maximum {
					precedence++
				}
			}
		}
	}
	smPolicyNotification := models.SmPolicyNotification{
		ResourceUri:      util.GetResourceUri(models.ServiceName_NPCF_SMPOLICYCONTROL, smPolicyID),
		SmPolicyDecision: decision,
	}
	go SendSMPolicyUpdateNotification(smPolicy.PolicyContext.NotificationUri, &smPolicyNotification)
	return nil
}

func getInfluenceID(resUri string) string {
	temp := strings.Split(resUri, "/")
	return temp[len(temp)-1]
}
