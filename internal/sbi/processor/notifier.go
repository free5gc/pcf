package processor

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/util"
)

func (p *Processor) HandleAmfStatusChangeNotify(
	c *gin.Context,
	amfStatusChangeNotification models.AmfStatusChangeNotification,
) {
	logger.CallbackLog.Warnf("[PCF] Handle Amf Status Change Notify is not implemented.")

	// TODO: handle AMF Status Change Notify
	logger.CallbackLog.Debugf("receive AMF status change notification[%+v]", amfStatusChangeNotification)

	c.JSON(http.StatusNoContent, nil)
}

func (p *Processor) HandlePolicyDataChangeNotify(
	c *gin.Context,
	supi string,
	policyDataChangeNotification models.PolicyDataChangeNotification,
) {
	logger.CallbackLog.Warnf("[PCF] Handle Policy Data Change Notify is not implemented.")

	PolicyDataChangeNotifyProcedure(supi, policyDataChangeNotification)

	c.JSON(http.StatusNotImplemented, nil)
}

// TODO: handle Policy Data Change Notify
func PolicyDataChangeNotifyProcedure(supi string, notification models.PolicyDataChangeNotification) {
}

func (p *Processor) HandleInfluenceDataUpdateNotify(
	c *gin.Context,
	supi string,
	pduSessionId string,
	trafficInfluDataNotif []models.TrafficInfluDataNotif,
) {
	logger.CallbackLog.Infof("[PCF] Handle Influence Data Update Notify")

	smPolicyID := fmt.Sprintf("%s-%s", supi, pduSessionId)
	ue := p.Context().PCFUeFindByPolicyId(smPolicyID)
	if ue == nil || ue.SmPolicyData[smPolicyID] == nil {
		problemDetail := util.GetProblemDetail("smPolicyID not found in PCF", util.CONTEXT_NOT_FOUND)
		logger.CallbackLog.Errorf(problemDetail.Detail)
		c.JSON(int(problemDetail.Status), problemDetail)
		return
	}
	smPolicy := ue.SmPolicyData[smPolicyID]
	decision := smPolicy.PolicyDecision
	influenceDataToPccRule := smPolicy.InfluenceDataToPccRule
	precedence := getAvailablePrecedence(smPolicy.PolicyDecision.PccRules)
	for _, notification := range trafficInfluDataNotif {
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
	go p.SendSMPolicyUpdateNotification(smPolicy.PolicyContext.NotificationUri, &smPolicyNotification)
	c.JSON(http.StatusNoContent, nil)
}

func getInfluenceID(resUri string) string {
	temp := strings.Split(resUri, "/")
	return temp[len(temp)-1]
}
