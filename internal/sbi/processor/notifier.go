package processor

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/mohae/deepcopy"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/util"
	"github.com/free5gc/util/metrics/sbi"
	"github.com/free5gc/util/mongoapi"
)

func (p *Processor) HandleAmfStatusChangeNotify(
	c *gin.Context,
	amfStatusChangeNotification models.Amf_Comm_AmfStatusChangeNotification,
) {
	logger.CallbackLog.Warnf("[PCF] Handle Amf Status Change Notify is not implemented.")

	// TODO: handle AMF Status Change Notify
	logger.CallbackLog.Debugf("receive AMF status change notification[%+v]", amfStatusChangeNotification)

	c.Status(http.StatusNoContent)
}

func (p *Processor) HandlePolicyDataChangeNotify(
	c *gin.Context,
	supi string,
	policyDataChangeNotification models.Udr_DR_PolicyDataChangeNotification,
) {
	logger.CallbackLog.Warnf("[PCF] Handle Policy Data Change Notify is not implemented.")

	PolicyDataChangeNotifyProcedure(supi, policyDataChangeNotification)

	c.JSON(http.StatusNotImplemented, gin.H{})
}

// TODO: handle Policy Data Change Notify
func PolicyDataChangeNotifyProcedure(supi string, notification models.Udr_DR_PolicyDataChangeNotification) {
}

func (p *Processor) HandleInfluenceDataUpdateNotify(
	c *gin.Context,
	supi string,
	pduSessionId string,
	trafficInfluDataNotif []models.Udr_DR_TrafficInfluDataNotif,
) {
	logger.CallbackLog.Infof("[PCF] Handle Influence Data Update Notify")

	smPolicyID := fmt.Sprintf("%s-%s", supi, pduSessionId)
	ue := p.Context().PCFUeFindByPolicyId(smPolicyID)
	if ue == nil || ue.SmPolicyData[smPolicyID] == nil {
		problemDetail := util.GetProblemDetail("smPolicyID not found in PCF", util.CONTEXT_NOT_FOUND)
		logger.CallbackLog.Error(problemDetail.Detail)
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetail.Cause)
		c.JSON(int(problemDetail.Status), problemDetail)
		return
	}
	storedPolicy := ue.SmPolicyData[smPolicyID]
	storedPolicy.InfluenceDataMu.Lock()
	defer storedPolicy.InfluenceDataMu.Unlock()

	// Commit the routing policy only after the entire notification batch succeeds.
	smPolicy := &pcf_context.UeSmPolicyData{
		PolicyContext:       storedPolicy.PolicyContext,
		PolicyDecision:      deepcopy.Copy(storedPolicy.PolicyDecision).(*models.Pcf_SMPolCtrl_SmPolicyDecision),
		PccRuleIdGenerator:  storedPolicy.PccRuleIdGenerator,
		ChargingIdGenerator: storedPolicy.ChargingIdGenerator,
		TrafficInfluence:    deepcopy.Copy(storedPolicy.TrafficInfluence).(*pcf_context.TrafficInfluenceState),
	}
	for _, notification := range trafficInfluDataNotif {
		influenceID := getInfluenceID(notification.ResUri)
		if influenceID == "" {
			continue
		}
		// notifying deletion
		if notification.TrafficInfluData == nil {
			var err error
			_, err = util.RemoveTrafficInfluencePolicy(smPolicy, influenceID)
			if err != nil {
				logger.CallbackLog.Errorf("Remove TI rules: %v", err)
				c.Status(http.StatusInternalServerError)
				return
			}
		} else {
			var chgData *models.Pcf_SMPolCtrl_ChargingData

			trafficInfluData := *notification.TrafficInfluData
			if trafficInfluData.Snssai == nil {
				problemDetail := util.GetProblemDetail(
					"Errorneous/Missing Mandotory IE: trafficInfluData.snssai",
					util.ERROR_REQUEST_PARAMETERS,
				)
				logger.CallbackLog.Warnf("Influence data notify validation failed: %+v", problemDetail)
				c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetail.Cause)
				c.JSON(int(problemDetail.Status), problemDetail)
				return
			}

			needsDefault, err := util.TrafficInfluenceNeedsDefault(smPolicy, trafficInfluData)
			if err != nil {
				problem := util.GetProblemDetail(err.Error(), util.ERROR_REQUEST_PARAMETERS)
				c.Set(sbi.IN_PB_DETAILS_CTX_STR, problem.Cause)
				c.JSON(int(problem.Status), problem)
				return
			}
			if needsDefault {
				filterCharging := bson.M{
					"ueId":   ue.Supi,
					"snssai": util.SnssaiModelsToHex(*trafficInfluData.Snssai),
					"dnn":    "",
					"filter": "",
				}
				chargingInterface, err := mongoapi.RestfulAPIGetOne(chargingDataColl, filterCharging, 2)
				if err != nil {
					logger.SmPolicyLog.Errorf("Fail to get charging data to mongoDB err: %+v", err)
					chgData = nil
				} else if chargingInterface != nil {
					rg, err1 := p.Context().RatingGroupIdGenerator.Allocate()
					if err1 != nil {
						logger.SmPolicyLog.Error("rating group allocate error")
						problemDetails := util.GetProblemDetail("rating group allocate error", util.ERROR_IDGENERATOR)
						c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
						c.JSON(int(problemDetails.Status), problemDetails)
						return
					}
					chgData = &models.Pcf_SMPolCtrl_ChargingData{
						ChgId:          util.GetChgId(smPolicy.ChargingIdGenerator),
						RatingGroup:    int32(rg),
						ReportingLevel: models.Pcf_SMPolCtrl_ReportingLevel_RAT_GR_LEVEL,
						MeteringMethod: models.Pcf_SMPolCtrl_MeteringMethod_VOLUME,
					}

					switch chargingInterface["chargingMethod"].(string) {
					case "Online":
						chgData.Online = true
						chgData.Offline = false
					case "Offline":
						chgData.Online = false
						chgData.Offline = true
					}

					chargingInterface["ratingGroup"] = chgData.RatingGroup
					logger.SmPolicyLog.Tracef("put ratingGroup[%+v] for [%+v] to MongoDB", chgData.RatingGroup, ue.Supi)
					if _, err = mongoapi.RestfulAPIPutOne(
						chargingDataColl, chargingInterface, chargingInterface, 2); err != nil {
						logger.SmPolicyLog.Errorf("Fail to put charging data to mongoDB err: %+v", err)
					} else {
						smPolicy.ChargingIdGenerator++
					}
					if ue.RatingGroupData == nil {
						ue.RatingGroupData = make(map[string][]int32)
					}
					ue.RatingGroupData[smPolicyID] = append(ue.RatingGroupData[smPolicyID], chgData.RatingGroup)
				}
			}

			_, err = util.SetTrafficInfluencePolicy(smPolicy, influenceID, trafficInfluData, chgData)
			if err != nil {
				problem := util.GetProblemDetail(err.Error(), util.ERROR_REQUEST_PARAMETERS)
				logger.CallbackLog.Warnf("Cannot apply TI routing policy: %v", err)
				c.Set(sbi.IN_PB_DETAILS_CTX_STR, problem.Cause)
				c.JSON(int(problem.Status), problem)
				return
			}
		}
	}
	decision := util.TrafficInfluencePolicyChanges(storedPolicy.PolicyDecision, smPolicy.PolicyDecision)
	*storedPolicy.PolicyDecision = *smPolicy.PolicyDecision
	storedPolicy.PccRuleIdGenerator = smPolicy.PccRuleIdGenerator
	storedPolicy.ChargingIdGenerator = smPolicy.ChargingIdGenerator
	storedPolicy.TrafficInfluence = smPolicy.TrafficInfluence
	smPolicyNotification := models.Pcf_SMPolCtrl_SmPolicyNotification{
		ResourceUri:      util.GetResourceUri(models.Nrf_NFMgmt_ServiceName_NPCF_SMPOLICYCONTROL, smPolicyID),
		SmPolicyDecision: decision,
	}
	if len(decision.PccRules) != 0 || len(decision.TraffContDecs) != 0 ||
		len(decision.QosDecs) != 0 || len(decision.ChgDecs) != 0 {
		p.SendSMPolicyUpdateNotification(smPolicy.PolicyContext.NotificationUri, &smPolicyNotification)
	}
	c.Status(http.StatusNoContent)
}

func getInfluenceID(resUri string) string {
	temp := strings.Split(resUri, "/")
	return temp[len(temp)-1]
}
