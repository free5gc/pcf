package producer

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/antihax/optional"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nudr_DataRepository"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/sbi/consumer"
	"github.com/free5gc/pcf/internal/util"
	"github.com/free5gc/util/httpwrapper"
	"github.com/free5gc/util/mongoapi"
)

const (
	flowRuleDataColl = "policyData.ues.flowRule"
	qosFlowDataColl  = "policyData.ues.qosFlow"
)

// SmPoliciesPost -
func HandleCreateSmPolicyRequest(request *httpwrapper.Request) *httpwrapper.Response {
	// step 1: log
	logger.SmPolicyLog.Infof("Handle CreateSmPolicy")
	// step 2: retrieve request
	requestDataType := request.Body.(models.SmPolicyContextData)

	// step 3: handle the message
	header, response, problemDetails := createSMPolicyProcedure(requestDataType)

	// step 4: process the return value from step 3
	if response != nil {
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusCreated, header, response)
	} else if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return httpwrapper.NewResponse(http.StatusNotFound, nil, nil)
	}
}

func newQosDataWithQosFlowMap(qosFlow map[string]interface{}) *models.QosData {
	qosData := &models.QosData{
		QosId:  strconv.Itoa(int(qosFlow["qfi"].(float64))),
		Qnc:    false,
		Var5qi: int32(qosFlow["5qi"].(float64)),
	}
	if qosFlow["mbrUL"] != nil {
		qosData.MaxbrUl = qosFlow["mbrUL"].(string)
	}
	if qosFlow["mbrDL"] != nil {
		qosData.MaxbrDl = qosFlow["mbrDL"].(string)
	}
	if qosFlow["gbrUL"] != nil {
		qosData.GbrUl = qosFlow["gbrUL"].(string)
	}
	if qosFlow["gbrDL"] != nil {
		qosData.GbrDl = qosFlow["gbrDL"].(string)
	}

	return qosData
}

func createSMPolicyProcedure(request models.SmPolicyContextData) (
	header http.Header, response *models.SmPolicyDecision, problemDetails *models.ProblemDetails,
) {
	var err error
	logger.SmPolicyLog.Tracef("Handle Create SM Policy Request")

	if request.Supi == "" || request.SliceInfo == nil || len(request.SliceInfo.Sd) != 6 {
		problemDetail := util.GetProblemDetail("Errorneous/Missing Mandotory IE", util.ERROR_INITIAL_PARAMETERS)
		logger.SmPolicyLog.Warnln("Errorneous/Missing Mandotory IE", util.ERROR_INITIAL_PARAMETERS)
		return nil, nil, &problemDetail
	}

	pcfSelf := pcf_context.GetSelf()
	var ue *pcf_context.UeContext
	if val, exist := pcfSelf.UePool.Load(request.Supi); exist {
		ue = val.(*pcf_context.UeContext)
	}

	if ue == nil {
		problemDetail := util.GetProblemDetail("Supi is not supported in PCF", util.USER_UNKNOWN)
		logger.SmPolicyLog.Warnf("Supi[%s] is not supported in PCF", request.Supi)
		return nil, nil, &problemDetail
	}
	udrUri := getUdrUri(ue)
	if udrUri == "" {
		problemDetail := util.GetProblemDetail("Can't find corresponding UDR with UE", util.USER_UNKNOWN)
		logger.SmPolicyLog.Warnf("Can't find corresponding UDR with UE[%s]", ue.Supi)
		return nil, nil, &problemDetail
	}
	var smData models.SmPolicyData
	smPolicyID := fmt.Sprintf("%s-%d", ue.Supi, request.PduSessionId)
	smPolicyData := ue.SmPolicyData[smPolicyID]
	if smPolicyData == nil || smPolicyData.SmPolicyData == nil {
		client := util.GetNudrClient(udrUri)
		param := Nudr_DataRepository.PolicyDataUesUeIdSmDataGetParamOpts{
			Snssai: optional.NewInterface(util.MarshToJsonString(*request.SliceInfo)),
			Dnn:    optional.NewString(request.Dnn),
		}
		var response *http.Response
		smData, response, err = client.DefaultApi.PolicyDataUesUeIdSmDataGet(context.Background(), ue.Supi, &param)
		if err != nil || response == nil || response.StatusCode != http.StatusOK {
			problemDetail := util.GetProblemDetail("Can't find UE SM Policy Data in UDR", util.USER_UNKNOWN)
			logger.SmPolicyLog.Warnf("Can't find UE[%s] SM Policy Data in UDR", ue.Supi)
			return nil, nil, &problemDetail
		}
		defer func() {
			if rspCloseErr := response.Body.Close(); rspCloseErr != nil {
				logger.SmPolicyLog.Errorf(
					"PolicyDataUesUeIdSmDataGet response body cannot close: %+v", rspCloseErr)
			}
		}()
		// TODO: subscribe to UDR
	} else {
		smData = *smPolicyData.SmPolicyData
	}
	amPolicy := ue.FindAMPolicy(request.AccessType, request.ServingNetwork)
	if amPolicy == nil {
		problemDetail := util.GetProblemDetail("Can't find corresponding AM Policy", util.POLICY_CONTEXT_DENIED)
		logger.SmPolicyLog.Warnf("Can't find corresponding AM Policy")
		// message.SendHttpResponseMessage(httpChannel, nil, int(rsp.Status), rsp)
		return nil, nil, &problemDetail
	}
	// TODO: check service restrict
	if ue.Gpsi == "" {
		ue.Gpsi = request.Gpsi
	}
	if ue.Pei == "" {
		ue.Pei = request.Pei
	}
	if smPolicyData != nil {
		delete(ue.SmPolicyData, smPolicyID)
	}
	smPolicyData = ue.NewUeSmPolicyData(smPolicyID, request, &smData)
	// Policy Decision
	decision := models.SmPolicyDecision{
		SessRules:     make(map[string]*models.SessionRule),
		PccRules:      make(map[string]*models.PccRule),
		TraffContDecs: make(map[string]*models.TrafficControlData),
	}
	SessRuleId := fmt.Sprintf("SessRuleId-%d", request.PduSessionId)
	sessRule := models.SessionRule{
		AuthSessAmbr: request.SubsSessAmbr,
		SessRuleId:   SessRuleId,
		// RefUmData
		// RefCondData
	}
	defQos := request.SubsDefQos
	if defQos != nil {
		sessRule.AuthDefQos = &models.AuthorizedDefaultQos{
			Var5qi:        defQos.Var5qi,
			Arp:           defQos.Arp,
			PriorityLevel: defQos.PriorityLevel,
			// AverWindow
			// MaxDataBurstVol
		}
	}
	decision.SessRules[SessRuleId] = &sessRule
	// TODO: See how UDR used
	dnnData := util.GetSMPolicyDnnData(smData, request.SliceInfo, request.Dnn)
	if dnnData != nil {
		decision.Online = dnnData.Online
		decision.Offline = dnnData.Offline
		decision.Ipv4Index = dnnData.Ipv4Index
		decision.Ipv6Index = dnnData.Ipv6Index
		// Set Aggregate GBR if exist
		if dnnData.GbrDl != "" {
			var gbrDL float64
			gbrDL, err = pcf_context.ConvertBitRateToKbps(dnnData.GbrDl)
			if err != nil {
				logger.SmPolicyLog.Warnf(err.Error())
			} else {
				smPolicyData.RemainGbrDL = &gbrDL
				logger.SmPolicyLog.Tracef("SM Policy Dnn[%s] Data Aggregate DL GBR[%.2f Kbps]", request.Dnn, gbrDL)
			}
		}
		if dnnData.GbrUl != "" {
			var gbrUL float64
			gbrUL, err = pcf_context.ConvertBitRateToKbps(dnnData.GbrUl)
			if err != nil {
				logger.SmPolicyLog.Warnf(err.Error())
			} else {
				smPolicyData.RemainGbrUL = &gbrUL
				logger.SmPolicyLog.Tracef("SM Policy Dnn[%s] Data Aggregate UL GBR[%.2f Kbps]", request.Dnn, gbrUL)
			}
		}
	} else {
		logger.SmPolicyLog.Warnf(
			"Policy Subscription Info: SMPolicyDnnData is null for dnn[%s] in UE[%s]", request.Dnn, ue.Supi)
		decision.Online = request.Online
		decision.Offline = request.Offline
	}

	filter := bson.M{"ueId": ue.Supi, "snssai": util.SnssaiModelsToHex(*request.SliceInfo), "dnn": request.Dnn}
	qosFlowInterface, err := mongoapi.RestfulAPIGetMany(qosFlowDataColl, filter)
	if err != nil {
		logger.SmPolicyLog.Errorf("createSMPolicyProcedure error: %+v", err)
	}

	// get qos flows from databases
	for _, qosFlow := range qosFlowInterface {
		qosData := newQosDataWithQosFlowMap(qosFlow)
		if decision.QosDecs == nil {
			decision.QosDecs = make(map[string]*models.QosData)
		}
		decision.QosDecs[qosData.QosId] = qosData
	}

	// get flow rules from databases
	flowRulesInterface, err := mongoapi.RestfulAPIGetMany(flowRuleDataColl, filter)
	if err != nil {
		logger.SmPolicyLog.Errorf("createSMPolicyProcedure error: %+v", err)
	}

	for _, flowRule := range flowRulesInterface {
		precedence := int32(flowRule["precedence"].(float64))
		pccRule := util.CreatePccRule(smPolicyData.PccRuleIdGenerator, precedence, []models.FlowInformation{
			{
				FlowDescription: flowRule["filter"].(string),
				FlowDirection:   models.FlowDirectionRm_BIDIRECTIONAL,
			},
		}, "")
		qfi := strconv.Itoa(int(flowRule["qfi"].(float64)))
		util.SetPccRuleRelatedByQFI(&decision, pccRule, qfi)
		smPolicyData.PccRuleIdGenerator++
	}

	requestSuppFeat, err := openapi.NewSupportedFeature(request.SuppFeat)
	if err != nil {
		logger.SmPolicyLog.Errorf("openapi NewSupportedFeature error: %+v", err)
	}
	decision.SuppFeat = pcfSelf.PcfSuppFeats[models.ServiceName_NPCF_SMPOLICYCONTROL].
		NegotiateWith(requestSuppFeat).String()
	decision.QosFlowUsage = request.QosFlowUsage
	// TODO: Trigger about UMC, ADC, NetLoc,...
	decision.PolicyCtrlReqTriggers = util.PolicyControlReqTrigToArray(0x40780f)
	smPolicyData.PolicyDecision = &decision
	// TODO: PCC rule, PraInfo ...
	// Get Application Data Influence Data from UDR
	reqParam := Nudr_DataRepository.ApplicationDataInfluenceDataGetParamOpts{
		Dnns:             optional.NewInterface([]string{request.Dnn}),
		Snssais:          optional.NewInterface(util.MarshToJsonString([]models.Snssai{*request.SliceInfo})),
		InternalGroupIds: optional.NewInterface(request.InterGrpIds),
		Supis:            optional.NewInterface([]string{request.Supi}),
	}

	udrClient := util.GetNudrClient(udrUri)
	var resp *http.Response
	trafficInfluDatas, resp, err := udrClient.InfluenceDataApi.
		ApplicationDataInfluenceDataGet(context.Background(), &reqParam)
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		logger.SmPolicyLog.Warnf("Error response from UDR Application Data Influence Data Get")
	}
	if err = resp.Body.Close(); err != nil {
		logger.SmPolicyLog.Warnf("failed to close response of Application Data Influence Data Get")
	}
	logger.SmPolicyLog.Infof("Matched [%d] trafficInfluDatas from UDR", len(trafficInfluDatas))
	if len(trafficInfluDatas) != 0 {
		// UE identity in UDR appData and apply appData to sm poliocy
		var precedence int32 = 23
		for _, tiData := range trafficInfluDatas {
			pccRule := util.CreatePccRule(smPolicyData.PccRuleIdGenerator, precedence, nil, tiData.AfAppId)
			util.SetSmPolicyDecisionByTrafficInfluData(&decision, pccRule, tiData)
			influenceID := getInfluenceID(tiData.ResUri)
			if influenceID != "" {
				smPolicyData.InfluenceDataToPccRule[influenceID] = pccRule.PccRuleId
			}
			smPolicyData.PccRuleIdGenerator++
			if precedence < Precedence_Maximum {
				precedence++
			}
		}
	}

	// Subscribe to Traffic Influence Data in UDR
	subscriptionID, problemDetail, err := consumer.CreateInfluenceDataSubscription(ue, request)
	if problemDetail != nil {
		logger.SmPolicyLog.Errorf("Subscribe UDR Influence Data Failed Problem[%+v]", problemDetail)
	} else if err != nil {
		logger.SmPolicyLog.Errorf("Subscribe UDR Influence Data Error[%v]", err.Error())
	}
	smPolicyData.SubscriptionID = subscriptionID

	// Create PCF binding data to BSF
	policyAuthorizationService := pcf_context.GetSelf().NfService[models.ServiceName_NPCF_POLICYAUTHORIZATION]
	pcfBinding := models.PcfBinding{
		Supi:           request.Supi,
		Gpsi:           request.Gpsi,
		Ipv4Addr:       request.Ipv4Address,
		Ipv6Prefix:     request.Ipv6AddressPrefix,
		IpDomain:       request.IpDomain,
		Dnn:            request.Dnn,
		Snssai:         request.SliceInfo,
		PcfFqdn:        policyAuthorizationService.ApiPrefix,
		PcfIpEndPoints: *policyAuthorizationService.IpEndPoints,
	}

	// TODO: Record BSF URI instead of discovering from NRF every time
	bsfUri := consumer.SendNFInstancesBSF(pcf_context.GetSelf().NrfUri)
	if bsfUri != "" {
		bsfClient := util.GetNbsfClient(bsfUri)
		_, resp, err = bsfClient.PCFBindingsCollectionApi.CreatePCFBinding(context.Background(), pcfBinding)
		if err != nil || resp == nil || resp.StatusCode != http.StatusCreated {
			logger.SmPolicyLog.Warnf("Create PCF binding data in BSF error[%+v]", err)
			// Uncomment the following to return error response --> PDU SessEstReq will fail
			// problemDetail := util.GetProblemDetail("Cannot create PCF binding data in BSF", "")
			// return nil, nil, &problemDetail
		}
		if resp != nil {
			if err := resp.Body.Close(); err != nil {
				logger.SmPolicyLog.Warnf("failed to close response of Create PCF binding")
			}
		}
	}
	locationHeader := util.GetResourceUri(models.ServiceName_NPCF_SMPOLICYCONTROL, smPolicyID)
	header = http.Header{
		"Location": {locationHeader},
	}
	logger.SmPolicyLog.Tracef("SMPolicy PduSessionId[%d] Create", request.PduSessionId)

	return header, &decision, nil
}

// SmPoliciessmPolicyIDDeletePost -
func HandleDeleteSmPolicyContextRequest(request *httpwrapper.Request) *httpwrapper.Response {
	// step 1: log
	logger.SmPolicyLog.Infof("Handle DeleteSmPolicyContext")

	// step 2: retrieve request
	smPolicyID := request.Params["smPolicyId"]

	// step 3: handle the message
	problemDetails := deleteSmPolicyContextProcedure(smPolicyID)

	// step 4: process the return value from step 3
	if problemDetails != nil {
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}

func deleteSmPolicyContextProcedure(smPolicyID string) *models.ProblemDetails {
	logger.AmPolicyLog.Traceln("Handle SM Policy Delete")

	ue := pcf_context.GetSelf().PCFUeFindByPolicyId(smPolicyID)
	if ue == nil || ue.SmPolicyData[smPolicyID] == nil {
		problemDetail := util.GetProblemDetail("smPolicyID not found in PCF", util.CONTEXT_NOT_FOUND)
		logger.SmPolicyLog.Warnf(problemDetail.Detail)
		return &problemDetail
	}

	pcfSelf := pcf_context.GetSelf()
	smPolicy := ue.SmPolicyData[smPolicyID]

	problemDetail, err := consumer.RemoveInfluenceDataSubscription(ue, smPolicy.SubscriptionID)
	if problemDetail != nil {
		logger.SmPolicyLog.Errorf("Remove UDR Influence Data Subscription Failed Problem[%+v]", problemDetail)
	} else if err != nil {
		logger.SmPolicyLog.Errorf("Remove UDR Influence Data Subscription Error[%v]", err.Error())
	}

	// Unsubscrice UDR
	delete(ue.SmPolicyData, smPolicyID)
	logger.SmPolicyLog.Tracef("SMPolicy smPolicyID[%s] DELETE", smPolicyID)

	// Release related App Session
	terminationInfo := models.TerminationInfo{
		TermCause: models.TerminationCause_PDU_SESSION_TERMINATION,
	}
	for appSessionID := range smPolicy.AppSessions {
		if val, exist := pcfSelf.AppSessionPool.Load(appSessionID); exist {
			appSession := val.(*pcf_context.AppSessionData)
			SendAppSessionTermination(appSession, terminationInfo)
			pcfSelf.AppSessionPool.Delete(appSessionID)
			logger.SmPolicyLog.Tracef("SMPolicy[%s] DELETE Related AppSession[%s]", smPolicyID, appSessionID)
		}
	}
	return nil
}

// SmPoliciessmPolicyIDGet -
func HandleGetSmPolicyContextRequest(request *httpwrapper.Request) *httpwrapper.Response {
	// step 1: log
	logger.SmPolicyLog.Infof("Handle GetSmPolicyContext")

	// step 2: retrieve request
	smPolicyID := request.Params["smPolicyId"]
	// step 3: handle the message
	response, problemDetails := getSmPolicyContextProcedure(smPolicyID)

	// step 4: process the return value from step 3
	if response != nil {
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getSmPolicyContextProcedure(smPolicyID string) (
	response *models.SmPolicyControl, problemDetails *models.ProblemDetails,
) {
	logger.SmPolicyLog.Traceln("Handle GET SM Policy Request")

	ue := pcf_context.GetSelf().PCFUeFindByPolicyId(smPolicyID)
	if ue == nil || ue.SmPolicyData[smPolicyID] == nil {
		problemDetail := util.GetProblemDetail("smPolicyID not found in PCF", util.CONTEXT_NOT_FOUND)
		logger.SmPolicyLog.Warnf(problemDetail.Detail)
		return nil, &problemDetail
	}
	smPolicyData := ue.SmPolicyData[smPolicyID]
	response = &models.SmPolicyControl{
		Policy:  smPolicyData.PolicyDecision,
		Context: smPolicyData.PolicyContext,
	}
	logger.SmPolicyLog.Tracef("SMPolicy smPolicyID[%s] GET", smPolicyID)
	return response, nil
}

// SmPoliciessmPolicyIDUpdatePost -
func HandleUpdateSmPolicyContextRequest(request *httpwrapper.Request) *httpwrapper.Response {
	// step 1: log
	logger.SmPolicyLog.Infof("Handle UpdateSmPolicyContext")

	// step 2: retrieve request
	requestDataType := request.Body.(models.SmPolicyUpdateContextData)
	smPolicyID := request.Params["smPolicyId"]

	// step 3: handle the message
	response, problemDetails := updateSmPolicyContextProcedure(requestDataType, smPolicyID)

	// step 4: process the return value from step 3
	if response != nil {
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func updateSmPolicyContextProcedure(request models.SmPolicyUpdateContextData, smPolicyID string) (
	response *models.SmPolicyDecision, problemDetails *models.ProblemDetails,
) {
	logger.SmPolicyLog.Traceln("Handle updateSmPolicyContext")

	ue := pcf_context.GetSelf().PCFUeFindByPolicyId(smPolicyID)
	if ue == nil || ue.SmPolicyData[smPolicyID] == nil {
		problemDetail := util.GetProblemDetail("smPolicyID not found in PCF", util.CONTEXT_NOT_FOUND)
		logger.SmPolicyLog.Warnf(problemDetail.Detail)
		return nil, &problemDetail
	}
	smPolicy := ue.SmPolicyData[smPolicyID]
	smPolicyDecision := smPolicy.PolicyDecision
	smPolicyContext := smPolicy.PolicyContext
	errCause := ""

	// For App Session Notification
	afEventsNotification := models.EventsNotification{}
	for _, trigger := range request.RepPolicyCtrlReqTriggers {
		switch trigger {
		case models.PolicyControlRequestTrigger_PLMN_CH: // PLMN Change
			if request.ServingNetwork == nil {
				errCause = "Serving Network is nil in Trigger PLMN_CH"
				break
			}
			smPolicyContext.ServingNetwork = request.ServingNetwork
			afEventsNotification.PlmnId = &models.PlmnId{
				Mcc: request.ServingNetwork.Mcc,
				Mnc: request.ServingNetwork.Mnc,
			}
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_PLMN_CHG,
			}
			afEventsNotification.EvNotifs = append(afEventsNotification.EvNotifs, afNotif)

			logger.SmPolicyLog.Tracef("SM Policy Update(%s) Successfully", trigger)
		case models.PolicyControlRequestTrigger_RES_MO_RE:
			// UE intiate resource modification to SMF (subsclause 4.2.4.17 in TS29512)
			req := request.UeInitResReq
			if req == nil {
				errCause = "UeInitResReq is nil in Trigger RES_MO_RE"
				break
			}
			switch req.RuleOp {
			case models.RuleOperation_CREATE_PCC_RULE:
				if req.ReqQos == nil || len(req.PackFiltInfo) < 1 {
					errCause = "Parameter Erroneous/Missing in Create Pcc Rule"
					break
				}
				// TODO: Packet Filters are covered by outstanding pcc rule
				id := smPolicy.PccRuleIdGenerator
				infos := util.ConvertPacketInfoToFlowInformation(req.PackFiltInfo)
				// Set PackFiltId
				for i := range infos {
					infos[i].PackFiltId = util.GetPackFiltId(smPolicy.PackFiltIdGenerator)
					smPolicy.PackFiltIdGenerator++
				}
				pccRule := util.CreatePccRule(id, req.Precedence, infos, "")
				// Add Traffic control Data
				tcData := util.CreateTcData(id, "", "")
				// TODO: ARP use real Data
				qosData := util.CreateQosData(id, req.ReqQos.Var5qi, 15)
				// TODO: Set MBR
				var err error
				// Set GBR
				qosData.GbrDl, qosData.GbrUl, err = smPolicy.DecreaseRemainGBR(req.ReqQos)
				if err != nil {
					problemDetail := util.GetProblemDetail(err.Error(), util.ERROR_TRAFFIC_MAPPING_INFO_REJECTED)
					logger.SmPolicyLog.Warnf(problemDetail.Detail)
					return nil, &problemDetail
				}
				if qosData.GbrDl != "" {
					logger.SmPolicyLog.Tracef("SM Policy Dnn[%s] Data Aggregate decrease %s and then DL GBR remain[%.2f Kbps]",
						smPolicyContext.Dnn, qosData.GbrDl, *smPolicy.RemainGbrDL)
				}
				if qosData.GbrUl != "" {
					logger.SmPolicyLog.Tracef("SM Policy Dnn[%s] Data Aggregate decrease %s and then UL GBR remain[%.2f Kbps]",
						smPolicyContext.Dnn, qosData.GbrUl, *smPolicy.RemainGbrUL)
				}
				util.SetPccRuleRelatedData(smPolicyDecision, pccRule, tcData, &qosData, nil, nil)
				// link Packet filters to PccRule
				for _, info := range infos {
					smPolicy.PackFiltMapToPccRuleId[info.PackFiltId] = pccRule.PccRuleId
				}
				smPolicy.PccRuleIdGenerator++
			case models.RuleOperation_DELETE_PCC_RULE:
				if req.PccRuleId == "" {
					errCause = "Parameter Erroneous/Missing in Create Pcc Rule"
					break
				}
				err := smPolicy.RemovePccRule(req.PccRuleId, nil)
				if err != nil {
					errCause = err.Error()
				}
			case models.RuleOperation_MODIFY_PCC_RULE_AND_ADD_PACKET_FILTERS,
				models.RuleOperation_MODIFY_PCC_RULE_AND_REPLACE_PACKET_FILTERS,
				models.RuleOperation_MODIFY_PCC_RULE_AND_DELETE_PACKET_FILTERS,
				models.RuleOperation_MODIFY_PCC_RULE_WITHOUT_MODIFY_PACKET_FILTERS:
				if req.PccRuleId == "" ||
					(req.RuleOp != models.RuleOperation_MODIFY_PCC_RULE_WITHOUT_MODIFY_PACKET_FILTERS &&
						len(req.PackFiltInfo) < 1) {
					errCause = "Parameter Erroneous/Missing in Modify Pcc Rule"
					break
				}
				if rule, exist := smPolicyDecision.PccRules[req.PccRuleId]; exist {
					// Modify Qos if included
					rule.Precedence = req.Precedence
					if req.ReqQos != nil && len(rule.RefQosData) != 0 {
						qosId := rule.RefQosData[0]
						if qosData, exist := smPolicyDecision.QosDecs[qosId]; exist {
							origUl, origDl := smPolicy.IncreaseRemainGBR(qosId)
							gbrDl, gbrUl, err := smPolicy.DecreaseRemainGBR(req.ReqQos)
							if err != nil {
								smPolicy.RemainGbrDL = origDl
								smPolicy.RemainGbrUL = origUl
								problemDetail := util.GetProblemDetail(err.Error(), util.ERROR_TRAFFIC_MAPPING_INFO_REJECTED)
								logger.SmPolicyLog.Warnf(problemDetail.Detail)
								return nil, &problemDetail
							}
							qosData.Var5qi = req.ReqQos.Var5qi
							qosData.GbrDl = gbrDl
							qosData.GbrUl = gbrUl
							if qosData.GbrDl != "" {
								logger.SmPolicyLog.Tracef("SM Policy Dnn[%s] Data Aggregate decrease %s and then DL GBR remain[%.2f Kbps]",
									smPolicyContext.Dnn, qosData.GbrDl, *smPolicy.RemainGbrDL)
							}
							if qosData.GbrUl != "" {
								logger.SmPolicyLog.Tracef("SM Policy Dnn[%s] Data Aggregate decrease %s and then UL GBR remain[%.2f Kbps]",
									smPolicyContext.Dnn, qosData.GbrUl, *smPolicy.RemainGbrUL)
							}
							smPolicyDecision.QosDecs[qosId] = qosData
						} else {
							errCause = "Parameter Erroneous/Missing in Modify Pcc Rule"
							break
						}
					}
					infos := util.ConvertPacketInfoToFlowInformation(req.PackFiltInfo)
					switch req.RuleOp {
					case models.RuleOperation_MODIFY_PCC_RULE_AND_ADD_PACKET_FILTERS:
						// Set PackFiltId
						for i := range infos {
							infos[i].PackFiltId = util.GetPackFiltId(smPolicy.PackFiltIdGenerator)
							smPolicy.PackFiltMapToPccRuleId[infos[i].PackFiltId] = req.PccRuleId
							smPolicy.PackFiltIdGenerator++
						}
						rule.FlowInfos = append(rule.FlowInfos, infos...)
					case models.RuleOperation_MODIFY_PCC_RULE_AND_REPLACE_PACKET_FILTERS:
						// Replace all Packet Filters
						for _, info := range rule.FlowInfos {
							delete(smPolicy.PackFiltMapToPccRuleId, info.PackFiltId)
						}
						// Set PackFiltId
						for i := range infos {
							infos[i].PackFiltId = util.GetPackFiltId(smPolicy.PackFiltIdGenerator)
							smPolicy.PackFiltMapToPccRuleId[infos[i].PackFiltId] = req.PccRuleId
							smPolicy.PackFiltIdGenerator++
						}
						rule.FlowInfos = infos
					case models.RuleOperation_MODIFY_PCC_RULE_AND_DELETE_PACKET_FILTERS:
						removeId := make(map[string]bool)
						for _, info := range infos {
							delete(smPolicy.PackFiltMapToPccRuleId, info.PackFiltId)
							removeId[info.PackFiltId] = true
						}
						result := []models.FlowInformation{}
						for _, info := range rule.FlowInfos {
							if _, exist := removeId[info.PackFiltId]; !exist {
								result = append(result, info)
							}
						}
						rule.FlowInfos = result
					}
					smPolicyDecision.PccRules[req.PccRuleId] = rule
				} else {
					errCause = fmt.Sprintf("Can't find the pccRuleId[%s] in Session[%d]", req.PccRuleId, smPolicyContext.PduSessionId)
				}
			}

		case models.PolicyControlRequestTrigger_AC_TY_CH: // UE Access Type Change (subsclause 4.2.4.8 in TS29512)
			if request.AccessType == "" {
				errCause = "Access Type is empty in Trigger AC_TY_CH"
				break
			}
			// if request.AccessType == models.AccessType__3_GPP_ACCESS && smPolicyContext.Var3gppPsDataOffStatus {
			// TODO: Handle Data off Status
			// Block Session Service except for Exempt Serice which is described in TS22011, TS 23221
			// }
			smPolicyContext.AccessType = request.AccessType
			afEventsNotification.AccessType = request.AccessType
			if request.RatType != "" {
				smPolicyContext.RatType = request.RatType
				afEventsNotification.RatType = request.RatType
			}
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_ACCESS_TYPE_CHANGE,
			}
			afEventsNotification.EvNotifs = append(afEventsNotification.EvNotifs, afNotif)
			logger.SmPolicyLog.Tracef("SM Policy Update(%s) Successfully", trigger)
		case models.PolicyControlRequestTrigger_UE_IP_CH: // SMF notice PCF "ipv4Address" & ipv6AddressPrefix (always)
			// TODO: Decide new Session Rule / Pcc rule
			if request.RelIpv4Address == smPolicyContext.Ipv4Address {
				smPolicyContext.Ipv4Address = ""
			}
			if request.RelIpv6AddressPrefix == smPolicyContext.Ipv6AddressPrefix {
				smPolicyContext.Ipv6AddressPrefix = ""
			}
			if request.Ipv4Address != "" {
				smPolicyContext.Ipv4Address = request.Ipv4Address
			}
			if request.Ipv6AddressPrefix != "" {
				smPolicyContext.Ipv6AddressPrefix = request.Ipv6AddressPrefix
			}
			logger.SmPolicyLog.Tracef("SM Policy Update(%s) Successfully", trigger)
		case models.PolicyControlRequestTrigger_UE_MAC_CH: // SMF notice PCF when SMF detect new UE MAC
		case models.PolicyControlRequestTrigger_AN_CH_COR:
		// Access Network Charging Correlation Info (subsclause 4.2.6.5.1, 4.2.4.13 in TS29512)
		// request.AccNetChIds
		case models.PolicyControlRequestTrigger_US_RE: // UMC (subsclause 4.2.4.10, 5.8 in TS29512)
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_USAGE_REPORT,
			}
			afEventsNotification.EvNotifs = append(afEventsNotification.EvNotifs, afNotif)
		case models.PolicyControlRequestTrigger_APP_STA: // ADC (subsclause 4.2.4.6, 5.8 in TS29512)
			// request.AppDetectionInfos
		case models.PolicyControlRequestTrigger_APP_STO: // ADC (subsclause 4.2.4.6, 5.8 in TS29512)
			// request.AppDetectionInfos
		case models.PolicyControlRequestTrigger_AN_INFO: // NetLoc (subsclause 4.2.4.9, 5.8 in TS29512)
		case models.PolicyControlRequestTrigger_CM_SES_FAIL: // Credit Management Session Failure
			// request.CreditManageStatus
		case models.PolicyControlRequestTrigger_PS_DA_OFF:
			// 3GPP PS Data Off status changed (subsclause 4.2.4.8, 5.8 in TS29512) (always)
			if smPolicyContext.Var3gppPsDataOffStatus != request.Var3gppPsDataOffStatus {
				// TODO: Handle Data off Status
				// if request.Var3gppPsDataOffStatus {
				// Block Session Service except for Exempt Serice which is described in TS22011, TS 23221
				// } else {
				// UnBlock Session Service
				// }
				smPolicyContext.Var3gppPsDataOffStatus = request.Var3gppPsDataOffStatus
			}
		case models.PolicyControlRequestTrigger_DEF_QOS_CH:
			// Default QoS Change (subsclause 4.2.4.5 in TS29512) (always)
			if request.SubsDefQos == nil {
				errCause = "SubsDefQos  is nil in Trigger DEF_QOS_CH"
				break
			}
			smPolicyContext.SubsDefQos = request.SubsDefQos
			sessRuleId := fmt.Sprintf("SessRuleId-%d", smPolicyContext.PduSessionId)
			if smPolicyDecision.SessRules[sessRuleId].AuthDefQos == nil {
				tmp := smPolicyDecision.SessRules[sessRuleId]
				tmp.AuthDefQos = new(models.AuthorizedDefaultQos)
				smPolicyDecision.SessRules[sessRuleId] = tmp
			}
			authQos := smPolicyDecision.SessRules[sessRuleId].AuthDefQos
			authQos.Var5qi = request.SubsDefQos.Var5qi
			authQos.Arp = request.SubsDefQos.Arp
			authQos.PriorityLevel = request.SubsDefQos.PriorityLevel
			logger.SmPolicyLog.Tracef("SM Policy Update(%s) Successfully", trigger)
		case models.PolicyControlRequestTrigger_SE_AMBR_CH: // Session Ambr Change (subsclause 4.2.4.4 in TS29512) (always)
			if request.SubsSessAmbr == nil {
				errCause = "SubsSessAmbr  is nil in Trigger SE_AMBR_CH"
				break
			}
			smPolicyContext.SubsSessAmbr = request.SubsSessAmbr
			sessRuleId := fmt.Sprintf("SessRuleId-%d", smPolicyContext.PduSessionId)
			if smPolicyDecision.SessRules[sessRuleId].AuthSessAmbr == nil {
				tmp := smPolicyDecision.SessRules[sessRuleId]
				tmp.AuthSessAmbr = new(models.Ambr)
				smPolicyDecision.SessRules[sessRuleId] = tmp
			}
			*smPolicyDecision.SessRules[sessRuleId].AuthSessAmbr = *request.SubsSessAmbr
			logger.SmPolicyLog.Tracef("SM Policy Update(%s) Successfully", trigger)
		case models.PolicyControlRequestTrigger_QOS_NOTIF:
			// SMF notify PCF when receiving from RAN that QoS can/can't be guaranteed (subsclause 4.2.4.20 in TS29512) (always)
			// request.QncReports
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_QOS_NOTIF,
			}
			afEventsNotification.EvNotifs = append(afEventsNotification.EvNotifs, afNotif)
			afEventsNotification.QncReports = request.QncReports
		case models.PolicyControlRequestTrigger_NO_CREDIT: // Out of Credit
		case models.PolicyControlRequestTrigger_PRA_CH: // Presence Reporting (subsclause 4.2.6.5.6, 4.2.4.16, 5.8 in TS29512)
			// request.RepPraInfos
		case models.PolicyControlRequestTrigger_SAREA_CH: // Change Of Service Area
			if request.UserLocationInfo == nil {
				errCause = "UserLocationInfo  is nil in Trigger SAREA_CH"
				break
			}
			smPolicyContext.UserLocationInfo = request.UserLocationInfo
			logger.SmPolicyLog.Tracef("SM Policy Update(%s) Successfully", trigger)
		case models.PolicyControlRequestTrigger_SCNN_CH: // Change of Serving Network Function
			if request.ServNfId == nil {
				errCause = "ServNfId  is nil in Trigger SCNN_CH"
				break
			}
			smPolicyContext.ServNfId = request.ServNfId
			logger.SmPolicyLog.Tracef("SM Policy Update(%s) Successfully", trigger)
		case models.PolicyControlRequestTrigger_RE_TIMEOUT: // Revalidation TimeOut (subsclause 4.2.4.13 in TS29512)
			// formatTimeStr := time.Now()
			// formatTimeStr = formatTimeStr.Add(time.Second * 60)
			// formatTimeStrAdd := formatTimeStr.Format(pcf_context.GetTimeformat())
			// formatTime, err := time.Parse(pcf_context.GetTimeformat(), formatTimeStrAdd)
			// if err == nil {
			// 	smPolicyDecision.RevalidationTime = &formatTime
			// }
		case models.PolicyControlRequestTrigger_RES_RELEASE:
			// Outcome of request Pcc rule removal (subsclause 4.2.6.5.2, 5.8 in TS29512)
		case models.PolicyControlRequestTrigger_SUCC_RES_ALLO:
			// Successful resource allocation (subsclause 4.2.6.5.5, 4.2.4.14 in TS29512)
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_SUCCESSFUL_RESOURCES_ALLOCATION,
			}
			afEventsNotification.EvNotifs = append(afEventsNotification.EvNotifs, afNotif)
		case models.PolicyControlRequestTrigger_RAT_TY_CH: // Change of RatType
			if request.RatType == "" {
				errCause = "RatType is empty in Trigger RAT_TY_CH"
				break
			}
			smPolicyContext.RatType = request.RatType
			logger.SmPolicyLog.Tracef("SM Policy Update(%s) Successfully", trigger)
		case models.PolicyControlRequestTrigger_REF_QOS_IND_CH: // Change of reflective Qos Indication from UE
			smPolicyContext.RefQosIndication = request.RefQosIndication
			// TODO: modify Decision about RefQos in Pcc rule
			logger.SmPolicyLog.Tracef("SM Policy Update(%s) Successfully", trigger)
		case models.PolicyControlRequestTrigger_NUM_OF_PACKET_FILTER: // Interworking Only (always)
		case models.PolicyControlRequestTrigger_UE_STATUS_RESUME: // UE State Resume
			// TODO
		case models.PolicyControlRequestTrigger_UE_TZ_CH: // UE TimeZome Change
			if request.UeTimeZone == "" {
				errCause = "Ue TimeZone is empty in Trigger UE_TZ_CH"
				break
			}
			smPolicyContext.UeTimeZone = request.UeTimeZone
			logger.SmPolicyLog.Tracef("SM Policy Update(%s) Successfully", trigger)
		}
	}

	var successRules, failRules []models.RuleReport
	for _, rule := range request.RuleReports {
		if rule.RuleStatus == models.RuleStatus_ACTIVE {
			successRules = append(successRules, rule)
		} else {
			failRules = append(failRules, rule)
			// release fail pccRules in SmPolicy
			for _, pccRuleID := range rule.PccRuleIds {
				if err := smPolicy.RemovePccRule(pccRuleID, nil); err != nil {
					logger.SmPolicyLog.Warnf(
						"SM Policy Notification about failed installing PccRule[%s]", err.Error())
				}
			}
		}
	}
	if len(failRules) > 0 {
		afNotif := models.AfEventNotification{
			Event: models.AfEvent_FAILED_RESOURCES_ALLOCATION,
		}
		afEventsNotification.EvNotifs = append(afEventsNotification.EvNotifs, afNotif)
	}
	if afEventsNotification.EvNotifs != nil {
		sendSmPolicyRelatedAppSessionNotification(
			smPolicy, afEventsNotification, request.AccuUsageReports, successRules, failRules)
	}

	if errCause != "" {
		problemDetail := util.GetProblemDetail(errCause, util.ERROR_TRIGGER_EVENT)
		logger.SmPolicyLog.Warnf(errCause)
		return nil, &problemDetail
	}
	logger.SmPolicyLog.Tracef("SMPolicy smPolicyID[%s] Update", smPolicyID)
	// message.SendHttpResponseMessage(httpChannel, nil, http.StatusOK, *smPolicyDecision)
	return smPolicyDecision, nil
}

func sendSmPolicyRelatedAppSessionNotification(smPolicy *pcf_context.UeSmPolicyData,
	notification models.EventsNotification, usageReports []models.AccuUsageReport,
	successRules, failRules []models.RuleReport,
) {
	for appSessionId := range smPolicy.AppSessions {
		if val, exist := pcf_context.GetSelf().AppSessionPool.Load(appSessionId); exist {
			appSession := val.(*pcf_context.AppSessionData)
			if len(appSession.Events) == 0 {
				continue
			}
			sessionNotif := models.EventsNotification{}
			for _, notif := range notification.EvNotifs {
				if _, found := appSession.Events[notif.Event]; found {
					switch notif.Event {
					case models.AfEvent_ACCESS_TYPE_CHANGE:
						sessionNotif.AccessType = notification.AccessType
						sessionNotif.RatType = notification.RatType
					case models.AfEvent_FAILED_RESOURCES_ALLOCATION:
						failItem := models.ResourcesAllocationInfo{
							McResourcStatus: models.MediaComponentResourcesStatus_INACTIVE,
						}
						flows := make(map[int32]models.Flows)
						for _, report := range failRules {
							for _, pccRuleId := range report.PccRuleIds {
								if key, exist := appSession.PccRuleIdMapToCompId[pccRuleId]; exist {
									items := strings.Split(key, "-")
									if items[0] != "appId" {
										compN, err := strconv.Atoi(items[0])
										if err != nil {
											logger.SmPolicyLog.Errorf("strconv Atoi error %+v", err)
										}
										compN32 := int32(compN)
										if len(items) == 1 {
											// Comp
											flow := models.Flows{
												MedCompN: compN32,
											}
											failItem.Flows = append(failItem.Flows, flow)
										} else if len(items) == 2 {
											// have subComp
											fNum, err := strconv.Atoi(items[1])
											if err != nil {
												logger.SmPolicyLog.Errorf("strconv Atoi error %+v", err)
											}
											fNum32 := int32(fNum)

											flow, exist := flows[compN32]
											if !exist {
												flow = models.Flows{
													MedCompN: compN32,
													FNums:    []int32{fNum32},
												}
											} else {
												flow.FNums = append(flow.FNums, fNum32)
											}
											flows[compN32] = flow
										}
									}
									// Release related resource
									delete(appSession.PccRuleIdMapToCompId, pccRuleId)
									delete(appSession.RelatedPccRuleIds, key)
								}
							}
						}
						for _, flow := range flows {
							failItem.Flows = append(failItem.Flows, flow)
						}
						if failItem.Flows != nil {
							sessionNotif.FailedResourcAllocReports = append(sessionNotif.FailedResourcAllocReports, failItem)
						} else {
							continue
						}
					case models.AfEvent_PLMN_CHG:
						sessionNotif.PlmnId = notification.PlmnId
					case models.AfEvent_QOS_NOTIF:
						for _, report := range sessionNotif.QncReports {
							for _, pccRuleId := range report.RefPccRuleIds {
								if _, exist := appSession.PccRuleIdMapToCompId[pccRuleId]; exist {
									sessionNotif.QncReports = append(sessionNotif.QncReports, report)
									break
								}
							}
						}
						if sessionNotif.QncReports == nil {
							continue
						}
					case models.AfEvent_SUCCESSFUL_RESOURCES_ALLOCATION:
						// Subscription to resources allocation outcome
						if successRules == nil {
							continue
						}
						flows := make(map[int32]models.Flows)
						for _, report := range successRules {
							for _, pccRuleId := range report.PccRuleIds {
								if key, exist := appSession.PccRuleIdMapToCompId[pccRuleId]; exist {
									items := strings.Split(key, "-")
									if items[0] != "appId" {
										compN, err := strconv.Atoi(items[0])
										if err != nil {
											logger.SmPolicyLog.Errorf("strconv Atoi error %+v", err)
										}
										compN32 := int32(compN)
										if len(items) == 1 {
											// Comp
											flow := models.Flows{
												MedCompN: compN32,
											}
											notif.Flows = append(notif.Flows, flow)
										} else if len(items) == 2 {
											// have subComp
											fNum, err := strconv.Atoi(items[1])
											if err != nil {
												logger.SmPolicyLog.Errorf("strconv Atoi error %+v", err)
											}
											fNum32 := int32(fNum)
											flow, exist := flows[compN32]
											if !exist {
												flow = models.Flows{
													MedCompN: compN32,
													FNums:    []int32{fNum32},
												}
											} else {
												flow.FNums = append(flow.FNums, fNum32)
											}
											flows[compN32] = flow
										}
									}
								}
							}
						}
						for _, flow := range flows {
							notif.Flows = append(notif.Flows, flow)
						}
						if notif.Flows == nil {
							continue
						}
					case models.AfEvent_USAGE_REPORT:
						for _, report := range usageReports {
							for _, pccRuleId := range appSession.RelatedPccRuleIds {
								if pccRule, exist := appSession.SmPolicyData.PolicyDecision.PccRules[pccRuleId]; exist {
									if pccRule.RefUmData != nil && pccRule.RefUmData[0] == report.RefUmIds {
										sessionNotif.UsgRep = &models.AccumulatedUsage{
											Duration:       report.TimeUsage,
											TotalVolume:    report.VolUsage,
											UplinkVolume:   report.VolUsageUplink,
											DownlinkVolume: report.VolUsageDownlink,
										}
										break
									}
								}
							}
							if sessionNotif.UsgRep != nil {
								sessionNotif.EvNotifs = append(sessionNotif.EvNotifs, notif)
								break
							}
						}
						fallthrough
					default:
						continue
					}
					sessionNotif.EvNotifs = append(sessionNotif.EvNotifs, notif)
				}
			}
			if sessionNotif.EvNotifs != nil {
				SendAppSessionEventNotification(appSession, sessionNotif)
			}
		}
	}
}

func SendSMPolicyUpdateNotification(
	uri string, request *models.SmPolicyNotification,
) {
	if uri == "" {
		logger.SmPolicyLog.Warnln("SM Policy Update Notification Error[uri is empty]")
		return
	}
	client := util.GetNpcfSMPolicyCallbackClient()
	logger.SmPolicyLog.Infof("Send SM Policy Update Notification to SMF")
	_, httpResponse, err := client.DefaultCallbackApi.SmPolicyUpdateNotification(context.Background(), uri, *request)
	defer func() {
		if httpResponse != nil {
			if err = httpResponse.Body.Close(); err != nil {
				logger.SmPolicyLog.Warnf(
					"failed to close response of SM Policy Update Notification")
			}
		}
	}()
	if err != nil {
		if httpResponse != nil {
			logger.SmPolicyLog.Warnf("SM Policy Update Notification Error[%s]", httpResponse.Status)
		} else {
			logger.SmPolicyLog.Warnf("SM Policy Update Notification Failed[%s]", err.Error())
		}
		return
	} else if httpResponse == nil {
		logger.SmPolicyLog.Warnln("SM Policy Update Notification Failed[HTTP Response is nil]")
		return
	}
	if httpResponse.StatusCode != http.StatusOK && httpResponse.StatusCode != http.StatusNoContent {
		logger.SmPolicyLog.Warnf("SM Policy Update Notification Failed")
	} else {
		logger.SmPolicyLog.Tracef("SM Policy Update Notification Success")
	}
}

func SendSMPolicyTerminationRequestNotification(
	uri string, request *models.TerminationNotification,
) {
	if uri == "" {
		logger.SmPolicyLog.Warnln("SM Policy Termination Request Notification Error[uri is empty]")
		return
	}
	client := util.GetNpcfSMPolicyCallbackClient()
	rsp, err := client.DefaultCallbackApi.
		SmPolicyControlTerminationRequestNotification(context.Background(), uri, *request)
	defer func() {
		if rsp != nil {
			if err = rsp.Body.Close(); err != nil {
				logger.SmPolicyLog.Warnf(
					"failed to close response of SM Policy Termination Request notification")
			}
		}
	}()
	if err != nil {
		if rsp != nil {
			logger.AmPolicyLog.Warnf("SM Policy Termination Request Notification Error[%s]", rsp.Status)
		} else {
			logger.AmPolicyLog.Warnf("SM Policy Termination Request Notification Error[%s]", err.Error())
		}
		return
	} else if rsp == nil {
		logger.AmPolicyLog.Warnln("SM Policy Termination Request Notification Error[HTTP Response is nil]")
		return
	}
	if rsp.StatusCode != http.StatusNoContent {
		logger.SmPolicyLog.Warnf("SM Policy Termination Request Notification  Failed")
	} else {
		logger.SmPolicyLog.Tracef("SM Policy Termination Request Notification Success")
	}
}
