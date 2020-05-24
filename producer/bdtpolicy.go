package pcf_producer

import (
	"context"
	"fmt"
	"free5gc/lib/openapi/Nnrf_NFDiscovery"
	"free5gc/lib/openapi/Nudr_DataRepository"
	"free5gc/lib/openapi/models"
	"free5gc/src/pcf/consumer"
	pcf_context "free5gc/src/pcf/context"
	"free5gc/src/pcf/handler/message"
	"free5gc/src/pcf/logger"
	"free5gc/src/pcf/util"
	"net/http"

	"github.com/google/uuid"
	"github.com/mohae/deepcopy"

	"github.com/antihax/optional"
)

func GetBDTPolicyContext(httpChannel chan message.HttpResponseMessage, bdtPolicyId string) {

	logger.Bdtpolicylog.Traceln("Handle BDT Policy GET")
	// check BdtPolicyId from pcfUeContext
	bdtPolicy, exist := pcf_context.PCF_Self().BdtPolicyPool[bdtPolicyId]
	if !exist {
		// not found
		rsp := util.GetProblemDetail("Can't find BDTPolicyId related resource", util.CONTEXT_NOT_FOUND)
		logger.Bdtpolicylog.Warnf(rsp.Detail)
		message.SendHttpResponseMessage(httpChannel, nil, int(rsp.Status), rsp)
		return
	}
	message.SendHttpResponseMessage(httpChannel, nil, http.StatusOK, bdtPolicy)

}

// UpdateBDTPolicy - Update an Individual BDT policy (choose policy data)
func UpdateBDTPolicyContext(httpChannel chan message.HttpResponseMessage, bdtPolicyId string, request models.BdtPolicyDataPatch) {

	logger.Bdtpolicylog.Traceln("Handle BDT Policy Update")
	// check BdtPolicyId from pcfUeContext
	pcfSelf := pcf_context.PCF_Self()
	bdtPolicy, exist := pcfSelf.BdtPolicyPool[bdtPolicyId]
	if !exist {
		// not found
		rsp := util.GetProblemDetail("Can't find BDTPolicyId related resource", util.CONTEXT_NOT_FOUND)
		logger.Bdtpolicylog.Warnf(rsp.Detail)
		message.SendHttpResponseMessage(httpChannel, nil, int(rsp.Status), rsp)
		return
	}
	for _, policy := range bdtPolicy.BdtPolData.TransfPolicies {
		if policy.TransPolicyId == request.SelTransPolicyId {
			polData := bdtPolicy.BdtPolData
			polReq := bdtPolicy.BdtReqData
			polData.SelTransPolicyId = request.SelTransPolicyId
			bdtData := models.BdtData{
				AspId:       polReq.AspId,
				TransPolicy: policy,
				BdtRefId:    polData.BdtRefId,
			}
			if polReq.NwAreaInfo != nil {
				bdtData.NwAreaInfo = *polReq.NwAreaInfo
			}
			param := Nudr_DataRepository.PolicyDataBdtDataBdtReferenceIdPutParamOpts{
				BdtData: optional.NewInterface(bdtData),
			}
			client := util.GetNudrClient(getDefaultUdrUri(pcfSelf))
			_, err := client.DefaultApi.PolicyDataBdtDataBdtReferenceIdPut(context.Background(), bdtData.BdtRefId, &param)
			if err != nil {
				logger.Bdtpolicylog.Warnf("UDR Put BdtDate error[%s]", err.Error())
			}
			logger.Bdtpolicylog.Tracef("BDTPolicyId[%s] has Updated with SelTransPolicyId[%d]", bdtPolicyId, request.SelTransPolicyId)
			message.SendHttpResponseMessage(httpChannel, nil, http.StatusOK, bdtPolicy)
			return
		}
	}
	rsp := util.GetProblemDetail(fmt.Sprintf("Can't find TransPolicyId[%d] in TransfPolicies with BDTPolicyId[%s]", request.SelTransPolicyId, bdtPolicyId), util.CONTEXT_NOT_FOUND)
	logger.Bdtpolicylog.Warnf(rsp.Detail)
	message.SendHttpResponseMessage(httpChannel, nil, int(rsp.Status), rsp)
}

//CreateBDTPolicy - Create a new Individual BDT policy
func CreateBDTPolicyContext(httpChannel chan message.HttpResponseMessage, request models.BdtReqData) {
	var rsp models.BdtPolicy

	logger.Bdtpolicylog.Traceln("Handle BDT Policy Create")

	pcfSelf := pcf_context.PCF_Self()
	udrUri := getDefaultUdrUri(pcfSelf)
	if udrUri == "" {
		// Can't find any UDR support this Ue
		rsp := models.ProblemDetails{
			Status: http.StatusServiceUnavailable,
			Detail: "Can't find any UDR which supported to this PCF",
		}
		logger.Bdtpolicylog.Warnf(rsp.Detail)
		message.SendHttpResponseMessage(httpChannel, nil, int(rsp.Status), rsp)
		return
	}
	pcfSelf.DefaultUdrUri = udrUri

	// Query BDT DATA array from UDR
	client := util.GetNudrClient(udrUri)
	bdtDatas, response, err := client.DefaultApi.PolicyDataBdtDataGet(context.Background())
	if err != nil || response == nil || response.StatusCode != http.StatusOK {
		rsp := models.ProblemDetails{
			Status: http.StatusServiceUnavailable,
			Detail: "Query to UDR failed",
		}
		logger.Bdtpolicylog.Warnf("Query to UDR failed")
		message.SendHttpResponseMessage(httpChannel, nil, int(rsp.Status), rsp)
		return
	}
	// TODO: decide BDT Policy from other bdt policy data
	rsp.BdtReqData = deepcopy.Copy(&request).(*models.BdtReqData)
	var bdtData *models.BdtData
	var bdtPolicyData models.BdtPolicyData
	for _, data := range bdtDatas {
		// If ASP has exist, use its background data policy
		if request.AspId == data.AspId {
			bdtData = &data
			break
		}
	}
	// Only support one bdt policy, TODO: more policy for decision
	if bdtData != nil {
		// found
		// modify policy according to new request
		bdtData.TransPolicy.RecTimeInt = request.DesTimeInt
	} else {
		// use default bdt policy, TODO: decide bdt transfer data policy
		bdtData = &models.BdtData{
			AspId:       request.AspId,
			BdtRefId:    uuid.New().String(),
			TransPolicy: getDefaultTransferPolicy(1, *request.DesTimeInt),
		}
	}
	if request.NwAreaInfo != nil {
		bdtData.NwAreaInfo = *request.NwAreaInfo
	}
	bdtPolicyData.SelTransPolicyId = bdtData.TransPolicy.TransPolicyId
	// no support feature in subclause 5.8 of TS29554
	bdtPolicyData.BdtRefId = bdtData.BdtRefId
	bdtPolicyData.TransfPolicies = append(bdtPolicyData.TransfPolicies, bdtData.TransPolicy)
	rsp.BdtPolData = &bdtPolicyData
	bdtPolicyId := pcfSelf.AllocBdtPolicyId()
	pcfSelf.BdtPolicyPool[bdtPolicyId] = rsp

	locationHeader := util.GetResourceUri(models.ServiceName_NPCF_BDTPOLICYCONTROL, bdtPolicyId)
	headers := http.Header{
		"Location": {locationHeader},
	}
	logger.Bdtpolicylog.Tracef("BDT Policy Id[%s] Create", bdtPolicyId)
	message.SendHttpResponseMessage(httpChannel, headers, http.StatusCreated, rsp)

	// Update UDR BDT Data(PUT)
	param := Nudr_DataRepository.PolicyDataBdtDataBdtReferenceIdPutParamOpts{
		BdtData: optional.NewInterface(*bdtData),
	}
	_, err = client.DefaultApi.PolicyDataBdtDataBdtReferenceIdPut(context.Background(), bdtPolicyData.BdtRefId, &param)
	if err != nil {
		logger.Bdtpolicylog.Warnf("UDR  Put BdtDate error[%s]", err.Error())
	}
}

func getDefaultUdrUri(context *pcf_context.PCFContext) string {
	if context.DefaultUdrUri != "" {
		return context.DefaultUdrUri
	}
	param := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{
		ServiceNames: optional.NewInterface([]models.ServiceName{models.ServiceName_NUDR_DR}),
	}
	resp, err := consumer.SendSearchNFInstances(context.NrfUri, models.NfType_UDR, models.NfType_PCF, param)
	if err != nil {
		return ""
	}
	for _, nfProfile := range resp.NfInstances {
		udruri := util.SearchNFServiceUri(nfProfile, models.ServiceName_NUDR_DR, models.NfServiceStatus_REGISTERED)
		if udruri != "" {
			return udruri
		}
	}
	return ""
}

// get default background data transfer policy
func getDefaultTransferPolicy(transferPolicyId int32, timeWindow models.TimeWindow) models.TransferPolicy {
	return models.TransferPolicy{
		TransPolicyId: transferPolicyId,
		RecTimeInt:    &timeWindow,
		RatingGroup:   1,
	}
}
