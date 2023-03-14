package consumer

import (
	"context"
	"strconv"
	"strings"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/util"
)

func CreateInfluenceDataSubscription(ue *pcf_context.UeContext, request models.SmPolicyContextData) (
	subscriptionID string, problemDetails *models.ProblemDetails, err error,
) {
	if ue.UdrUri == "" {
		problemDetail := util.GetProblemDetail("Can't find corresponding UDR with UE", util.USER_UNKNOWN)
		logger.ConsumerLog.Warnf("Can't find corresponding UDR with UE[%s]", ue.Supi)
		return "", &problemDetail, nil
	}
	udrClient := util.GetNudrClient(ue.UdrUri)
	trafficInfluSub := buildTrafficInfluSub(request)
	_, httpResp, localErr := udrClient.InfluenceDataSubscriptionsCollectionApi.
		ApplicationDataInfluenceDataSubsToNotifyPost(context.Background(), trafficInfluSub)
	if localErr == nil {
		locationHeader := httpResp.Header.Get("Location")
		subscriptionID := locationHeader[strings.LastIndex(locationHeader, "/")+1:]
		logger.ConsumerLog.Debugf("Influence Data Subscription ID: %s", subscriptionID)
		return subscriptionID, nil, nil
	} else if httpResp != nil {
		defer func() {
			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("CreateInfluenceDataSubscription response body cannot close: %+v",
					rspCloseErr)
			}
		}()
		if httpResp.Status != localErr.Error() {
			err = localErr
			return
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}
	return "", problemDetails, err
}

func buildTrafficInfluSub(request models.SmPolicyContextData) models.TrafficInfluSub {
	trafficInfluSub := models.TrafficInfluSub{
		Dnns:             []string{request.Dnn},
		Snssais:          []models.Snssai{*request.SliceInfo},
		InternalGroupIds: request.InterGrpIds,
		Supis:            []string{request.Supi},
		NotificationUri: pcf_context.GetSelf().GetIPv4Uri() +
			pcf_context.InfluenceDataUpdateNotifyUri + "/" +
			request.Supi + "/" + strconv.Itoa(int(request.PduSessionId)),
		// TODO: support expiry time and resend subscription when expired
	}
	return trafficInfluSub
}

func RemoveInfluenceDataSubscription(ue *pcf_context.UeContext, subscriptionID string) (
	problemDetails *models.ProblemDetails, err error,
) {
	if ue.UdrUri == "" {
		problemDetail := util.GetProblemDetail("Can't find corresponding UDR with UE", util.USER_UNKNOWN)
		logger.ConsumerLog.Warnf("Can't find corresponding UDR with UE[%s]", ue.Supi)
		return &problemDetail, nil
	}
	udrClient := util.GetNudrClient(ue.UdrUri)
	httpResp, localErr := udrClient.IndividualInfluenceDataSubscriptionDocumentApi.
		ApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete(context.Background(), subscriptionID)
	if localErr == nil {
		logger.ConsumerLog.Debugf("Nudr_DataRepository Remove Influence Data Subscription Status %s",
			httpResp.Status)
	} else if httpResp != nil {
		defer func() {
			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("RemoveInfluenceDataSubscription response body cannot close: %+v",
					rspCloseErr)
			}
		}()
		if httpResp.Status != localErr.Error() {
			err = localErr
			return
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}
	return problemDetails, err
}
