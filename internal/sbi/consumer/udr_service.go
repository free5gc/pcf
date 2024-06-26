package consumer

import (
	"strconv"
	"strings"
	"sync"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nudr_DataRepository"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/util"
)

type nudrService struct {
	consumer *Consumer

	nfDataSubMu sync.RWMutex

	nfDataSubClients map[string]*Nudr_DataRepository.APIClient
}

func (s *nudrService) getDataSubscription(uri string) *Nudr_DataRepository.APIClient {
	if uri == "" {
		return nil
	}
	s.nfDataSubMu.RLock()
	client, ok := s.nfDataSubClients[uri]
	if ok {
		defer s.nfDataSubMu.RUnlock()
		return client
	}

	configuration := Nudr_DataRepository.NewConfiguration()
	configuration.SetBasePath(uri)
	client = Nudr_DataRepository.NewAPIClient(configuration)

	s.nfDataSubMu.RUnlock()
	s.nfDataSubMu.Lock()
	defer s.nfDataSubMu.Unlock()
	s.nfDataSubClients[uri] = client
	return client
}

func (s *nudrService) CreateInfluenceDataSubscription(ue *pcf_context.UeContext, request models.SmPolicyContextData) (
	subscriptionID string, problemDetails *models.ProblemDetails, err error,
) {
	if ue.UdrUri == "" {
		problemDetail := util.GetProblemDetail("Can't find corresponding UDR with UE", util.USER_UNKNOWN)
		logger.ConsumerLog.Warnf("Can't find corresponding UDR with UE[%s]", ue.Supi)
		return "", &problemDetail, nil
	}
	ctx, pd, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NfType_UDR)
	if err != nil {
		return "", pd, err
	}
	client := s.getDataSubscription(ue.UdrUri)
	trafficInfluSub := s.buildTrafficInfluSub(request)
	_, httpResp, localErr := client.InfluenceDataSubscriptionsCollectionApi.
		ApplicationDataInfluenceDataSubsToNotifyPost(ctx, trafficInfluSub)
	if localErr == nil {
		locationHeader := httpResp.Header.Get("Location")
		subscriptionID = locationHeader[strings.LastIndex(locationHeader, "/")+1:]
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
			return subscriptionID, problemDetails, err
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}
	return "", problemDetails, err
}

func (s *nudrService) buildTrafficInfluSub(request models.SmPolicyContextData) models.TrafficInfluSub {
	trafficInfluSub := models.TrafficInfluSub{
		Dnns:             []string{request.Dnn},
		Snssais:          []models.Snssai{*request.SliceInfo},
		InternalGroupIds: request.InterGrpIds,
		Supis:            []string{request.Supi},
		NotificationUri: s.consumer.Context().GetIPv4Uri() +
			pcf_context.InfluenceDataUpdateNotifyUri + "/" +
			request.Supi + "/" + strconv.Itoa(int(request.PduSessionId)),
		// TODO: support expiry time and resend subscription when expired
	}
	return trafficInfluSub
}

func (s *nudrService) RemoveInfluenceDataSubscription(ue *pcf_context.UeContext, subscriptionID string) (
	problemDetails *models.ProblemDetails, err error,
) {
	if ue.UdrUri == "" {
		problemDetail := util.GetProblemDetail("Can't find corresponding UDR with UE", util.USER_UNKNOWN)
		logger.ConsumerLog.Warnf("Can't find corresponding UDR with UE[%s]", ue.Supi)
		return &problemDetail, nil
	}
	ctx, pd, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NfType_UDR)
	if err != nil {
		return pd, err
	}
	client := s.getDataSubscription(ue.UdrUri)
	httpResp, localErr := client.IndividualInfluenceDataSubscriptionDocumentApi.
		ApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete(ctx, subscriptionID)
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
			return problemDetails, err
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}
	return problemDetails, err
}
