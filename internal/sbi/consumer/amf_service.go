package consumer

import (
	"fmt"
	"strings"
	"sync"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Namf_Communication"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/pkg/factory"
)

type namfService struct {
	consumer *Consumer

	nfComMu sync.RWMutex

	nfComClients map[string]*Namf_Communication.APIClient
}

func (s *namfService) getNFCommunicationClient(uri string) *Namf_Communication.APIClient {
	if uri == "" {
		return nil
	}
	s.nfComMu.RLock()
	client, ok := s.nfComClients[uri]
	if ok {
		defer s.nfComMu.RUnlock()
		return client
	}

	configuration := Namf_Communication.NewConfiguration()
	configuration.SetBasePath(uri)
	client = Namf_Communication.NewAPIClient(configuration)

	s.nfComMu.RUnlock()
	s.nfComMu.Lock()
	defer s.nfComMu.Unlock()
	s.nfComClients[uri] = client
	return client
}

func (s *namfService) AmfStatusChangeSubscribe(amfUri string, guamiList []models.Guami) (
	problemDetails *models.ProblemDetails, err error,
) {
	logger.ConsumerLog.Debugf("PCF Subscribe to AMF status[%+v]", amfUri)
	pcfContext := s.consumer.pcf.Context()

	// Set client and set url
	client := s.getNFCommunicationClient(amfUri)

	subscriptionData := models.SubscriptionData{
		AmfStatusUri: fmt.Sprintf("%s"+factory.PcfCallbackResUriPrefix+"/amfstatus", pcfContext.GetIPv4Uri()),
		GuamiList:    guamiList,
	}
	ctx, pd, err := pcfContext.GetTokenCtx(models.ServiceName_NAMF_COMM, models.NfType_AMF)
	if err != nil {
		return pd, err
	}
	res, httpResp, localErr := client.SubscriptionsCollectionDocumentApi.AMFStatusChangeSubscribe(
		ctx, subscriptionData)
	defer func() {
		if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
			logger.ConsumerLog.Errorf("AMFStatusChangeSubscribe response body cannot close: %+v",
				rspCloseErr)
		}
	}()
	if localErr == nil {
		locationHeader := httpResp.Header.Get("Location")
		logger.ConsumerLog.Debugf("location header: %+v", locationHeader)

		subscriptionID := locationHeader[strings.LastIndex(locationHeader, "/")+1:]
		amfStatusSubsData := pcf_context.AMFStatusSubscriptionData{
			AmfUri:       amfUri,
			AmfStatusUri: res.AmfStatusUri,
			GuamiList:    res.GuamiList,
		}
		pcfContext.NewAmfStatusSubscription(subscriptionID, amfStatusSubsData)
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return nil, err
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("%s: server no response", amfUri)
	}
	return problemDetails, err
}
