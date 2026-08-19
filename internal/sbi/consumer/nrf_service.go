package consumer

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/nrf/NFDisc"
	"github.com/free5gc/openapi/nrf/NFMgmt"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/util"
	sbi_metrics "github.com/free5gc/util/metrics/sbi"
)

type nnrfService struct {
	consumer *Consumer

	nfMngmntMu sync.RWMutex
	nfDiscMu   sync.RWMutex

	nfMngmntClients map[string]*NFMgmt.APIClient
	nfDiscClients   map[string]*NFDisc.APIClient
}

func (s *nnrfService) getNFManagementClient(uri string) *NFMgmt.APIClient {
	if uri == "" {
		return nil
	}
	s.nfMngmntMu.RLock()
	client, ok := s.nfMngmntClients[uri]
	if ok {
		defer s.nfMngmntMu.RUnlock()
		return client
	}

	configuration := NFMgmt.NewConfiguration()
	configuration.SetBasePath(uri)
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = NFMgmt.NewAPIClient(configuration)

	s.nfMngmntMu.RUnlock()
	s.nfMngmntMu.Lock()
	defer s.nfMngmntMu.Unlock()
	s.nfMngmntClients[uri] = client
	return client
}

func (s *nnrfService) getNFDiscClient(uri string) *NFDisc.APIClient {
	if uri == "" {
		return nil
	}
	s.nfDiscMu.RLock()
	client, ok := s.nfDiscClients[uri]
	if ok {
		defer s.nfDiscMu.RUnlock()
		return client
	}

	configuration := NFDisc.NewConfiguration()
	configuration.SetBasePath(uri)
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = NFDisc.NewAPIClient(configuration)

	s.nfDiscMu.RUnlock()
	s.nfDiscMu.Lock()
	defer s.nfDiscMu.Unlock()
	s.nfDiscClients[uri] = client
	return client
}

func (s *nnrfService) SendSearchNFInstances(
	nrfUri string, targetNfType, requestNfType models.Nrf_NFMgmt_NFType, param NFDisc.SearchNFInstancesRequest) (
	*models.Nrf_NFDisc_SearchResult, error,
) {
	// Set client and set url
	client := s.getNFDiscClient(nrfUri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.Nrf_NFMgmt_ServiceName_NNRF_DISC, models.Nrf_NFMgmt_NFType_NRF)
	if err != nil {
		return nil, err
	}
	param.TargetNfType = &targetNfType
	param.RequesterNfType = &requestNfType
	res, err := client.NFInstancesStoreApi.SearchNFInstances(ctx, &param)
	if err != nil {
		logger.ConsumerLog.Errorf("SearchNFInstances failed: %+v", err)
		return nil, err
	}
	// The search result is a pointer in the new openapi models, so it can be
	// nil even when the call itself succeeded; callers walk NfInstances
	// straight after checking err.
	if res == nil || res.Nrf_NFDisc_SearchResult == nil {
		return nil, errors.New("no search result from NRF")
	}

	return res.Nrf_NFDisc_SearchResult, nil
}

func (s *nnrfService) SendNFInstancesUDR(nrfUri, id string) string {
	targetNfType := models.Nrf_NFMgmt_NFType_UDR
	requestNfType := models.Nrf_NFMgmt_NFType_PCF
	localVarOptionals := NFDisc.SearchNFInstancesRequest{
		// 	DataSet: optional.NewInterface(models.Nrf_NFMgmt_DataSetId_SUBSCRIPTION),
	}

	result, err := s.SendSearchNFInstances(nrfUri, targetNfType, requestNfType, localVarOptionals)
	if err != nil {
		logger.ConsumerLog.Error(err.Error())
		return ""
	}
	for _, profile := range result.NfInstances {
		if uri := util.SearchNFServiceUri(profile, models.Nrf_NFMgmt_ServiceName_NUDR_DR, models.Nrf_NFMgmt_NFServiceStatus_REGISTERED); uri != "" { //nolint:lll
			return uri
		}
	}
	return ""
}

func (s *nnrfService) SendNFInstancesBSF(nrfUri string) string {
	targetNfType := models.Nrf_NFMgmt_NFType_BSF
	requestNfType := models.Nrf_NFMgmt_NFType_PCF
	localVarOptionals := NFDisc.SearchNFInstancesRequest{}

	result, err := s.SendSearchNFInstances(nrfUri, targetNfType, requestNfType, localVarOptionals)
	if err != nil {
		logger.ConsumerLog.Error(err.Error())
		return ""
	}
	for _, profile := range result.NfInstances {
		if uri := util.SearchNFServiceUri(profile, models.Nrf_NFMgmt_ServiceName_NBSF_MANAGEMENT,
			models.Nrf_NFMgmt_NFServiceStatus_REGISTERED); uri != "" {
			return uri
		}
	}
	return ""
}

func (
	s *nnrfService) SendNFInstancesAMF(nrfUri string, guami models.Guami, serviceName models.Nrf_NFMgmt_ServiceName,
) string {
	targetNfType := models.Nrf_NFMgmt_NFType_AMF
	requestNfType := models.Nrf_NFMgmt_NFType_PCF

	localVarOptionals := NFDisc.SearchNFInstancesRequest{
		Guami: &guami,
	}

	result, err := s.SendSearchNFInstances(nrfUri, targetNfType, requestNfType, localVarOptionals)
	if err != nil {
		logger.ConsumerLog.Error(err.Error())
		return ""
	}
	for _, profile := range result.NfInstances {
		return util.SearchNFServiceUri(profile, serviceName, models.Nrf_NFMgmt_NFServiceStatus_REGISTERED)
	}
	return ""
}

// management
func (s *nnrfService) BuildNFInstance(
	context *pcf_context.PCFContext,
) (profile models.Nrf_NFMgmt_NFProfile, err error) {
	profile.NfInstanceId = context.NfId
	profile.NfType = models.Nrf_NFMgmt_NFType_PCF
	profile.NfStatus = models.Nrf_NFMgmt_NFStatus_REGISTERED
	profile.Ipv4Addresses = append(profile.Ipv4Addresses, context.RegisterIPv4)
	services := []models.Nrf_NFMgmt_NFService{}
	for _, nfService := range context.NfService {
		services = append(services, nfService)
	}
	if len(services) > 0 {
		profile.NfServices = services
	}
	profile.PcfInfo = &models.Nrf_NFMgmt_PcfInfo{
		DnnList: []string{
			"free5gc",
			"internet",
		},
		// SupiRanges: &[]models.Nrf_NFMgmt_SupiRange{
		// 	{
		// 		//from TS 29.510 6.1.6.2.9 example2
		//		//no need to set supirange in this moment 2019/10/4
		// 		Start:   "123456789040000",
		// 		End:     "123456789059999",
		// 		Pattern: "^imsi-12345678904[0-9]{4}$",
		// 	},
		// },
	}
	if context.Locality != "" {
		profile.Locality = context.Locality
	}
	return profile, nil
}

func (s *nnrfService) SendRegisterNFInstance(ctx context.Context) (
	resouceNrfUri string, retrieveNfInstanceID string, err error,
) {
	// Set client and set url
	pcfContext := s.consumer.Context()

	client := s.getNFManagementClient(pcfContext.NrfUri)
	nfProfile, err := s.BuildNFInstance(pcfContext)
	if err != nil {
		return "", "",
			errors.Wrap(err, "RegisterNFInstance buildNfProfile()")
	}

	var nf models.Nrf_NFMgmt_NFProfile
	var res *NFMgmt.RegisterNFInstanceResponse

	finish := false
	for !finish {
		select {
		case <-ctx.Done():
			return "", "", fmt.Errorf("RegisterNFInstance context done")
		default:
			req := &NFMgmt.RegisterNFInstanceRequest{
				NfInstanceID: &pcfContext.NfId,
				RequestBody:  &nfProfile,
			}
			res, err = client.NFInstanceIDDocumentApi.RegisterNFInstance(ctx, req)
			if err != nil || res == nil {
				logger.ConsumerLog.Errorf("PCF register to NRF Error[%v]", err)
				time.Sleep(2 * time.Second)
				continue
			}
			nf = *res.Nrf_NFMgmt_NFProfile

			if res.Location == "" {
				// NFUpdate
				finish = true
			} else {
				// NFRegister
				resourceUri := res.Location
				resouceNrfUri = resourceUri[:strings.Index(resourceUri, "/nnrf-nfm/")]
				retrieveNfInstanceID = resourceUri[strings.LastIndex(resourceUri, "/")+1:]

				oauth2 := false
				if customInfo, isMap := nf.CustomInfo.(map[string]interface{}); isMap {
					v, ok := customInfo["oauth2"].(bool)
					if ok {
						oauth2 = v
						logger.MainLog.Infoln("OAuth2 setting receive from NRF:", oauth2)
					}
				}
				pcf_context.GetSelf().OAuth2Required = oauth2
				if oauth2 && pcf_context.GetSelf().NrfCertPem == "" {
					logger.CfgLog.Error("OAuth2 enable but no nrfCertPem provided in config.")
				}

				finish = true
			}
		}
	}

	return resouceNrfUri, retrieveNfInstanceID, err
}

func (s *nnrfService) SendDeregisterNFInstance() (problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Infof("Send Deregister NFInstance")

	ctx, pd, err := pcf_context.GetSelf().GetTokenCtx(models.Nrf_NFMgmt_ServiceName_NNRF_NFM, models.Nrf_NFMgmt_NFType_NRF)
	if err != nil {
		return pd, err
	}

	pcfContext := s.consumer.Context()
	client := s.getNFManagementClient(pcfContext.NrfUri)
	request := &NFMgmt.DeregisterNFInstanceRequest{
		NfInstanceID: &pcfContext.NfId,
	}

	_, err = client.NFInstanceIDDocumentApi.DeregisterNFInstance(ctx, request)

	return problemDetails, err
}
