package consumer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/nrf/NFDisc"
	"github.com/free5gc/openapi/nrf/NFMgmt"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/util"
	sbi_metrics "github.com/free5gc/util/metrics/sbi"
	"github.com/free5gc/util/nfheartbeat"
)

const registerRetryInterval = 2 * time.Second

type nnrfService struct {
	consumer *Consumer

	nfMngmntMu sync.RWMutex
	nfDiscMu   sync.RWMutex

	nfMngmntClients map[string]*NFMgmt.APIClient
	nfDiscClients   map[string]*NFDisc.APIClient

	heartbeat *nfheartbeat.Runner

	// Interval in seconds from the last registration response. Written before the heartbeat starts, then only on
	// the heartbeat goroutine.
	heartbeatTimer int32
}

func (s *nnrfService) getNFManagementClient(uri string) *NFMgmt.APIClient {
	if uri == "" {
		return nil
	}
	s.nfMngmntMu.RLock()
	client, ok := s.nfMngmntClients[uri]
	s.nfMngmntMu.RUnlock()
	if ok {
		return client
	}

	s.nfMngmntMu.Lock()
	defer s.nfMngmntMu.Unlock()
	// Another caller may have stored a client while the read lock was down.
	if client, ok = s.nfMngmntClients[uri]; ok {
		return client
	}

	configuration := NFMgmt.NewConfiguration()
	configuration.SetBasePath(uri)
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = NFMgmt.NewAPIClient(configuration)

	s.nfMngmntClients[uri] = client
	return client
}

func (s *nnrfService) getNFDiscClient(uri string) *NFDisc.APIClient {
	if uri == "" {
		return nil
	}
	s.nfDiscMu.RLock()
	client, ok := s.nfDiscClients[uri]
	s.nfDiscMu.RUnlock()
	if ok {
		return client
	}

	s.nfDiscMu.Lock()
	defer s.nfDiscMu.Unlock()
	// Another caller may have stored a client while the read lock was down.
	if client, ok = s.nfDiscClients[uri]; ok {
		return client
	}

	configuration := NFDisc.NewConfiguration()
	configuration.SetBasePath(uri)
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = NFDisc.NewAPIClient(configuration)

	s.nfDiscClients[uri] = client
	return client
}

func (s *nnrfService) SendSearchNFInstances(
	nrfUri string, targetNfType, requestNfType models.Nrf_NFMgmt_NFType, param NFDisc.SearchNFInstancesRequest) (
	*models.Nrf_NFDisc_SearchResult, error,
) {
	// Set client and set url
	client := s.getNFDiscClient(nrfUri)
	if client == nil {
		return nil, errors.Errorf("SendSearchNFInstances: nrf not found")
	}

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

// SendRegisterNFInstance PUTs the profile on the NF's own instance ID (3GPP TS 29.510 clause 5.2.2.2.2) until it
// succeeds or ctx is done. Only the startup call may pass applyOAuth2: it writes OAuth2Required unsynchronized.
func (s *nnrfService) SendRegisterNFInstance(ctx context.Context, applyOAuth2 bool) error {
	pcfContext := s.consumer.Context()
	client := s.getNFManagementClient(pcfContext.NrfUri)
	if client == nil {
		return fmt.Errorf("SendRegisterNFInstance: nrf not found")
	}

	nfProfile, err := s.BuildNFInstance(pcfContext)
	if err != nil {
		return fmt.Errorf("SendRegisterNFInstance BuildNFInstance(): %w", err)
	}

	var res *NFMgmt.RegisterNFInstanceResponse
	registerNFInstanceRequest := &NFMgmt.RegisterNFInstanceRequest{
		NfInstanceID: &pcfContext.NfId,
		RequestBody:  &nfProfile,
	}
	for ctx.Err() == nil {
		res, err = client.NFInstanceIDDocumentApi.RegisterNFInstance(ctx, registerNFInstanceRequest)
		if err == nil && res != nil {
			var nf models.Nrf_NFMgmt_NFProfile
			if res.Nrf_NFMgmt_NFProfile != nil {
				nf = *res.Nrf_NFMgmt_NFProfile
			}
			s.processRegisterResponse(pcfContext, nf, applyOAuth2)
			return nil
		}
		logger.ConsumerLog.Errorf("PCF register to NRF Error[%v]", err)
		select {
		case <-ctx.Done():
		case <-time.After(registerRetryInterval):
		}
	}
	return fmt.Errorf("NFRegister aborted: %w (last error: %v)", ctx.Err(), err)
}

// processRegisterResponse adopts what the NRF answered to the NFRegister PUT: the
// heartbeat interval and the oauth2 custom info.
func (s *nnrfService) processRegisterResponse(
	pcfContext *pcf_context.PCFContext,
	nf models.Nrf_NFMgmt_NFProfile,
	applyOAuth2 bool,
) {
	s.heartbeatTimer = nf.HeartBeatTimer

	oauth2 := false
	if customInfo, isMap := nf.CustomInfo.(map[string]interface{}); isMap {
		if v, ok := customInfo["oauth2"].(bool); ok {
			oauth2 = v
			logger.MainLog.Infoln("OAuth2 setting receive from NRF:", oauth2)
		}
	}
	if applyOAuth2 {
		pcfContext.OAuth2Required = oauth2
		if oauth2 && pcfContext.NrfCertPem == "" {
			logger.CfgLog.Error("OAuth2 enable but no nrfCertPem provided in config.")
		}
	} else if oauth2 != pcfContext.OAuth2Required {
		logger.ConsumerLog.Warnf("NRF OAuth2 setting changed to %v, restart PCF to apply it", oauth2)
	}
}

// SendUpdateNFInstance sends an NFUpdate PATCH to the NRF, honoring ctx. The
// raw err comes back alongside any ProblemDetails so callers can read its
// GenericOpenAPIError status.
func (s *nnrfService) SendUpdateNFInstance(ctx context.Context, patchItems []models.PatchItem) (
	nf models.Nrf_NFMgmt_NFProfile, problemDetails *models.ProblemDetails, err error,
) {
	pcfContext := s.consumer.Context()
	tokCtx, pd, err := pcfContext.GetTokenCtx(
		models.Nrf_NFMgmt_ServiceName_NNRF_NFM,
		models.Nrf_NFMgmt_NFType_NRF,
	)
	if err != nil {
		return nf, pd, err
	}
	// GetTokenCtx takes no parent, so the token request stays uncancellable;
	// transplanting the token lets at least the PATCH honor ctx.
	if tok := tokCtx.Value(openapi.ContextOAuth2); tok != nil {
		ctx = context.WithValue(ctx, openapi.ContextOAuth2, tok)
	}

	client := s.getNFManagementClient(pcfContext.NrfUri)
	if client == nil {
		return nf, nil, errors.Errorf("SendUpdateNFInstance: nrf not found")
	}

	request := &NFMgmt.UpdateNFInstanceRequest{
		NfInstanceID: &pcfContext.NfId,
		RequestBody:  patchItems,
	}

	res, err := client.NFInstanceIDDocumentApi.UpdateNFInstance(ctx, request)
	if err != nil {
		var apiErr openapi.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			if updateErr, okModel := apiErr.Model().(NFMgmt.UpdateNFInstanceError); okModel {
				return nf, updateErr.ProblemDetails, err
			}
		}
		return nf, nil, err
	}
	if res == nil {
		return nf, nil, errors.Errorf("empty NFUpdate response")
	}
	if res.Nrf_NFMgmt_NFProfile != nil {
		nf = *res.Nrf_NFMgmt_NFProfile
	}
	return nf, nil, nil
}

func (s *nnrfService) SendDeregisterNFInstance() (*models.ProblemDetails, error) {
	logger.ConsumerLog.Infof("Send Deregister NFInstance")

	pcfContext := s.consumer.Context()
	ctx, pd, err := pcfContext.GetTokenCtx(models.Nrf_NFMgmt_ServiceName_NNRF_NFM, models.Nrf_NFMgmt_NFType_NRF)
	if err != nil {
		return pd, err
	}

	client := s.getNFManagementClient(pcfContext.NrfUri)
	if client == nil {
		return nil, errors.Errorf("SendDeregisterNFInstance: nrf not found")
	}
	request := &NFMgmt.DeregisterNFInstanceRequest{
		NfInstanceID: &pcfContext.NfId,
	}

	_, err = client.NFInstanceIDDocumentApi.DeregisterNFInstance(ctx, request)
	var apiErr openapi.GenericOpenAPIError
	if errors.As(err, &apiErr) {
		if deregNfError, okDeg := apiErr.Model().(NFMgmt.DeregisterNFInstanceError); okDeg {
			return deregNfError.ProblemDetails, err
		}
	}
	return nil, err
}
