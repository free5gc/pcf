package consumer

import (
	"sync"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/pcf/AMPolicyControl"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/util"
)

type npcfService struct {
	consumer *Consumer

	nfAMPolicyControlMu sync.RWMutex

	nfAMPolicyControlClient map[string]*AMPolicyControl.APIClient
}

func (s *npcfService) getAMPolicyControl(uri string) *AMPolicyControl.APIClient {
	if uri == "" {
		return nil
	}
	s.nfAMPolicyControlMu.RLock()
	client, ok := s.nfAMPolicyControlClient[uri]
	if ok {
		defer s.nfAMPolicyControlMu.RUnlock()
		return client
	}

	configuration := AMPolicyControl.NewConfiguration()
	configuration.SetBasePath(uri)
	client = AMPolicyControl.NewAPIClient(configuration)

	s.nfAMPolicyControlMu.RUnlock()
	s.nfAMPolicyControlMu.Lock()
	defer s.nfAMPolicyControlMu.Unlock()
	s.nfAMPolicyControlClient[uri] = client
	return client
}

func (s *npcfService) SendAMPolicyUpdateNotification(uri string, request *models.PcfAmPolicyControlPolicyUpdate) (
	rsp *AMPolicyControl.CreateIndividualAMPolicyAssociationPolicyUpdateNotificationPostResponse,
	problemDetail *models.ProblemDetails, err error,
) {
	if uri == "" {
		problemDetail := util.GetProblemDetail("NPcf client can't find call back uri",
			"SendAMPolicyAssociationPolicyAssocitionTerminationRequestNotification Can't find URI")
		return nil, &problemDetail, nil
	}

	if request == nil {
		problemDetail := util.GetProblemDetail("SendAMPolicyUpdateNotification request is nil",
			"SendAMPolicyUpdateNotification function in consumer request is nil")
		return nil, &problemDetail, nil
	}

	ctx, problemDetails, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NPCF_AM_POLICY_CONTROL,
		models.NrfNfManagementNfType_PCF)
	if err != nil {
		return nil, nil, err
	} else if problemDetails != nil {
		return nil, problemDetails, nil
	}

	client := s.getAMPolicyControl(uri)
	param := AMPolicyControl.CreateIndividualAMPolicyAssociationPolicyUpdateNotificationPostRequest{
		PcfAmPolicyControlPolicyUpdate: request,
	}
	rsp, err = client.AMPolicyAssociationsCollectionApi.
		CreateIndividualAMPolicyAssociationPolicyUpdateNotificationPost(
			ctx, uri, &param)
	if err != nil {
		logger.AmPolicyLog.Warnf("SendAMPolicyUpdateNotification function in consumer Error[%s]",
			err.Error())
		return nil, nil, err
	} else if rsp == nil {
		logger.AmPolicyLog.Warnln("SendAMPolicyUpdateNotification function in consumer Failed[Response is nil]")
		problemDetail := util.GetProblemDetail("SendAMPolicyUpdateNotification function in consumer Fault[%s]",
			"Response is nil")
		return nil, &problemDetail, nil
	}
	return rsp, nil, nil
}

func (s *npcfService) SendAMPolicyAssociationPolicyAssocitionTerminationRequestNotification(
	uri string, request *models.PcfAmPolicyControlTerminationNotification,
) (
	problemDetails *models.ProblemDetails, err error,
) {
	if uri == "" {
		problemDetail := util.GetProblemDetail("NPcf client can't find call back uri",
			"SendAMPolicyAssociationPolicyAssocitionTerminationRequestNotification Can't find URI")
		return &problemDetail, nil
	}

	if request == nil {
		problemDetail := util.GetProblemDetail(
			"SendAMPolicyAssociationPolicyAssocitionTerminationRequestNotification request is nil",
			"SendAMPolicyAssociationPolicyAssocitionTerminationRequestNotification request is nil")
		return &problemDetail, nil
	}

	ctx, problemDetails, err := s.consumer.Context().GetTokenCtx(
		models.ServiceName_NPCF_AM_POLICY_CONTROL,
		models.NrfNfManagementNfType_PCF)
	if err != nil {
		return nil, err
	} else if problemDetails != nil {
		return problemDetails, nil
	}

	client := s.getAMPolicyControl(uri)
	param := AMPolicyControl.
		CreateIndividualAMPolicyAssociationPolicyAssocitionTerminationRequestNotificationPostRequest{
		PcfAmPolicyControlTerminationNotification: request,
	}
	_, err = client.AMPolicyAssociationsCollectionApi.
		CreateIndividualAMPolicyAssociationPolicyAssocitionTerminationRequestNotificationPost(
			ctx, uri, &param)
	if err != nil {
		logger.AmPolicyLog.Warnf(
			"CreateIndividualAMPolicyAssociationPolicyAssocitionTerminationRequestNotificationPost Error[%s]",
			err.Error())
		return nil, err
	}
	return nil, nil
}
