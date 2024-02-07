package consumer

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nnrf_NFManagement"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
)

func BuildNFInstance(context *pcf_context.PCFContext) (profile models.NfProfile, err error) {
	profile.NfInstanceId = context.NfId
	profile.NfType = models.NfType_PCF
	profile.NfStatus = models.NfStatus_REGISTERED
	profile.Ipv4Addresses = append(profile.Ipv4Addresses, context.RegisterIPv4)
	service := []models.NfService{}
	for _, nfService := range context.NfService {
		service = append(service, nfService)
	}
	profile.NfServices = &service
	profile.PcfInfo = &models.PcfInfo{
		DnnList: []string{
			"free5gc",
			"internet",
		},
		// SupiRanges: &[]models.SupiRange{
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
	return
}

func SendRegisterNFInstance(nrfUri, nfInstanceId string, profile models.NfProfile) (
	resouceNrfUri string, retrieveNfInstanceID string, err error,
) {
	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(nrfUri)
	apiClient := Nnrf_NFManagement.NewAPIClient(configuration)

	ctx, _, err := pcf_context.GetSelf().GetTokenCtx(models.ServiceName_NNRF_NFM, models.NfType_NRF)
	if err != nil {
		return "", "",
			errors.Errorf("SendRegisterNFInstance error: %+v", err)
	}

	var res *http.Response
	var nf models.NfProfile
	for {
		nf, res, err = apiClient.NFInstanceIDDocumentApi.RegisterNFInstance(ctx, nfInstanceId, profile)
		if err != nil || res == nil {
			// TODO : add log
			fmt.Println(fmt.Errorf("PCF register to NRF Error[%v]", err.Error()))
			time.Sleep(2 * time.Second)
			continue
		}
		defer func() {
			if resCloseErr := res.Body.Close(); resCloseErr != nil {
				logger.ConsumerLog.Errorf("RegisterNFInstance response body cannot close: %+v", resCloseErr)
			}
		}()
		status := res.StatusCode
		if status == http.StatusOK {
			// NFUpdate
			break
		} else if status == http.StatusCreated {
			// NFRegister
			resourceUri := res.Header.Get("Location")
			resouceNrfUri = resourceUri[:strings.Index(resourceUri, "/nnrf-nfm/")]
			retrieveNfInstanceID = resourceUri[strings.LastIndex(resourceUri, "/")+1:]

			oauth2 := false
			if nf.CustomInfo != nil {
				v, ok := nf.CustomInfo["oauth2"].(bool)
				if ok {
					oauth2 = v
					logger.MainLog.Infoln("OAuth2 setting receive from NRF:", oauth2)
				}
			}
			pcf_context.GetSelf().OAuth2Required = oauth2

			if oauth2 && pcf_context.GetSelf().NrfCertPem == "" {
				logger.CfgLog.Error("OAuth2 enable but no nrfCertPem provided in config.")
			}
			break
		} else {
			fmt.Println("NRF return wrong status code", status)
		}
	}
	return resouceNrfUri, retrieveNfInstanceID, err
}

func SendDeregisterNFInstance() (problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Infof("Send Deregister NFInstance")

	ctx, pd, err := pcf_context.GetSelf().GetTokenCtx(models.ServiceName_NNRF_NFM, models.NfType_NRF)
	if err != nil {
		return pd, err
	}

	pcfSelf := pcf_context.GetSelf()
	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(pcfSelf.NrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response

	res, err = client.NFInstanceIDDocumentApi.DeregisterNFInstance(ctx, pcfSelf.NfId)
	if err == nil {
		return nil, nil
	} else if res != nil {
		defer func() {
			if resCloseErr := res.Body.Close(); resCloseErr != nil {
				logger.ConsumerLog.Errorf("DeregisterNFInstance response cannot close: %+v", resCloseErr)
			}
		}()
		if res.Status != err.Error() {
			return nil, err
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}
	return problemDetails, err
}
