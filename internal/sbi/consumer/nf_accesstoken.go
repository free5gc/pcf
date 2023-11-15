package consumer

import (
	"context"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
)

func GetTokenCtx(scope, targetNF string) (context.Context, *models.ProblemDetails, error) {
	if pcf_context.GetSelf().OAuth2Required {
		logger.ConsumerLog.Infof("GetToekenCtx")
		pcfSelf := pcf_context.GetSelf()
		tok, pd, err := oauth.SendAccTokenReq(pcfSelf.NfId, models.NfType_PCF, scope, targetNF, pcfSelf.NrfUri)
		if err != nil {
			return nil, pd, err
		}
		return context.WithValue(context.Background(),
			openapi.ContextOAuth2, tok), pd, nil
	}
	return context.TODO(), nil, nil
}
