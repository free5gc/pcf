package util

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/pkg/factory"
)

type RouterAuthorizationCheck struct {
	serviceName models.Nrf_NFMgmt_ServiceName
}

func NewRouterAuthorizationCheck(serviceName models.Nrf_NFMgmt_ServiceName) *RouterAuthorizationCheck {
	return &RouterAuthorizationCheck{
		serviceName: serviceName,
	}
}

func (rac *RouterAuthorizationCheck) Check(c *gin.Context, pcfContext pcf_context.NFContext) {
	token := c.Request.Header.Get("Authorization")
	err := pcfContext.AuthorizationCheck(token, rac.serviceName)
	if err != nil {
		logger.UtilLog.Debugf("RouterAuthorizationCheck::Check Unauthorized: %s", err)
		baseURI := "http://localhost"
		if factory.PcfConfig != nil && factory.PcfConfig.Configuration != nil && factory.PcfConfig.Configuration.Sbi != nil {
			baseURI = fmt.Sprintf("%s://%s:%d",
				factory.PcfConfig.GetSbiScheme(), factory.PcfConfig.Configuration.Sbi.RegisterIPv4, factory.PcfConfig.GetSbiPort())
		}
		status, challenge, reason := oauthChallenge(c.Request, string(rac.serviceName), token, err, baseURI)
		c.Header("WWW-Authenticate", challenge)
		c.Header("Content-Type", "application/problem+json")
		c.AbortWithStatusJSON(status, models.ProblemDetails{
			Status: int32(status),
			Title:  http.StatusText(status),
			Detail: reason,
		})
		return
	}

	logger.UtilLog.Debugf("RouterAuthorizationCheck::Check Authorized")
}
