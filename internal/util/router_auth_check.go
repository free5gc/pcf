package util

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
)

type RouterAuthorizationCheck struct {
	realm       string
	serviceName models.Nrf_NFMgmt_ServiceName
}

func NewRouterAuthorizationCheck(
	serviceName models.Nrf_NFMgmt_ServiceName, realm string,
) (*RouterAuthorizationCheck, error) {
	u, err := url.ParseRequestURI(realm)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" ||
		u.User != nil || u.Path == "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(realm, "#") {
		return nil, fmt.Errorf("invalid PCF service URI for %s", serviceName)
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("invalid PCF service port for %s", serviceName)
		}
	}
	return &RouterAuthorizationCheck{serviceName: serviceName, realm: realm}, nil
}

func (rac *RouterAuthorizationCheck) Check(c *gin.Context, pcfContext pcf_context.NFContext) {
	token := c.Request.Header.Get("Authorization")
	err := pcfContext.AuthorizationCheck(token, rac.serviceName)
	if err != nil {
		logger.UtilLog.Debugf("RouterAuthorizationCheck::Check Unauthorized: %s", err)
		status, challenge, reason := oauthChallenge(string(rac.serviceName), token, err, rac.realm)
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
