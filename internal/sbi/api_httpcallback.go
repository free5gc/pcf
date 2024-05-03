package sbi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/sbi/producer"
	"github.com/free5gc/util/httpwrapper"
)

func (s *Server) getHttpCallBackEndpoints() []Endpoint {
	return []Endpoint{
		{
			Method:  http.MethodPost,
			Pattern: "/nudr-notify/policy-data/:supi",
			APIFunc: s.HTTPUdrPolicyDataChangeNotify,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/nudr-notify/influence-data/:supi/:pduSessionId",
			APIFunc: s.HTTPUdrInfluenceDataUpdateNotify,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/amfstatus",
			APIFunc: s.HTTPAmfStatusChangeNotify,
		},
	}
}

// amf_status_change
func (s *Server) HTTPAmfStatusChangeNotify(c *gin.Context) {
	var amfStatusChangeNotification models.AmfStatusChangeNotification

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.CallbackLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&amfStatusChangeNotification, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CallbackLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, amfStatusChangeNotification)

	rsp := producer.HandleAmfStatusChangeNotify(req)

	if rsp.Status == http.StatusNoContent {
		c.Status(rsp.Status)
	} else {
		responseBody, err := openapi.Serialize(rsp.Body, "application/json")
		if err != nil {
			logger.CallbackLog.Errorln(err)
			problemDetails := models.ProblemDetails{
				Status: http.StatusInternalServerError,
				Cause:  "SYSTEM_FAILURE",
				Detail: err.Error(),
			}
			c.JSON(http.StatusInternalServerError, problemDetails)
		} else {
			c.Data(rsp.Status, "application/json", responseBody)
		}
	}
}

// sm_policy_notify
// Nudr-Notify-smpolicy
func (s *Server) HTTPUdrPolicyDataChangeNotify(c *gin.Context) {
	var policyDataChangeNotification models.PolicyDataChangeNotification

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.CallbackLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&policyDataChangeNotification, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CallbackLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, policyDataChangeNotification)
	req.Params["supi"] = c.Params.ByName("supi")

	rsp := producer.HandlePolicyDataChangeNotify(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.CallbackLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, "application/json", responseBody)
	}
}

// Influence Data Update Notification
func (s *Server) HTTPUdrInfluenceDataUpdateNotify(c *gin.Context) {
	var trafficInfluDataNotif []models.TrafficInfluDataNotif

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.CallbackLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&trafficInfluDataNotif, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CallbackLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, trafficInfluDataNotif)
	req.Params["supi"] = c.Params.ByName("supi")
	req.Params["pduSessionId"] = c.Params.ByName("pduSessionId")

	rsp := producer.HandleInfluenceDataUpdateNotify(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.CallbackLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, "application/json", responseBody)
	}
}
