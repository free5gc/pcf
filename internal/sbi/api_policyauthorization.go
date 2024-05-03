/*
 * Npcf_PolicyAuthorization Service API
 *
 * This is the Policy Authorization Service
 *
 * API version: 1.0.1
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package sbi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/sbi/processor"
	"github.com/free5gc/pcf/internal/util"
	"github.com/free5gc/util/httpwrapper"
)

func (s *Server) getPolicyAuthorizationRoutes() []Route {
	return []Route{
		{
			Method:  http.MethodPost,
			Pattern: "/app-sessions",
			APIFunc: s.HTTPPostAppSessions,
		},
		{
			Method:  http.MethodDelete,
			Pattern: "/app-sessions/:appSessionId/events-subscription",
			APIFunc: s.HTTPDeleteEventsSubsc,
		},
		{
			Method:  http.MethodPut,
			Pattern: "/app-sessions/:appSessionId/events-subscription",
			APIFunc: s.HTTPUpdateEventsSubsc,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/app-sessions/:appSessionId/delete",
			APIFunc: s.HTTPDeleteAppSession,
		},
		{
			Method:  http.MethodGet,
			Pattern: "/app-sessions/:appSessionId",
			APIFunc: s.HTTPGetAppSession,
		},
		{
			Method:  http.MethodPatch,
			Pattern: "/app-sessions/:appSessionId",
			APIFunc: s.HTTPModAppSession,
		},
	}
}

// api_application_session
// HTTPPostAppSessions - Creates a new Individual Application Session Context resource
func (s *Server) HTTPPostAppSessions(c *gin.Context) {
	var appSessionContext models.AppSessionContext

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.PolicyAuthLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&appSessionContext, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.PolicyAuthLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	ascReqData := appSessionContext.AscReqData
	if ascReqData == nil || ascReqData.SuppFeat == "" || ascReqData.NotifUri == "" {
		// Check Mandatory IEs
		rsp := util.GetProblemDetail("Errorneous/Missing Mandotory IE", util.ERROR_INITIAL_PARAMETERS)
		logger.PolicyAuthLog.Errorln(rsp.Detail)
		c.JSON(int(rsp.Status), rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, appSessionContext)
	rsp := s.processor.HandlePostAppSessionsContext(req)

	for key, val := range rsp.Header {
		c.Header(key, val[0])
	}
	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.PolicyAuthLog.Errorln(err)
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

// api_events_subscription
// HTTPDeleteEventsSubsc - deletes the Events Subscription subresource
func (s *Server) HTTPDeleteEventsSubsc(c *gin.Context) {
	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["appSessionId"], _ = c.Params.Get("appSessionId")

	rsp := processor.HandleDeleteEventsSubscContext(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.PolicyAuthLog.Errorln(err)
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

// HTTPUpdateEventsSubsc - creates or modifies an Events Subscription subresource
func (s *Server) HTTPUpdateEventsSubsc(c *gin.Context) {
	var eventsSubscReqData models.EventsSubscReqData

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.PolicyAuthLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&eventsSubscReqData, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.PolicyAuthLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	if eventsSubscReqData.Events == nil || eventsSubscReqData.NotifUri == "" {
		problemDetail := util.GetProblemDetail("Errorneous/Missing Mandotory IE", util.ERROR_REQUEST_PARAMETERS)
		logger.PolicyAuthLog.Errorln(problemDetail.Detail)
		c.JSON(int(problemDetail.Status), problemDetail)
		return
	}

	req := httpwrapper.NewRequest(c.Request, eventsSubscReqData)
	req.Params["appSessionId"], _ = c.Params.Get("appSessionId")

	rsp := processor.HandleUpdateEventsSubscContext(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.PolicyAuthLog.Errorln(err)
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

// api_individual
// HTTPDeleteAppSession - Deletes an existing Individual Application Session Context
func (s *Server) HTTPDeleteAppSession(c *gin.Context) {
	var eventsSubscReqData *models.EventsSubscReqData

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.PolicyAuthLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	// EventsSubscReqData is Optional
	if len(requestBody) > 0 {
		err = openapi.Deserialize(&eventsSubscReqData, requestBody, "application/json")
		if err != nil {
			problemDetail := "[Request Body] " + err.Error()
			rsp := models.ProblemDetails{
				Title:  "Malformed request syntax",
				Status: http.StatusBadRequest,
				Detail: problemDetail,
			}
			logger.PolicyAuthLog.Errorln(problemDetail)
			c.JSON(http.StatusBadRequest, rsp)
			return
		}
	}

	req := httpwrapper.NewRequest(c.Request, eventsSubscReqData)
	req.Params["appSessionId"], _ = c.Params.Get("appSessionId")

	rsp := processor.HandleDeleteAppSessionContext(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.PolicyAuthLog.Errorln(err)
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

// HTTPGetAppSession - Reads an existing Individual Application Session Context
func (s *Server) HTTPGetAppSession(c *gin.Context) {
	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["appSessionId"], _ = c.Params.Get("appSessionId")

	rsp := processor.HandleGetAppSessionContext(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.PolicyAuthLog.Errorln(err)
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

// HTTPModAppSession - Modifies an existing Individual Application Session Context
func (s *Server) HTTPModAppSession(c *gin.Context) {
	var appSessionContextUpdateData models.AppSessionContextUpdateData

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.PolicyAuthLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&appSessionContextUpdateData, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.PolicyAuthLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, appSessionContextUpdateData)
	req.Params["appSessionId"], _ = c.Params.Get("appSessionId")

	rsp := s.processor.HandleModAppSessionContext(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.PolicyAuthLog.Errorln(err)
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
