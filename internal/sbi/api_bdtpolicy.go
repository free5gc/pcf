/*
 * Npcf_BDTPolicyControl Service API
 *
 * The Npcf_BDTPolicyControl Service is used by an NF service consumer to
 * retrieve background data transfer policies from the PCF and to update
 * the PCF with the background data transfer policy selected by the NF
 * service consumer.
 *
 * API version: 1.0.0
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
	"github.com/free5gc/util/httpwrapper"
)

func (s *Server) getBdtPolicyRoutes() []Route {
	return []Route{
		{
			Method:  http.MethodPost,
			Pattern: "/bdtpolicies",
			APIFunc: s.HTTPCreateBDTPolicy,
		},
		{
			Method:  http.MethodGet,
			Pattern: "/bdtpolicies/:bdtPolicyId",
			APIFunc: s.HTTPGetBDTPolicy,
		},
		{
			Method:  http.MethodPatch,
			Pattern: "/bdtpolicies/:bdtPolicyId",
			APIFunc: s.HTTPUpdateBDTPolicy,
		},
	}
}

// api_bdt_policy
// CreateBDTPolicy - Create a new Individual BDT policy
func (s *Server) HTTPCreateBDTPolicy(c *gin.Context) {
	var bdtReqData models.BdtReqData
	// step 1: retrieve http request body
	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.BdtPolicyLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	// step 2: convert requestBody to openapi models
	err = openapi.Deserialize(&bdtReqData, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.BdtPolicyLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, bdtReqData)
	rsp := s.processor.HandleCreateBDTPolicyContextRequest(req)
	// step 5: response
	for key, val := range rsp.Header { // header response is optional
		c.Header(key, val[0])
	}
	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.BdtPolicyLog.Errorln(err)
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
// GetBDTPolicy - Read an Individual BDT policy
func (s *Server) HTTPGetBDTPolicy(c *gin.Context) {
	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["bdtPolicyId"] = c.Params.ByName("bdtPolicyId")

	rsp := processor.HandleGetBDTPolicyContextRequest(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.BdtPolicyLog.Errorln(err)
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

// UpdateBDTPolicy - Update an Individual BDT policy
func (s *Server) HTTPUpdateBDTPolicy(c *gin.Context) {
	var bdtPolicyDataPatch models.BdtPolicyDataPatch
	// step 1: retrieve http request body
	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.BdtPolicyLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	// step 2: convert requestBody to openapi models
	err = openapi.Deserialize(&bdtPolicyDataPatch, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.BdtPolicyLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, bdtPolicyDataPatch)
	req.Params["bdtPolicyId"] = c.Params.ByName("bdtPolicyId")

	rsp := s.processor.HandleUpdateBDTPolicyContextProcedure(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.BdtPolicyLog.Errorln(err)
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
