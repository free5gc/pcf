package sbi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/sbi/producer"
	"github.com/free5gc/pcf/internal/util"
	"github.com/free5gc/util/httpwrapper"
)

func (s *Server) HTTPPoliciesPolAssoIdDelete(c *gin.Context) {
	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["polAssoId"], _ = c.Params.Get("polAssoId")

	rsp := producer.HandleDeletePoliciesPolAssoId(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.AmPolicyLog.Errorln(err)
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

// HTTPPoliciesPolAssoIdGet -
func (s *Server) HTTPPoliciesPolAssoIdGet(c *gin.Context) {
	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["polAssoId"], _ = c.Params.Get("polAssoId")

	rsp := producer.HandleGetPoliciesPolAssoId(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.AmPolicyLog.Errorln(err)
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

// HTTPPoliciesPolAssoIdUpdatePost -
func (s *Server) HTTPPoliciesPolAssoIdUpdatePost(c *gin.Context) {
	var policyAssociationUpdateRequest models.PolicyAssociationUpdateRequest

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.AmPolicyLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&policyAssociationUpdateRequest, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.AmPolicyLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, policyAssociationUpdateRequest)
	req.Params["polAssoId"], _ = c.Params.Get("polAssoId")

	rsp := producer.HandleUpdatePostPoliciesPolAssoId(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.AmPolicyLog.Errorln(err)
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

// HTTPPoliciesPost -
func (s *Server) HTTPPoliciesPost(c *gin.Context) {
	var policyAssociationRequest models.PolicyAssociationRequest

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.AmPolicyLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&policyAssociationRequest, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.AmPolicyLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	if policyAssociationRequest.Supi == "" || policyAssociationRequest.NotificationUri == "" {
		rsp := util.GetProblemDetail("Miss Mandotory IE", util.ERROR_REQUEST_PARAMETERS)
		logger.AmPolicyLog.Errorln(rsp.Detail)
		c.JSON(int(rsp.Status), rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, policyAssociationRequest)
	req.Params["polAssoId"], _ = c.Params.Get("polAssoId")

	rsp := producer.HandlePostPolicies(req)

	for key, val := range rsp.Header {
		c.Header(key, val[0])
	}

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.AmPolicyLog.Errorln(err)
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

func (s *Server) getAmPolicyRoutes() []Route {
	return []Route{

		{
			Method:  http.MethodGet,
			Pattern: "/policies/:polAssoId",
			APIFunc: s.HTTPPoliciesPolAssoIdGet,
		},
		{
			Method:  http.MethodDelete,
			Pattern: "/policies/:polAssoId",
			APIFunc: s.HTTPPoliciesPolAssoIdDelete,
		},
		{
			Method:  http.MethodGet,
			Pattern: "/policies/:polAssoId",
			APIFunc: s.HTTPPoliciesPolAssoIdGet,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/policies/:polAssoId/update",
			APIFunc: s.HTTPPoliciesPolAssoIdUpdatePost,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/policies",
			APIFunc: s.HTTPPoliciesPost,
		},
	}
}
