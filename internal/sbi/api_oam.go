package sbi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) setCorsHeader(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
	c.Writer.Header().Set(
		"Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, "+
			"X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, PATCH, DELETE")
}

func (s *Server) HTTPOAMGetAmPolicy(c *gin.Context) {
	s.setCorsHeader(c)

	supi := c.Params.ByName("supi")
	s.Processor().HandleOAMGetAmPolicyRequest(c, supi)

	// req := httpwrapper.NewRequest(c.Request, nil)
	// req.Params["supi"] = c.Params.ByName("supi")

	// rsp := processor.HandleOAMGetAmPolicyRequest(req)

	// responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	// if err != nil {
	// 	logger.OamLog.Errorln(err)
	// 	problemDetails := models.ProblemDetails{
	// 		Status: http.StatusInternalServerError,
	// 		Cause:  "SYSTEM_FAILURE",
	// 		Detail: err.Error(),
	// 	}
	// 	c.JSON(http.StatusInternalServerError, problemDetails)
	// } else {
	// 	c.Data(rsp.Status, "application/json", responseBody)
	// }
}

func (s *Server) getOamRoutes() []Route {
	return []Route{
		{
			Method:  http.MethodGet,
			Pattern: "/am-policy/:supi",
			APIFunc: s.HTTPOAMGetAmPolicy,
		},
	}
}
