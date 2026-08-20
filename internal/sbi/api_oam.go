package sbi

import (
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pcf/internal/util"
	"github.com/free5gc/util/metrics/sbi"
)

const (
	CorsConfigMaxAge = 86400
)

func oamCorsMiddleware() gin.HandlerFunc {
	// turn these values into configurable variables
	return cors.New(cors.Config{
		AllowMethods: []string{"GET", "POST", "OPTIONS", "PUT", "PATCH", "DELETE"},
		AllowHeaders: []string{
			"Origin", "Content-Length", "Content-Type", "User-Agent",
			"Referrer", "Host", "Token", "X-Requested-With",
			"Accept", "Accept-Encoding", "Authorization", "Cache-Control",
			"X-CSRF-Token",
		},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowAllOrigins:  true,
		MaxAge:           CorsConfigMaxAge,
	})
}

func (s *Server) HTTPOAMGetAmPolicy(c *gin.Context) {
	supi := c.Params.ByName("supi")
	if supi == "" {
		problemDetails := &models.ProblemDetails{
			Title:  util.ERROR_INITIAL_PARAMETERS,
			Status: http.StatusBadRequest,
		}
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Title)
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}
	s.Processor().HandleOAMGetAmPolicyRequest(c, supi)
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
