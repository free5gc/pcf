package processor

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
)

type UEAmPolicy struct {
	PolicyAssociationID string
	AccessType          models.AccessType
	Rfsp                string
	Triggers            []models.RequestTrigger
	/*Service Area Restriction */
	RestrictionType models.RestrictionType
	Areas           []models.Area
	MaxNumOfTAs     int32
}

type UEAmPolicys []UEAmPolicy

func HandleOAMGetAmPolicyRequest(
	c *gin.Context,
	supi string) {
	// step 1: log
	logger.OamLog.Infof("Handle OAMGetAmPolicy")

	// step 2: retrieve request

	// step 3: handle the message
	response, problemDetails := OAMGetAmPolicyProcedure(supi)

	if response != nil {
		c.JSON(http.StatusOK, response)
		return
	} else if problemDetails != nil {
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	c.JSON(int(problemDetails.Status), problemDetails)

	// step 4: process the return value from step 3
	// if response != nil {
	// 	// status code is based on SPEC, and option headers
	// 	return httpwrapper.NewResponse(http.StatusOK, nil, response)
	// } else if problemDetails != nil {
	// 	return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	// }
	// problemDetails = &models.ProblemDetails{
	// 	Status: http.StatusForbidden,
	// 	Cause:  "UNSPECIFIED",
	// }
	// return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func OAMGetAmPolicyProcedure(supi string) (response *UEAmPolicys, problemDetails *models.ProblemDetails) {
	logger.OamLog.Infof("Handle OAM Get Am Policy")
	response = &UEAmPolicys{}
	pcfSelf := context.GetSelf()

	if val, exists := pcfSelf.UePool.Load(supi); exists {
		ue := val.(*context.UeContext)
		for _, amPolicy := range ue.AMPolicyData {
			ueAmPolicy := UEAmPolicy{
				PolicyAssociationID: amPolicy.PolAssoId,
				AccessType:          amPolicy.AccessType,
				Rfsp:                strconv.Itoa(int(amPolicy.Rfsp)),
				Triggers:            amPolicy.Triggers,
			}
			if amPolicy.ServAreaRes != nil {
				servAreaRes := amPolicy.ServAreaRes
				ueAmPolicy.RestrictionType = servAreaRes.RestrictionType
				ueAmPolicy.Areas = servAreaRes.Areas
				ueAmPolicy.MaxNumOfTAs = servAreaRes.MaxNumOfTAs
			}
			*response = append(*response, ueAmPolicy)
		}
		return response, nil
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
		}
		return nil, problemDetails
	}
}
