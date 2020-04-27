package pcf_producer

import (
	"free5gc/lib/openapi/models"
	"free5gc/src/pcf/logger"
	"free5gc/src/pcf/pcf_context"
	"free5gc/src/pcf/pcf_handler/pcf_message"
	"net/http"
	"strconv"
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

func HandleOAMGetAmPolicy(httpChannel chan pcf_message.HttpResponseMessage, supi string) {
	logger.OamLog.Infof("Handle OAM Get Am Policy")

	var response UEAmPolicys
	pcfSelf := pcf_context.PCF_Self()

	if ue, exists := pcfSelf.UePool[supi]; exists {
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
			response = append(response, ueAmPolicy)
		}
		pcf_message.SendHttpResponseMessage(httpChannel, nil, http.StatusOK, response)
	} else {
		problem := models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
		}
		pcf_message.SendHttpResponseMessage(httpChannel, nil, http.StatusNotFound, problem)
	}
}
