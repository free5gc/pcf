package context

import (
	"slices"

	"github.com/free5gc/openapi/models"
)

const (
	ServiceNameNAMFCallback models.Nrf_NFMgmt_ServiceName = "namf-callback"
	ServiceNameNPCFCallback models.Nrf_NFMgmt_ServiceName = "npcf-callback"
)

var servicePolicies = map[models.Nrf_NFMgmt_ServiceName][]models.Nrf_NFMgmt_NFType{
	models.Nrf_NFMgmt_ServiceName_NPCF_AM_POLICY_CONTROL: {
		models.Nrf_NFMgmt_NFType_AMF,
	},
	models.Nrf_NFMgmt_ServiceName_NPCF_SMPOLICYCONTROL: {
		models.Nrf_NFMgmt_NFType_SMF,
	},
	models.Nrf_NFMgmt_ServiceName_NPCF_BDTPOLICYCONTROL: {
		models.Nrf_NFMgmt_NFType_NEF,
	},
	models.Nrf_NFMgmt_ServiceName_NPCF_POLICYAUTHORIZATION: {
		models.Nrf_NFMgmt_NFType_AF,
		models.Nrf_NFMgmt_NFType_NEF,
	},
	models.Nrf_NFMgmt_ServiceName_NPCF_EVENTEXPOSURE: {
		models.Nrf_NFMgmt_NFType_NEF,
		models.Nrf_NFMgmt_NFType_AF,
		models.Nrf_NFMgmt_NFType_NWDAF,
		models.Nrf_NFMgmt_NFType_DCCF,
	},
	models.Nrf_NFMgmt_ServiceName_NPCF_UE_POLICY_CONTROL: {
		models.Nrf_NFMgmt_NFType_AMF,
		models.Nrf_NFMgmt_NFType_PCF,
	},
	ServiceNameNPCFCallback: {
		models.Nrf_NFMgmt_NFType_AMF,
		models.Nrf_NFMgmt_NFType_UDR,
	},
	// OAM authentication is out of scope. Keep it explicitly known and unrestricted.
	models.Nrf_NFMgmt_ServiceName_NPCF_OAM: nil,
}

func AllowedNfTypesForService(
	serviceName models.Nrf_NFMgmt_ServiceName,
) ([]models.Nrf_NFMgmt_NFType, bool) {
	allowed, known := servicePolicies[serviceName]
	return slices.Clone(allowed), known
}
