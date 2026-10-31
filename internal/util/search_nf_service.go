package util

import (
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/util/serviceuri"
)

// SearchNFServiceUri selects an NF instance from an NRF discovery result and
// returns the API root of service name, or "" if no instance is usable.
func SearchNFServiceUri(instances []models.Nrf_NFDisc_NFProfile, name models.Nrf_NFMgmt_ServiceName) string {
	// NFs that still register a full URL as apiPrefix remain reachable.
	_, uri, err := serviceuri.ResolveFromSearchResult(instances, name,
		serviceuri.Options{AllowLegacyAbsoluteAPIPrefix: true})
	if err != nil {
		logger.UtilLog.Warnf("NF service %s API root resolution failed: %v", name, err)
		return ""
	}
	return uri
}
