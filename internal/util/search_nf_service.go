package util

import (
	"errors"
	"fmt"
	"sort"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pcf/internal/logger"
)

// Only a missing usable address permits trying the next matching NFService.
var errNFServiceAddressUnavailable = errors.New("NFService has no usable FQDN or IP address")

// SearchNFServiceUri preserves the API expected by existing PCF callers.
// It enables an explicitly logged compatibility path for free5GC's historical
// (non-3GPP) absolute-URL apiPrefix registration convention.
func SearchNFServiceUri(profile models.Nrf_NFDisc_NFProfile, name models.Nrf_NFMgmt_ServiceName,
	status models.Nrf_NFMgmt_NFServiceStatus,
) string {
	uri, err := ResolveNFServiceURI(profile, name, status, ServiceURIOptions{
		AllowLegacyAbsoluteAPIPrefix: true,
	})
	if err != nil {
		logger.UtilLog.Warnf("NF Service API root resolution failed: %v", err)
		return ""
	}
	return uri
}

// ResolveNFServiceURI is the strict / policy-aware resolver, and returns an
// error instead of passing an invalid BasePath to OpenAPI.
func ResolveNFServiceURI(profile models.Nrf_NFDisc_NFProfile, name models.Nrf_NFMgmt_ServiceName,
	status models.Nrf_NFMgmt_NFServiceStatus, opts ServiceURIOptions,
) (string, error) {
	var lastAddressError error
	for _, service := range profile.NfServices {
		if service.ServiceName == name && service.NfServiceStatus == status {
			uri, err := buildNFServiceURI(profile, service, opts)
			if errors.Is(err, errNFServiceAddressUnavailable) {
				lastAddressError = err
				continue
			}
			return uri, err
		}
	}

	// Discovery may represent services by nfServiceList instead of nfServices.
	// Sorting the keys keeps error/selection behavior reproducible in tests.
	keys := make([]string, 0, len(profile.NfServiceList))
	for key := range profile.NfServiceList {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		service := profile.NfServiceList[key]
		if service.ServiceName == name && service.NfServiceStatus == status {
			uri, err := buildNFServiceURI(profile, service, opts)
			if errors.Is(err, errNFServiceAddressUnavailable) {
				lastAddressError = err
				continue
			}
			return uri, err
		}
	}
	if lastAddressError != nil {
		return "", lastAddressError
	}
	return "", fmt.Errorf("NF service %q with status %q not found", name, status)
}
