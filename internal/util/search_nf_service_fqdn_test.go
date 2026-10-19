package util

import (
	"testing"

	"github.com/free5gc/openapi/models"
)

// TestServiceFQDN verifies that an API root
// is constructed from the service scheme, FQDN,
// endpoint port, and optional API prefix.
func TestServiceFQDN(t *testing.T) {
	profile := models.Nrf_NFDisc_NFProfile{
		NfServices: []models.Nrf_NFDisc_NFService{
			{
				ServiceName:     models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
				NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
				Scheme:          models.UriScheme_HTTP,
				Fqdn:            "amf.example.org",
				IpEndPoints: []models.Nrf_NFMgmt_IpEndPoint{
					{
						Port: 8000,
					},
				},
				ApiPrefix: "/custom",
			},
		},
	}

	got := SearchNFServiceUri(
		profile,
		models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
		models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
	)

	want := "http://amf.example.org:8000/custom"

	if got != want {
		t.Fatalf(
			"API root mismatch: got %q, want %q",
			got, want,
		)
	}
}

// TestHTTPSFQDN verifies HTTPS API-root
// construction without downgrading the scheme.
func TestHTTPSFQDN(t *testing.T) {
	profile := models.Nrf_NFDisc_NFProfile{
		NfServices: []models.Nrf_NFDisc_NFService{
			{
				ServiceName:     models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
				NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
				Scheme:          models.UriScheme_HTTPS,
				Fqdn:            "amf.example.org",
				IpEndPoints: []models.Nrf_NFMgmt_IpEndPoint{
					{
						Port: 8443,
					},
				},
				ApiPrefix: "/sbi",
			},
		},
	}

	got := SearchNFServiceUri(
		profile,
		models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
		models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
	)

	want := "https://amf.example.org:8443/sbi"

	if got != want {
		t.Fatalf(
			"API root mismatch: got %q, want %q",
			got, want,
		)
	}
}
