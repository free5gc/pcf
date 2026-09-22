package util

import (
	"testing"

	"github.com/free5gc/openapi/models"
)

func TestSearchNFServiceUri(t *testing.T) {
	const bareAMFAddress = "amf.5gc.mnc077.mcc222.3gppnetwork.org:80"

	tests := []struct {
		name     string
		profile  models.Nrf_NFDisc_NFProfile
		expected string
	}{
		{
			name: "add service scheme to profile FQDN",
			profile: models.Nrf_NFDisc_NFProfile{
				Fqdn: bareAMFAddress,
				NfServices: []models.Nrf_NFDisc_NFService{
					{
						ServiceName:     models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
						Scheme:          models.UriScheme_HTTP,
						NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
					},
				},
			},
			expected: "http://" + bareAMFAddress,
		},
		{
			name: "add service scheme to service FQDN",
			profile: models.Nrf_NFDisc_NFProfile{
				NfServices: []models.Nrf_NFDisc_NFService{
					{
						ServiceName:     models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
						Scheme:          models.UriScheme_HTTPS,
						NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
						Fqdn:            bareAMFAddress,
					},
				},
			},
			expected: "https://" + bareAMFAddress,
		},
		{
			name: "keep absolute API prefix",
			profile: models.Nrf_NFDisc_NFProfile{
				NfServices: []models.Nrf_NFDisc_NFService{
					{
						ServiceName:     models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
						Scheme:          models.UriScheme_HTTP,
						NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
						ApiPrefix:       "http://192.0.2.10:8000",
					},
				},
			},
			expected: "http://192.0.2.10:8000",
		},
		{
			name: "add service scheme to bare API prefix",
			profile: models.Nrf_NFDisc_NFProfile{
				NfServices: []models.Nrf_NFDisc_NFService{
					{
						ServiceName:     models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
						Scheme:          models.UriScheme_HTTP,
						NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
						ApiPrefix:       bareAMFAddress,
					},
				},
			},
			expected: "http://" + bareAMFAddress,
		},
		{
			name: "keep IP endpoint behavior",
			profile: models.Nrf_NFDisc_NFProfile{
				NfServices: []models.Nrf_NFDisc_NFService{
					{
						ServiceName:     models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
						Scheme:          models.UriScheme_HTTP,
						NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
						IpEndPoints: []models.Nrf_NFMgmt_IpEndPoint{
							{Ipv4Address: "192.0.2.10", Port: 8080},
						},
					},
				},
			},
			expected: "http://192.0.2.10:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := SearchNFServiceUri(
				tt.profile,
				models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
				models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
			)
			if actual != tt.expected {
				t.Errorf("SearchNFServiceUri() = %q, want %q", actual, tt.expected)
			}
		})
	}
}
