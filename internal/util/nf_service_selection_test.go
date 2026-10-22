package util

import (
	"testing"

	"github.com/free5gc/openapi/models"
)

func TestEdgeServiceSelection(t *testing.T) {
	const expectedURI = "http://10.101.200.28:8000"

	makeService := func(
		name models.Nrf_NFMgmt_ServiceName,
		status models.Nrf_NFMgmt_NFServiceStatus,
		ip string,
	) models.Nrf_NFDisc_NFService {
		service := models.Nrf_NFDisc_NFService{
			ServiceName:     name,
			NfServiceStatus: status,
			Scheme:          models.UriScheme_HTTP,
		}

		if ip != "" {
			service.IpEndPoints = []models.Nrf_NFMgmt_IpEndPoint{
				{
					Ipv4Address: ip,
					Port:        8000,
				},
			}
		}

		return service
	}

	valid := makeService(
		models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
		models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
		"10.101.200.28",
	)

	wrongName := makeService(
		models.Nrf_NFMgmt_ServiceName_NUDR_DR,
		models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
		"10.101.200.28",
	)

	notRegistered := makeService(
		models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
		models.Nrf_NFMgmt_NFServiceStatus("SUSPENDED"),
		"10.101.200.28",
	)

	noEndpoint := makeService(
		models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
		models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
		"",
	)

	cases := []struct {
		name     string
		services []models.Nrf_NFDisc_NFService
		want     string
	}{
		{
			name: "NoServices",
			want: "",
		},
		{
			name: "WrongServiceName",
			services: []models.Nrf_NFDisc_NFService{
				wrongName,
			},
			want: "",
		},
		{
			name: "ServiceNotRegistered",
			services: []models.Nrf_NFDisc_NFService{
				notRegistered,
			},
			want: "",
		},
		{
			name: "NoAvailableEndpoint",
			services: []models.Nrf_NFDisc_NFService{
				noEndpoint,
			},
			want: "",
		},
		{
			name: "SkipWrongService",
			services: []models.Nrf_NFDisc_NFService{
				wrongName,
				valid,
			},
			want: expectedURI,
		},
		{
			name: "SkipUnregisteredService",
			services: []models.Nrf_NFDisc_NFService{
				notRegistered,
				valid,
			},
			want: expectedURI,
		},
		{
			name: "SkipServiceWithoutEndpoint",
			services: []models.Nrf_NFDisc_NFService{
				noEndpoint,
				valid,
			},
			want: expectedURI,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profile := models.Nrf_NFDisc_NFProfile{
				NfServices: tc.services,
			}

			got := SearchNFServiceUri(
				profile,
				models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
				models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
			)

			if got != tc.want {
				t.Fatalf(
					"Unexpected API Root: got %q, want %q",
					got,
					tc.want,
				)
			}

			t.Logf("Service selection PASS: %q", got)
		})
	}
}
