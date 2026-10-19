package util

import (
	"strings"
	"testing"

	"github.com/free5gc/openapi/models"
)

func newNFServiceProfile(service models.Nrf_NFDisc_NFService) models.Nrf_NFDisc_NFProfile {
	service.ServiceName = models.Nrf_NFMgmt_ServiceName_NAMF_COMM
	service.NfServiceStatus = models.Nrf_NFMgmt_NFServiceStatus_REGISTERED
	return models.Nrf_NFDisc_NFProfile{NfServices: []models.Nrf_NFDisc_NFService{service}}
}

func resolveNFServiceForTest(p models.Nrf_NFDisc_NFProfile, opts ServiceURIOptions) (string, error) {
	return ResolveNFServiceURI(p, models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
		models.Nrf_NFMgmt_NFServiceStatus_REGISTERED, opts)
}

func TestAdditionalStandardURI(t *testing.T) {
	cases := []struct {
		name    string
		profile models.Nrf_NFDisc_NFProfile
		want    string
	}{
		{"HTTP service FQDN and default port", newNFServiceProfile(models.Nrf_NFDisc_NFService{
			Scheme: models.UriScheme_HTTP, Fqdn: "amf.example.org",
		}), "http://amf.example.org:80"},
		{"HTTPS service FQDN and explicit port", newNFServiceProfile(models.Nrf_NFDisc_NFService{
			Scheme: models.UriScheme_HTTPS, Fqdn: "amf.example.org",
			IpEndPoints: []models.Nrf_NFMgmt_IpEndPoint{{Port: 8443}}, ApiPrefix: "/sbi",
		}), "https://amf.example.org:8443/sbi"},
		{"direct HTTP service IP precedence", models.Nrf_NFDisc_NFProfile{
			Fqdn: "profile.example.org", NfServices: []models.Nrf_NFDisc_NFService{{
				ServiceName:     models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
				NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
				Scheme:          models.UriScheme_HTTP,
				IpEndPoints:     []models.Nrf_NFMgmt_IpEndPoint{{Ipv4Address: "192.0.2.20", Port: 8081}},
			}},
		}, "http://192.0.2.20:8081"},
		{"port only with profile FQDN", models.Nrf_NFDisc_NFProfile{
			Fqdn: "profile.example.org", NfServices: []models.Nrf_NFDisc_NFService{{
				ServiceName:     models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
				NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
				Scheme:          models.UriScheme_HTTP,
				IpEndPoints:     []models.Nrf_NFMgmt_IpEndPoint{{Port: 8080}},
			}},
		}, "http://profile.example.org:8080"},
		{"HTTPS profile FQDN and default port", models.Nrf_NFDisc_NFProfile{
			Fqdn: "profile.example.org", NfServices: []models.Nrf_NFDisc_NFService{{
				ServiceName:     models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
				NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
				Scheme:          models.UriScheme_HTTPS,
			}},
		}, "https://profile.example.org:443"},
		{"direct HTTP IPv6", newNFServiceProfile(models.Nrf_NFDisc_NFService{
			Scheme:      models.UriScheme_HTTP,
			IpEndPoints: []models.Nrf_NFMgmt_IpEndPoint{{Ipv6Address: "2001:db8::1", Port: 8000}},
			ApiPrefix:   "/api",
		}), "http://[2001:db8::1]:8000/api"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveNFServiceForTest(tt.profile, ServiceURIOptions{})
			if err != nil || got != tt.want {
				t.Fatalf("got %q, error %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestAdditionalLegacyCompatibility(t *testing.T) {
	p := newNFServiceProfile(models.Nrf_NFDisc_NFService{
		Scheme:      models.UriScheme_HTTP,
		ApiPrefix:   "http://amf.free5gc.org:8000",
		IpEndPoints: []models.Nrf_NFMgmt_IpEndPoint{{Ipv4Address: "192.0.2.11", Port: 8000}},
	})
	if _, err := resolveNFServiceForTest(p, ServiceURIOptions{}); err == nil {
		t.Fatal("strict mode must reject the non-standard absolute apiPrefix")
	}
	got, err := resolveNFServiceForTest(p, ServiceURIOptions{AllowLegacyAbsoluteAPIPrefix: true})
	if err != nil || got != "http://amf.free5gc.org:8000" {
		t.Fatalf("compatibility returned %q, %v", got, err)
	}
	got = SearchNFServiceUri(p, models.Nrf_NFMgmt_ServiceName_NAMF_COMM, models.Nrf_NFMgmt_NFServiceStatus_REGISTERED)
	if got != "http://amf.free5gc.org:8000" {
		t.Fatalf("legacy caller returned %q", got)
	}
}

func TestAdditionalInvalidInput(t *testing.T) {
	cases := []struct {
		name   string
		scheme models.UriScheme
		prefix string
		fqdn   string
	}{
		{"missing scheme", "", "/x", "amf.example.org"},
		{"bad scheme", "ftp", "/x", "amf.example.org"},
		{"relative prefix", models.UriScheme_HTTP, "bad", "amf.example.org"},
		{"query prefix", models.UriScheme_HTTP, "/x?admin=1", "amf.example.org"},
		{"authority prefix", models.UriScheme_HTTP, "//evil.example.org", "amf.example.org"},
		{"absolute prefix", models.UriScheme_HTTP, "http://evil.example.org", "amf.example.org"},
		{"missing FQDN for TLS", models.UriScheme_HTTPS, "/x", ""},
		{"invalid FQDN scheme", models.UriScheme_HTTP, "/x", "http://evil.example.org"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p := newNFServiceProfile(models.Nrf_NFDisc_NFService{
				Scheme: tt.scheme, Fqdn: tt.fqdn, ApiPrefix: tt.prefix,
			})
			if got, err := resolveNFServiceForTest(p, ServiceURIOptions{}); err == nil {
				t.Fatalf("accepted invalid case: %q", got)
			}
		})
	}
}

func TestAdditionalNFServiceList(t *testing.T) {
	p := models.Nrf_NFDisc_NFProfile{NfServiceList: map[string]models.Nrf_NFDisc_NFService{
		"comm": {
			ServiceName:     models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
			NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
			Scheme:          models.UriScheme_HTTP, Fqdn: "amf.example.org",
		},
	}}
	got, err := resolveNFServiceForTest(p, ServiceURIOptions{})
	if err != nil || got != "http://amf.example.org:80" {
		t.Fatalf("NFServiceList returned %q, %v", got, err)
	}
}

func TestAdditionalMultiIPv4(t *testing.T) {
	p := newNFServiceProfile(models.Nrf_NFDisc_NFService{
		Scheme: models.UriScheme_HTTP,
		IpEndPoints: []models.Nrf_NFMgmt_IpEndPoint{
			{Ipv4Address: "192.0.2.10", Port: 8080},
			{Ipv4Address: "192.0.2.11", Port: 8081},
		},
	})
	observed := map[string]bool{}
	for i := 0; i < 100; i++ {
		got, err := resolveNFServiceForTest(p, ServiceURIOptions{})
		if err != nil || (got != "http://192.0.2.10:8080" && got != "http://192.0.2.11:8081") {
			t.Fatalf("invalid multi-endpoint choice: %q, %v", got, err)
		}
		observed[got] = true
	}
	if len(observed) != 2 {
		t.Log("selection variation is probabilistic; both addresses not seen in this run")
	}
}

func TestAdditionalNoTLSFallbackToIP(t *testing.T) {
	p := newNFServiceProfile(models.Nrf_NFDisc_NFService{
		Scheme:      models.UriScheme_HTTPS,
		IpEndPoints: []models.Nrf_NFMgmt_IpEndPoint{{Ipv4Address: "192.0.2.10", Port: 8443}},
	})
	got, err := resolveNFServiceForTest(p, ServiceURIOptions{})
	if err == nil || strings.Contains(got, "192.0.2.10") {
		t.Fatalf("TLS must not silently use bare IP endpoint: got %q, %v", got, err)
	}
}
