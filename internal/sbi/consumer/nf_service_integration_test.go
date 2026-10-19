package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/free5gc/openapi/amf/Comm"
	"github.com/free5gc/openapi/models"
	pcfutil "github.com/free5gc/pcf/internal/util"
)

func newNFServiceProfile(
	scheme models.UriScheme,
	fqdn, prefix string,
	endpoints []models.Nrf_NFMgmt_IpEndPoint,
) models.Nrf_NFDisc_NFProfile {
	return models.Nrf_NFDisc_NFProfile{
		NfInstanceId: "test-amf-instance",
		NfType:       models.Nrf_NFMgmt_NFType_AMF,
		NfStatus:     models.Nrf_NFMgmt_NFStatus_REGISTERED,
		NfServices: []models.Nrf_NFDisc_NFService{
			{
				ServiceInstanceId: "test-namf-comm-instance",
				ServiceName:       models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
				Versions: []models.Nrf_NFMgmt_NFServiceVersion{
					{
						ApiVersionInUri: "v1",
						ApiFullVersion:  "1.0.0",
					},
				},
				Scheme:          scheme,
				NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
				Fqdn:            fqdn,
				ApiPrefix:       prefix,
				IpEndPoints:     endpoints,
			},
		},
	}
}

func resolveNFServiceForTest(
	profile models.Nrf_NFDisc_NFProfile,
) string {
	return pcfutil.SearchNFServiceUri(
		profile,
		models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
		models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
	)
}

func TestStandardAPIRoot(t *testing.T) {
	tests := []struct {
		name    string
		profile models.Nrf_NFDisc_NFProfile
		want    string
	}{
		{
			name: "HTTP_IP_NoPrefix",
			profile: newNFServiceProfile(
				models.UriScheme_HTTP,
				"",
				"",
				[]models.Nrf_NFMgmt_IpEndPoint{
					{Ipv4Address: "10.101.200.18", Port: 8000},
				},
			),
			want: "http://10.101.200.18:8000",
		},
		{
			name: "HTTP_IP_PathPrefix",
			profile: newNFServiceProfile(
				models.UriScheme_HTTP,
				"",
				"/operator/edge",
				[]models.Nrf_NFMgmt_IpEndPoint{
					{Ipv4Address: "10.101.200.18", Port: 8000},
				},
			),
			want: "http://10.101.200.18:8000/operator/edge",
		},
		{
			name: "HTTPS_ServiceFQDN_PathPrefix",
			profile: newNFServiceProfile(
				models.UriScheme_HTTPS,
				"amf.example.org",
				"/sbi",
				[]models.Nrf_NFMgmt_IpEndPoint{
					{Port: 8443},
				},
			),
			want: "https://amf.example.org:8443/sbi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveNFServiceForTest(tt.profile)

			if got != tt.want {
				t.Fatalf(
					"API Root mismatch:\ngot:  %q\nwant: %q",
					got, tt.want,
				)
			}

			parsed, err := url.Parse(got)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Host == "" ||
				(parsed.Scheme != "http" &&
					parsed.Scheme != "https") {
				t.Fatalf("Invalid API Root: %q", got)
			}

			t.Logf("API Root PASS: %s", got)
		})
	}
}

func TestStandardAMFClient(t *testing.T) {
	const prefix = "/operator/edge"
	const expectedPath = "/operator/edge/namf-comm/v1/subscriptions"

	var calls atomic.Int32
	var server *httptest.Server

	server = httptest.NewServer(
		h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)

			if r.Method != http.MethodPost {
				http.Error(w, "Unexpected method", http.StatusMethodNotAllowed)
				return
			}

			if r.URL.Path != expectedPath {
				http.Error(w, "Unexpected URI path", http.StatusNotFound)
				return
			}

			if r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "Unexpected Content-Type", http.StatusUnsupportedMediaType)
				return
			}

			var subscription models.Amf_Comm_SubscriptionData

			if err := json.NewDecoder(r.Body).Decode(&subscription); err != nil {
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}

			if subscription.AmfStatusUri == "" ||
				len(subscription.GuamiList) != 1 {
				http.Error(w, "Invalid subscription data", http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set(
				"Location",
				server.URL+expectedPath+"/test-subscription-1",
			)
			w.WriteHeader(http.StatusCreated)

			if err := json.NewEncoder(w).Encode(subscription); err != nil {
				t.Errorf("Response encoding failed: %v", err)
			}
		}), &http2.Server{}),
	)
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}

	profile := newNFServiceProfile(
		models.UriScheme_HTTP,
		"",
		prefix,
		[]models.Nrf_NFMgmt_IpEndPoint{
			{
				Ipv4Address: parsed.Hostname(),
				Port:        int32(port),
			},
		},
	)

	apiRoot := resolveNFServiceForTest(profile)
	expectedRoot := server.URL + prefix

	if apiRoot != expectedRoot {
		t.Fatalf(
			"API Root mismatch: got %q, want %q",
			apiRoot, expectedRoot,
		)
	}

	service := &namfService{
		nfComClients: make(map[string]*Comm.APIClient),
	}

	client := service.getNFCommunicationClient(apiRoot)
	if client == nil {
		t.Fatal("AMF client is nil")
	}

	subscriptionData := models.Amf_Comm_SubscriptionData{
		AmfStatusUri: "http://pcf.example.org/npcf-callback/v1/amfstatus",
		GuamiList: []models.Guami{
			{
				PlmnId: &models.PlmnIdNid{
					Mcc: "208",
					Mnc: "93",
				},
				AmfId: "cafe00",
			},
		},
	}

	request := &Comm.AMFStatusChangeSubscribeRequest{}
	request.SetRequestBody(subscriptionData)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	response, err := client.
		SubscriptionsCollectionCollectionApi.
		AMFStatusChangeSubscribe(ctx, request)

	if err != nil {
		t.Fatalf("AMF Subscription failed: %v", err)
	}

	if response == nil ||
		response.Location != server.URL+expectedPath+"/test-subscription-1" {
		t.Fatalf("Unexpected subscription response: %+v", response)
	}

	if calls.Load() != 1 {
		t.Fatalf("Expected 1 HTTP request, got %d", calls.Load())
	}

	t.Logf("Standard API Root: %s", apiRoot)
	t.Logf("AMF Request Path: %s", expectedPath)
	t.Logf("AMF Location: %s", response.Location)
	t.Log(fmt.Sprintf("Standard AMF OpenAPI subscription: PASS"))
}
