package consumer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/free5gc/openapi/amf/Comm"
	"github.com/free5gc/openapi/models"
	pcf_util "github.com/free5gc/pcf/internal/util"
)

// free5gc/free5gc#1173: the AMF API root resolved from an NRF discovery result
// (scheme + IP endpoint + apiPrefix) must be usable by the Namf_Communication
// client for AMFStatusChangeSubscribe.
func TestAMFStatusChangeSubscribeWithResolvedAPIRoot(t *testing.T) {
	const prefix = "/operator/edge"
	const path = prefix + "/namf-comm/v1/subscriptions"

	// The openapi client uses HTTP/2 without TLS (h2c) for the http scheme.
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != path {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		var data models.Amf_Comm_SubscriptionData
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", "http://"+r.Host+path+"/1")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(data); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}

	instances := []models.Nrf_NFDisc_NFProfile{{
		NfInstanceId: "amf-1",
		NfServices: []models.Nrf_NFDisc_NFService{{
			ServiceName:     models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
			NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
			Scheme:          models.UriScheme_HTTP,
			ApiPrefix:       prefix,
			IpEndPoints:     []models.Nrf_NFMgmt_IpEndPoint{{Ipv4Address: u.Hostname(), Port: int32(port)}},
		}},
	}}
	apiRoot := pcf_util.SearchNFServiceUri(instances, models.Nrf_NFMgmt_ServiceName_NAMF_COMM)
	if apiRoot != server.URL+prefix {
		t.Fatalf("API root = %q, want %q", apiRoot, server.URL+prefix)
	}

	s := &namfService{nfComClients: make(map[string]*Comm.APIClient)}
	req := &Comm.AMFStatusChangeSubscribeRequest{}
	req.SetRequestBody(models.Amf_Comm_SubscriptionData{
		AmfStatusUri: "http://pcf.example.org/npcf-callback/v1/amfstatus",
		GuamiList:    []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rsp, err := s.getNFCommunicationClient(apiRoot).SubscriptionsCollectionCollectionApi.
		AMFStatusChangeSubscribe(ctx, req)
	if err != nil {
		t.Fatalf("AMFStatusChangeSubscribe failed: %v", err)
	}
	if rsp == nil || rsp.Location != server.URL+path+"/1" {
		t.Fatalf("unexpected response: %+v", rsp)
	}
}
