package processor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/sbi/consumer"
)

type amCreateTestPCF struct {
	PCF
	ctx      *pcf_context.PCFContext
	consumer *consumer.Consumer
}

func (a *amCreateTestPCF) Context() *pcf_context.PCFContext { return a.ctx }
func (a *amCreateTestPCF) Consumer() *consumer.Consumer     { return a.consumer }
func (a *amCreateTestPCF) CancelContext() context.Context   { return context.Background() }

func amCreateFixture(t *testing.T, discover bool, udr http.HandlerFunc) (*Processor, *pcf_context.PCFContext) {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/nnrf-disc/") {
			if !discover {
				writeAMTestResponse(t, w, `{"nfInstances":[]}`)
				return
			}
			if err := json.NewEncoder(w).Encode(map[string]interface{}{"nfInstances": []interface{}{
				map[string]interface{}{
					"nfInstanceId": "udr-test", "nfType": "UDR", "nfStatus": "REGISTERED",
					"nfServices": []interface{}{
						map[string]interface{}{
							"serviceInstanceId": "dr", "serviceName": "nudr-dr", "nfServiceStatus": "REGISTERED",
							"scheme": "http", "apiPrefix": server.URL,
						},
					},
				},
			}}); err != nil {
				t.Error(err)
			}
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/am-data") {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		udr(w, r)
	}))
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server.Config.Protocols = protocols
	server.Start()
	t.Cleanup(server.Close)
	ctx := &pcf_context.PCFContext{NrfUri: server.URL}
	app := &amCreateTestPCF{ctx: ctx}
	var err error
	app.consumer, err = consumer.NewConsumer(app)
	if err != nil {
		t.Fatal(err)
	}
	return &Processor{PCF: app}, ctx
}

func amRequest(supi string) models.Pcf_AMPolCtrl_PolicyAssociationRequest {
	return models.Pcf_AMPolCtrl_PolicyAssociationRequest{
		Supi: supi, SuppFeat: "0", NotificationUri: "http://amf.example/callback",
	}
}

func TestAMCreateFailureDoesNotRetainUE(t *testing.T) {
	for _, mode := range []string{"not_found", "invalid_response", "no_udr"} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/existing=%t", mode, existing), func(t *testing.T) {
				p, ctx := amCreateFixture(t, mode != "no_udr", func(w http.ResponseWriter, r *http.Request) {
					if mode == "invalid_response" {
						writeAMTestResponse(t, w, `invalid-json`)
						return
					}
					w.WriteHeader(http.StatusNotFound)
					writeAMTestResponse(t, w, `{"status":404,"cause":"USER_UNKNOWN"}`)
				})
				for i := 0; i < 20; i++ {
					supi := fmt.Sprintf("imsi-%015d", i/2)
					var original *pcf_context.UeContext
					if existing {
						var err error
						original, err = ctx.NewPCFUe(supi)
						if err != nil {
							t.Fatal(err)
						}
						original.AMPolicyData["existing-am"] = &pcf_context.UeAMPolicyData{PolAssoId: "existing-am"}
						original.SmPolicyData["existing-sm"] = &pcf_context.UeSmPolicyData{}
					}
					response, location, problem := p.PostPoliciesProcedure("", amRequest(supi))
					if response != nil || location != "" || problem == nil {
						t.Fatal("expected failed creation")
					}
					value, found := ctx.UePool.Load(supi)
					if !existing && found {
						t.Fatal("failed create retained a new UE")
					}
					if existing && (!found || value != original || len(original.AMPolicyData) != 1 ||
						len(original.SmPolicyData) != 1 || original.PolAssociationIDGenerator != 1) {
						t.Fatal("failed create removed or changed existing policies")
					}
				}
			})
		}
	}
}

func TestAMCreateConcurrentPublication(t *testing.T) {
	for _, failFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("firstFails=%t", failFirst), func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			var calls atomic.Int32
			p, ctx := amCreateFixture(t, true, func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					close(entered)
					<-release
					if failFirst {
						w.WriteHeader(http.StatusNotFound)
						writeAMTestResponse(t, w, `{"status":404,"cause":"USER_UNKNOWN"}`)
						return
					}
				}
				writeAMTestResponse(t, w, `{}`)
			})
			supi := "imsi-001010000000001"
			done := make(chan bool, 1)
			go func() {
				response, _, problem := p.PostPoliciesProcedure("", amRequest(supi))
				done <- (response != nil && problem == nil)
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("first request did not reach UDR")
			}
			// The first candidate must remain private while waiting for the UDR.
			if _, found := ctx.UePool.Load(supi); found {
				close(release)
				<-done
				t.Fatal("UE published before UDR success")
			}
			response, location, problem := p.PostPoliciesProcedure("", amRequest(supi))
			value, found := ctx.UePool.Load(supi)
			close(release)
			var firstSucceeded bool
			select {
			case firstSucceeded = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("create did not finish")
			}
			if response == nil || problem != nil || !strings.HasSuffix(location, supi+"-1") || !found {
				t.Fatal("successful create was not retained")
			}
			if firstSucceeded == failFirst {
				t.Fatal("unexpected first request result")
			}
			current, _ := ctx.UePool.Load(supi)
			if current != value {
				t.Fatal("concurrent request replaced the successful UE")
			}
			ue := current.(*pcf_context.UeContext)
			want := 1
			if !failFirst {
				want = 2
			}
			if len(ue.AMPolicyData) != want || ue.PolAssociationIDGenerator != uint32(want+1) {
				t.Fatal("lost or duplicated association")
			}
		})
	}
}

func writeAMTestResponse(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()
	if _, err := w.Write([]byte(body)); err != nil {
		t.Error(err)
	}
}
