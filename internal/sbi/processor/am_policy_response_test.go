package processor

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	pcf_context "github.com/free5gc/pcf/internal/context"
)

type blockedAMPolicyWriter struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
}

func (w *blockedAMPolicyWriter) Write(b []byte) (int, error) {
	close(w.entered)
	<-w.release
	return w.ResponseRecorder.Write(b)
}

func TestSlowGETDoesNotBlockDelete(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := &pcf_context.PCFContext{}
	ue, err := ctx.NewPCFUe("imsi-001010000000001")
	if err != nil {
		t.Fatal(err)
	}
	id := ue.Supi + "-1"
	ue.AMPolicyData[id] = &pcf_context.UeAMPolicyData{PolAssoId: id}
	p := &Processor{PCF: &allocationTestPCF{ctx: ctx}}
	w := &blockedAMPolicyWriter{httptest.NewRecorder(), make(chan struct{}), make(chan struct{})}
	c, _ := gin.CreateTestContext(w)
	getDone := make(chan struct{})
	go func() {
		p.HandleGetPoliciesPolAssoId(c, id)
		close(getDone)
	}()
	<-w.entered
	deleteDone := make(chan struct{})
	d, _ := gin.CreateTestContext(httptest.NewRecorder())
	go func() {
		p.HandleDeletePoliciesPolAssoId(d, id)
		close(deleteDone)
	}()
	select {
	case <-deleteDone:
	case <-time.After(time.Second):
		t.Error("delete waits for slow GET response writer while holding AMPolicyMu")
	}
	close(w.release)
	<-getDone
	<-deleteDone
}
