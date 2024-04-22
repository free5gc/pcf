package consumer

import (
	"context"

	"github.com/free5gc/pcf/pkg/factory"
	"github.com/free5gc/openapi/Nnrf_NFDiscovery"
	"github.com/free5gc/openapi/Nnrf_NFManagement"
	
	pcf_context "github.com/free5gc/pcf/internal/context"
)

type pcf interface {
	Config() *factory.Config
	Context() *pcf_context.PCFContext
	CancelContext() context.Context
}

type Consumer struct {
	pcf

	// consumer services
	*nnrfService
}

func NewConsumer(pcf pcf) (*Consumer, error) {
	c := &Consumer{
		pcf: pcf,
	}

	c.nnrfService = &nnrfService{
		consumer:        c,
		nfMngmntClients: make(map[string]*Nnrf_NFManagement.APIClient),
		nfDiscClients:   make(map[string]*Nnrf_NFDiscovery.APIClient),
	}

	return c, nil
}