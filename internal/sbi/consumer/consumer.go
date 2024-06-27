package consumer

import (
	"context"

	"github.com/free5gc/openapi/Namf_Communication"
	"github.com/free5gc/openapi/Nnrf_NFDiscovery"
	"github.com/free5gc/openapi/Nnrf_NFManagement"
	"github.com/free5gc/openapi/Nudr_DataRepository"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/pkg/factory"
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
	*namfService
	*nudrService
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

	c.namfService = &namfService{
		consumer:     c,
		nfComClients: make(map[string]*Namf_Communication.APIClient),
	}

	c.nudrService = &nudrService{
		consumer:         c,
		nfDataSubClients: make(map[string]*Nudr_DataRepository.APIClient),
	}

	return c, nil
}
