package sbi

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/sbi/consumer"
	"github.com/free5gc/pcf/internal/sbi/processor"
	"github.com/free5gc/pcf/internal/util"
	"github.com/free5gc/pcf/pkg/app"
	"github.com/free5gc/pcf/pkg/factory"
	"github.com/free5gc/util/httpwrapper"
	logger_util "github.com/free5gc/util/logger"
	"github.com/free5gc/util/metrics"
)

type Route struct {
	Name    string
	Method  string
	Pattern string
	APIFunc gin.HandlerFunc
}

func applyRoutes(group *gin.RouterGroup, routes []Route) {
	for _, route := range routes {
		switch route.Method {
		case "GET":
			group.GET(route.Pattern, route.APIFunc)
		case "POST":
			group.POST(route.Pattern, route.APIFunc)
		case "PUT":
			group.PUT(route.Pattern, route.APIFunc)
		case "PATCH":
			group.PATCH(route.Pattern, route.APIFunc)
		case "DELETE":
			group.DELETE(route.Pattern, route.APIFunc)
		}
	}
}

type pcf interface {
	app.App
	Processor() *processor.Processor
	Consumer() *consumer.Consumer
	CancelContext() context.Context
}

type Server struct {
	pcf

	httpServer *http.Server
	router     *gin.Engine
}

func NewServer(pcf pcf, tlsKeyLogPath string) (*Server, error) {
	s := &Server{
		pcf:    pcf,
		router: logger_util.NewGinWithLogrus(logger.GinLog),
	}

	s.router.Use(metrics.InboundMetrics())

	for _, api := range []struct {
		name   models.Nrf_NFMgmt_ServiceName
		prefix string
		routes []Route
	}{
		{models.Nrf_NFMgmt_ServiceName_NPCF_SMPOLICYCONTROL, factory.PcfSMpolicyCtlResUriPrefix, s.getSmPolicyRoutes()},
		{models.Nrf_NFMgmt_ServiceName_NPCF_AM_POLICY_CONTROL, factory.PcfAMpolicyCtlResUriPrefix, s.getAmPolicyRoutes()},
		{models.Nrf_NFMgmt_ServiceName_NPCF_BDTPOLICYCONTROL, factory.PcfBdtPolicyCtlResUriPrefix, s.getBdtPolicyRoutes()},
		{models.Nrf_NFMgmt_ServiceName_NPCF_OAM, factory.PcfOamResUriPrefix, s.getOamRoutes()},
		{
			models.Nrf_NFMgmt_ServiceName_NPCF_POLICYAUTHORIZATION,
			factory.PcfPolicyAuthResUriPrefix, s.getPolicyAuthorizationRoutes(),
		},
		{models.Nrf_NFMgmt_ServiceName_NPCF_UE_POLICY_CONTROL, factory.PcfUePolicyCtlResUriPrefix, s.getUePolicyRoutes()},
	} {
		realm, advertised := s.Context().PcfServiceUris[api.name]
		if !advertised {
			// Local routes such as OAM can be mounted without NRF advertisement.
			realm = s.Context().GetIPv4Uri() + strings.TrimSuffix(api.prefix, "/")
		}
		check, err := util.NewRouterAuthorizationCheck(api.name, realm)
		if err != nil {
			return nil, err
		}
		group := s.router.Group(api.prefix)
		if api.name == models.Nrf_NFMgmt_ServiceName_NPCF_OAM {
			group.Use(oamCorsMiddleware())
		}
		group.Use(func(c *gin.Context) { check.Check(c, s.Context()) })
		applyRoutes(group, api.routes)
	}

	// TS 29.500 Rel-17 §6.7.3 excludes notify operations from OAuth.
	applyRoutes(s.router.Group(factory.PcfCallbackResUriPrefix), s.getHttpCallBackRoutes())

	cfg := s.Config()
	bindAddr := cfg.GetSbiBindingAddr()
	logger.SBILog.Infof("Binding addr: [%s]", bindAddr)
	var err error
	if s.httpServer, err = httpwrapper.NewHttp2Server(
		bindAddr, tlsKeyLogPath, s.router, cfg.GetIdleTimeout(),
	); err != nil {
		logger.InitLog.Errorf("Initialize HTTP server failed: %v", err)
		return nil, err
	}
	s.httpServer.ErrorLog = log.New(logger.SBILog.WriterLevel(logrus.ErrorLevel), "HTTP2: ", 0)

	return s, nil
}

func (s *Server) Run(traceCtx context.Context, wg *sync.WaitGroup) error {
	ctx := s.CancelContext()
	if err := s.Consumer().SendRegisterNFInstance(ctx, true); err != nil {
		logger.InitLog.Errorf("PCF register to NRF Error[%s]", err.Error())
		return err
	}
	s.Consumer().StartHeartbeat(ctx, wg)

	wg.Add(1)
	go s.startServer(wg)

	return nil
}

func (s *Server) Shutdown(traceCtx context.Context) {
	const defaultShutdownTimeout time.Duration = 2 * time.Second

	if s.httpServer != nil {
		logger.SBILog.Infof("Stop SBI server (listen on %s)", s.httpServer.Addr)
		toCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
		defer cancel()
		if err := s.httpServer.Shutdown(toCtx); err != nil {
			logger.SBILog.Errorf("Could not close SBI server: %#v", err)
		}
	}
}

func (s *Server) startServer(wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.SBILog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			s.Terminate()
		}

		wg.Done()
	}()

	logger.SBILog.Infof("Start SBI server (listen on %s)", s.httpServer.Addr)

	var err error
	cfg := s.Config()
	scheme := cfg.GetSbiScheme()
	switch scheme {
	case "http":
		err = s.httpServer.ListenAndServe()
	case "https":
		err = s.httpServer.ListenAndServeTLS(
			cfg.GetCertPemPath(),
			cfg.GetCertKeyPath())
	default:
		err = fmt.Errorf("no support this scheme[%s]", scheme)
	}

	if err != nil && err != http.ErrServerClosed {
		logger.SBILog.Errorf("SBI server error: %v", err)
	}
	logger.SBILog.Infof("SBI server (listen on %s) stopped", s.httpServer.Addr)
}
