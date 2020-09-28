package logger

import (
	"os"
	"time"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"

	"free5gc/lib/logger_conf"
	"free5gc/lib/logger_util"
)

var log *logrus.Logger
var AppLog *logrus.Entry
var InitLog *logrus.Entry
var HandlerLog *logrus.Entry
var Bdtpolicylog *logrus.Entry
var PolicyAuthorizationlog *logrus.Entry
var AMpolicylog *logrus.Entry
var SMpolicylog *logrus.Entry
var Consumerlog *logrus.Entry
var UtilLog *logrus.Entry
var CallbackLog *logrus.Entry
var OamLog *logrus.Entry
var CtxLog *logrus.Entry
var GinLog *logrus.Entry

func init() {
	log = logrus.New()
	log.SetReportCaller(false)

	log.Formatter = &formatter.Formatter{
		TimestampFormat: time.RFC3339,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category"},
	}

	free5gcLogHook, err := logger_util.NewFileHook(logger_conf.Free5gcLogFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err == nil {
		log.Hooks.Add(free5gcLogHook)
	}

	selfLogHook, err := logger_util.NewFileHook(logger_conf.NfLogDir+"pcf.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err == nil {
		log.Hooks.Add(selfLogHook)
	}

	AppLog = log.WithFields(logrus.Fields{"component": "PCF", "category": "App"})
	InitLog = log.WithFields(logrus.Fields{"component": "PCF", "category": "Init"})
	HandlerLog = log.WithFields(logrus.Fields{"component": "PCF", "category": "Handler"})
	Bdtpolicylog = log.WithFields(logrus.Fields{"component": "PCF", "category": "Bdtpolicy"})
	AMpolicylog = log.WithFields(logrus.Fields{"component": "PCF", "category": "Ampolicy"})
	PolicyAuthorizationlog = log.WithFields(logrus.Fields{"component": "PCF", "category": "PolicyAuth"})
	SMpolicylog = log.WithFields(logrus.Fields{"component": "PCF", "category": "SMpolicy"})
	UtilLog = log.WithFields(logrus.Fields{"component": "PCF", "category": "Util"})
	CallbackLog = log.WithFields(logrus.Fields{"component": "PCF", "category": "Callback"})
	Consumerlog = log.WithFields(logrus.Fields{"component": "PCF", "category": "Consumer"})
	OamLog = log.WithFields(logrus.Fields{"component": "PCF", "category": "OAM"})
	CtxLog = log.WithFields(logrus.Fields{"component": "PCF", "category": "Context"})
	GinLog = log.WithFields(logrus.Fields{"component": "PCF", "category": "GIN"})
}

func SetLogLevel(level logrus.Level) {
	log.SetLevel(level)
}

func SetReportCaller(bool bool) {
	log.SetReportCaller(bool)
}
