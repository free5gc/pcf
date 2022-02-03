package logger

import (
	"os"
	"time"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"

	logger_util "github.com/free5gc/util/logger"
)

var (
	log                    *logrus.Logger
	AppLog                 *logrus.Entry
	InitLog                *logrus.Entry
	CfgLog                 *logrus.Entry
	HandlerLog             *logrus.Entry
	Bdtpolicylog           *logrus.Entry
	PolicyAuthorizationlog *logrus.Entry
	AMpolicylog            *logrus.Entry
	SMpolicylog            *logrus.Entry
	Consumerlog            *logrus.Entry
	UtilLog                *logrus.Entry
	CallbackLog            *logrus.Entry
	OamLog                 *logrus.Entry
	CtxLog                 *logrus.Entry
	ConsumerLog            *logrus.Entry
	GinLog                 *logrus.Entry
	NotifyEventLog         *logrus.Entry
)

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

	AppLog = log.WithFields(logrus.Fields{"component": "PCF", "category": "App"})
	InitLog = log.WithFields(logrus.Fields{"component": "PCF", "category": "Init"})
	CfgLog = log.WithFields(logrus.Fields{"component": "PCF", "category": "CFG"})
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
	ConsumerLog = log.WithFields(logrus.Fields{"component": "PCF", "category": "Consumer"})
	GinLog = log.WithFields(logrus.Fields{"component": "PCF", "category": "GIN"})
	NotifyEventLog = log.WithFields(logrus.Fields{"component": "PCF", "category": "NotifyEvent"})
}

func LogFileHook(logNfPath string, log5gcPath string) error {
	if fullPath, err := logger_util.CreateFree5gcLogFile(log5gcPath); err == nil {
		if fullPath != "" {
			free5gcLogHook, hookErr := logger_util.NewFileHook(fullPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
			if hookErr != nil {
				return hookErr
			}
			log.Hooks.Add(free5gcLogHook)
		}
	} else {
		return err
	}

	if fullPath, err := logger_util.CreateNfLogFile(logNfPath, "pcf.log"); err == nil {
		selfLogHook, hookErr := logger_util.NewFileHook(fullPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
		if hookErr != nil {
			return hookErr
		}
		log.Hooks.Add(selfLogHook)
	} else {
		return err
	}

	return nil
}

func SetLogLevel(level logrus.Level) {
	log.SetLevel(level)
}

func SetReportCaller(enable bool) {
	log.SetReportCaller(enable)
}
