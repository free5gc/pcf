package logger

import (
	"fmt"
	"os"
	"runtime"
	"strings"

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

func init() {
	log = logrus.New()
	log.SetReportCaller(true)

	log.Formatter = &logrus.TextFormatter{
		ForceColors:               true,
		DisableColors:             false,
		EnvironmentOverrideColors: false,
		DisableTimestamp:          false,
		FullTimestamp:             true,
		TimestampFormat:           "",
		DisableSorting:            false,
		SortingFunc:               nil,
		DisableLevelTruncation:    false,
		QuoteEmptyFields:          false,
		FieldMap:                  nil,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			orgFilename, _ := os.Getwd()
			repopath := orgFilename
			repopath = strings.Replace(repopath, "/bin", "", 1)
			filename := strings.Replace(f.File, repopath, "", -1)
			return fmt.Sprintf("%s()", f.Function), fmt.Sprintf("%s:%d", filename, f.Line)
		},
	}

	free5gcLogHook, err := logger_util.NewFileHook(logger_conf.Free5gcLogFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err == nil {
		log.Hooks.Add(free5gcLogHook)
	}

	selfLogHook, err := logger_util.NewFileHook(logger_conf.NfLogDir+"pcf.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err == nil {
		log.Hooks.Add(selfLogHook)
	}

	AppLog = log.WithFields(logrus.Fields{"PCF": "app"})
	InitLog = log.WithFields(logrus.Fields{"PCF": "init"})
	HandlerLog = log.WithFields(logrus.Fields{"PCF": "Handler"})
	Bdtpolicylog = log.WithFields(logrus.Fields{"PCF": "bdtpolicy"})
	AMpolicylog = log.WithFields(logrus.Fields{"PCF": "ampolicy"})
	PolicyAuthorizationlog = log.WithFields(logrus.Fields{"PCF": "PolicyAuthorization"})
	SMpolicylog = log.WithFields(logrus.Fields{"PCF": "SMpolicy"})
	UtilLog = log.WithFields(logrus.Fields{"PCF": "Util"})
	CallbackLog = log.WithFields(logrus.Fields{"PCF": "Callback"})
	Consumerlog = log.WithFields(logrus.Fields{"PCF": "Consumer"})
	OamLog = log.WithFields(logrus.Fields{"PCF": "OAM"})
}

func SetLogLevel(level logrus.Level) {
	log.SetLevel(level)
}

func SetReportCaller(bool bool) {
	log.SetReportCaller(bool)
}
