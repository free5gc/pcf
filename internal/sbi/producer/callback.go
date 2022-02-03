package producer

import (
	"net/http"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/util/httpwrapper"
)

func HandleAmfStatusChangeNotify(request *httpwrapper.Request) *httpwrapper.Response {
	logger.CallbackLog.Warnf("[PCF] Handle Amf Status Change Notify is not implemented.")

	notification := request.Body.(models.AmfStatusChangeNotification)

	AmfStatusChangeNotifyProcedure(notification)

	return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
}

// TODO: handle AMF Status Change Notify
func AmfStatusChangeNotifyProcedure(notification models.AmfStatusChangeNotification) {
	logger.CallbackLog.Debugf("receive AMF status change notification[%+v]", notification)
}

func HandleSmPolicyNotify(request *httpwrapper.Request) *httpwrapper.Response {
	logger.CallbackLog.Warnf("[PCF] Handle Sm Policy Notify is not implemented.")

	notification := request.Body.(models.PolicyDataChangeNotification)
	supi := request.Params["ReqURI"]

	SmPolicyNotifyProcedure(supi, notification)

	return httpwrapper.NewResponse(http.StatusNotImplemented, nil, nil)
}

// TODO: handle SM Policy Notify
func SmPolicyNotifyProcedure(supi string, notification models.PolicyDataChangeNotification) {
}
