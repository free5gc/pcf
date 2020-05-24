package pcf_producer

import (
	"free5gc/lib/openapi/models"
	"free5gc/src/pcf/handler/message"
	"free5gc/src/pcf/logger"
	"net/http"
)

func HandleAmfStatusChangeNotify(httpChannel chan message.HttpResponseMessage, notification models.AmfStatusChangeNotification) {
	logger.CallbackLog.Warnf("[PCF] Handle Amf Status Change Notify is not implemented.")
	logger.CallbackLog.Debugf("receive AMF status change notification[%+v]", notification)
	// TODO: handle AMF Status Change Notify
	message.SendHttpResponseMessage(httpChannel, nil, http.StatusNoContent, nil)
}
