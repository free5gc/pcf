package httpcallback

import (
	"free5gc/lib/http_wrapper"
	"free5gc/lib/openapi/models"
	"free5gc/src/pcf/handler/message"
	"free5gc/src/pcf/logger"
	"github.com/gin-gonic/gin"
	"net/http"
)

func AmfStatusChangeNotify(c *gin.Context) {
	var request models.AmfStatusChangeNotification

	err := c.ShouldBindJSON(&request)
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CallbackLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := http_wrapper.NewRequest(c.Request, request)

	channelMsg := message.NewHttpChannelMessage(message.EventAMFStatusChangeNotify, req)
	message.SendMessage(channelMsg)

	recvMsg := <-channelMsg.HttpChannel
	HTTPResponse := recvMsg.HTTPResponse
	c.JSON(HTTPResponse.Status, HTTPResponse.Body)
}
