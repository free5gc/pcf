package oam

import (
	"github.com/gin-gonic/gin"
	"free5gc/lib/http_wrapper"
	"free5gc/src/pcf/handler/message"
)

func setCorsHeader(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, PATCH, DELETE")
}

func OAMGetAmPolicy(c *gin.Context) {
	setCorsHeader(c)

	req := http_wrapper.NewRequest(c.Request, nil)
	req.Params["supi"] = c.Params.ByName("supi")

	handlerMsg := message.NewHttpChannelMessage(message.EventOAMGetAmPolicy, req)
	message.SendMessage(handlerMsg)

	rsp := <-handlerMsg.HttpChannel

	HTTPResponse := rsp.HTTPResponse

	c.JSON(HTTPResponse.Status, HTTPResponse.Body)
}
