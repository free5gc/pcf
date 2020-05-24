package handler

import (
	"free5gc/lib/openapi/models"
	"free5gc/src/pcf/handler/message"
	"free5gc/src/pcf/logger"
	"free5gc/src/pcf/producer"
	"time"

	"github.com/sirupsen/logrus"
)

var HandlerLog *logrus.Entry

func init() {
	// init Pool
	HandlerLog = logger.HandlerLog
}

func Handle() {
	for {
		select {
		case msg, ok := <-message.PCFChannel:
			if ok {
				switch msg.Event {
				case message.EventBDTPolicyCreate:
					pcf_producer.CreateBDTPolicyContext(msg.HttpChannel, msg.HTTPRequest.Body.(models.BdtReqData))
				case message.EventBDTPolicyGet:
					bdtPolicyId := msg.HTTPRequest.Params["bdtPolicyId"]
					pcf_producer.GetBDTPolicyContext(msg.HttpChannel, bdtPolicyId)
				case message.EventBDTPolicyUpdate:
					bdtPolicyId := msg.HTTPRequest.Params["bdtPolicyId"]
					pcf_producer.UpdateBDTPolicyContext(msg.HttpChannel, bdtPolicyId, msg.HTTPRequest.Body.(models.BdtPolicyDataPatch))
				case message.EventPostAppSessions:
					pcf_producer.PostAppSessionsContext(msg.HttpChannel, msg.HTTPRequest.Body.(models.AppSessionContext))
				case message.EventGetAppSession:
					appSessionId := msg.HTTPRequest.Params["appSessionId"]
					pcf_producer.GetAppSessionContext(msg.HttpChannel, appSessionId)
				case message.EventDeleteAppSession:
					appSessionId := msg.HTTPRequest.Params["appSessionId"]
					pcf_producer.DeleteAppSessionContext(msg.HttpChannel, appSessionId, msg.HTTPRequest.Body.(*models.EventsSubscReqData))
				case message.EventModAppSession:
					appSessionId := msg.HTTPRequest.Params["appSessionId"]
					pcf_producer.ModAppSessionContext(msg.HttpChannel, appSessionId, msg.HTTPRequest.Body.(models.AppSessionContextUpdateData))
				case message.EventDeleteEventsSubsc:
					appSessionId := msg.HTTPRequest.Params["appSessionId"]
					pcf_producer.DeleteEventsSubscContext(msg.HttpChannel, appSessionId)
				case message.EventUpdateEventsSubsc:
					appSessionId := msg.HTTPRequest.Params["appSessionId"]
					pcf_producer.UpdateEventsSubscContext(msg.HttpChannel, appSessionId, msg.HTTPRequest.Body.(models.EventsSubscReqData))
				case message.EventAMPolicyGet:
					PolAssoId := msg.HTTPRequest.Params["polAssoId"]
					pcf_producer.GetPoliciesPolAssoId(msg.HttpChannel, PolAssoId)
				case message.EventAMPolicyDelete:
					PolAssoId := msg.HTTPRequest.Params["polAssoId"]
					pcf_producer.DeletePoliciesPolAssoId(msg.HttpChannel, PolAssoId)
				case message.EventAMPolicyCreate:
					pcf_producer.PostPolicies(msg.HttpChannel, msg.HTTPRequest.Body.(models.PolicyAssociationRequest))
				case message.EventAMPolicyUpdate:
					PolAssoId := msg.HTTPRequest.Params["polAssoId"]
					pcf_producer.UpdatePostPoliciesPolAssoId(msg.HttpChannel, PolAssoId, msg.HTTPRequest.Body.(models.PolicyAssociationUpdateRequest))
				case message.EventSMPolicyCreate:
					pcf_producer.CreateSmPolicy(msg.HttpChannel, msg.HTTPRequest.Body.(models.SmPolicyContextData))
				case message.EventSMPolicyGet:
					smPolicyId := msg.HTTPRequest.Params["smPolicyId"]
					pcf_producer.GetSmPolicyContext(msg.HttpChannel, smPolicyId)
				case message.EventSMPolicyUpdate:
					smPolicyId := msg.HTTPRequest.Params["smPolicyId"]
					pcf_producer.UpdateSmPolicyContext(msg.HttpChannel, smPolicyId, msg.HTTPRequest.Body.(models.SmPolicyUpdateContextData))
				case message.EventSMPolicyDelete:
					smPolicyId := msg.HTTPRequest.Params["smPolicyId"]
					pcf_producer.DeleteSmPolicyContext(msg.HttpChannel, smPolicyId)
				case message.EventSMPolicyNotify:
					ReqURI := msg.HTTPRequest.Params["ReqURI"]
					pcf_producer.HandleSmPolicyNotify(msg.HttpChannel, ReqURI, msg.HTTPRequest.Body.(models.PolicyDataChangeNotification))
				case message.EventAMFStatusChangeNotify:
					pcf_producer.HandleAmfStatusChangeNotify(msg.HttpChannel, msg.HTTPRequest.Body.(models.AmfStatusChangeNotification))
					// TODO: http event dispatcher
				case message.EventOAMGetAmPolicy:
					supi := msg.HTTPRequest.Params["supi"]
					pcf_producer.HandleOAMGetAmPolicy(msg.HttpChannel, supi)
				default:
					HandlerLog.Warnf("Event[%s] has not implemented", msg.Event)
				}
			} else {
				HandlerLog.Errorln("Channel closed!")
			}

		case <-time.After(time.Second * 1):

		}
	}
}
