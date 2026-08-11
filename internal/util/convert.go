package util

import (
	"fmt"

	"github.com/free5gc/openapi/models"
)

var policyTriggerArray = []models.Pcf_SMPolCtrl_PolicyControlRequestTrigger{
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_PLMN_CH,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_RES_MO_RE,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_AC_TY_CH,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_UE_IP_CH,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_UE_MAC_CH,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_AN_CH_COR,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_US_RE,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_APP_STA,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_APP_STO,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_AN_INFO,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_CM_SES_FAIL,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_PS_DA_OFF,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_DEF_QOS_CH,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_SE_AMBR_CH,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_QOS_NOTIF,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_NO_CREDIT,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_PRA_CH,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_SAREA_CH,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_SCNN_CH,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_RE_TIMEOUT,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_RES_RELEASE,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_SUCC_RES_ALLO,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_RAT_TY_CH,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_REF_QOS_IND_CH,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_NUM_OF_PACKET_FILTER,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_UE_STATUS_RESUME,
	models.Pcf_SMPolCtrl_PolicyControlRequestTrigger_UE_TZ_CH,
}

// func GetSMPolicyKey(snssai *models.Snssai, dnn string) string {
// 	if snssai == nil || len(snssai.Sd) != 6 || dnn == "" {
// 		return ""
// 	}
// 	return fmt.Sprintf("%02x%s-%s", snssai.Sst, snssai.Sd, dnn)
// }

// Convert Snssai form models to hexString(sst(2)+sd(6))
// TODO: In R17 openapi, it's would be replace by openapi.SnssaiModelsToHex
func SnssaiModelsToHex(snssai models.Snssai) string {
	sst := fmt.Sprintf("%02x", snssai.Sst)
	return sst + snssai.Sd
}

// Use BitMap to generate requested policy control triggers,
// 1 means yes, 0 means no, see subscaulse 5.6.3.6-1 in TS29512
func PolicyControlReqTrigToArray(bitMap uint64) (trigger []models.Pcf_SMPolCtrl_PolicyControlRequestTrigger) {
	cnt := 0
	size := len(policyTriggerArray)
	for bitMap > 0 && cnt < size {
		if (bitMap & 0x01) > 0 {
			trigger = append(trigger, policyTriggerArray[cnt])
		}
		bitMap >>= 1
		cnt++
	}
	return
}
