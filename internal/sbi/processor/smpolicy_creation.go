package processor

import (
	"go.mongodb.org/mongo-driver/bson"

	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/util/idgenerator"
	"github.com/free5gc/util/mongoapi"
)

// smPolicyCreation owns only resources acquired by one create request. In
// particular, a failed replacement must not free another session's rating groups.
type smPolicyCreation struct {
	ue               *pcf_context.UeContext
	policyID         string
	previousPolicy   *pcf_context.UeSmPolicyData
	previousGroups   []int32
	hadGroups        bool
	generator        *idgenerator.IDGenerator
	allocated        []int64
	insertedCharging []bson.M
	committed        bool
}

func newSmPolicyCreation(ue *pcf_context.UeContext, policyID string,
	generator *idgenerator.IDGenerator,
) *smPolicyCreation {
	groups, exists := ue.RatingGroupData[policyID]
	return &smPolicyCreation{
		ue: ue, policyID: policyID, previousPolicy: ue.SmPolicyData[policyID],
		previousGroups: append([]int32(nil), groups...), hadGroups: exists, generator: generator,
	}
}

func (creation *smPolicyCreation) allocateRatingGroup() (int64, error) {
	id, err := creation.generator.Allocate()
	if err == nil {
		creation.allocated = append(creation.allocated, id)
	}
	return id, err
}

func (creation *smPolicyCreation) putChargingData(data map[string]interface{}, strength int) error {
	existed, err := mongoapi.RestfulAPIPutOne(chargingDataColl, data, data, strength)
	if err == nil && !existed {
		// A newly allocated rating group identifies this request's charging copy.
		// Do not match mutable charging fields when rolling back, and do not
		// delete unrelated copies that might share the subscriber's UE/S-NSSAI.
		creation.insertedCharging = append(creation.insertedCharging, bson.M{
			"ueId": data["ueId"], "snssai": data["snssai"],
			"dnn": data["dnn"], "filter": data["filter"],
			"ratingGroup": data["ratingGroup"],
		})
	}
	return err
}

func (creation *smPolicyCreation) rollback() {
	if creation.committed {
		return
	}
	// If MongoDB cannot delete a charging copy, avoid reusing the same
	// rating group while that copy may still exist in the database.
	unsafeToReuse := make(map[int64]struct{})
	for _, filter := range creation.insertedCharging {
		if err := mongoapi.RestfulAPIDeleteOne(chargingDataColl, filter); err != nil {
			logger.SmPolicyLog.Errorf("Failed to clean up charging data after SM policy create failure: %v", err)
			if group, ok := filter["ratingGroup"].(int32); ok {
				unsafeToReuse[int64(group)] = struct{}{}
			}
		}
	}
	for _, id := range creation.allocated {
		if _, unsafe := unsafeToReuse[id]; unsafe {
			continue
		}
		creation.generator.FreeID(id)
	}
	if creation.hadGroups {
		creation.ue.RatingGroupData[creation.policyID] = creation.previousGroups
	} else {
		delete(creation.ue.RatingGroupData, creation.policyID)
	}
	if creation.previousPolicy != nil {
		creation.ue.SmPolicyData[creation.policyID] = creation.previousPolicy
	} else {
		delete(creation.ue.SmPolicyData, creation.policyID)
	}
}

// commit retains only the new policy's rating groups. When replacing an existing
// policy, its old groups must not remain associated with the replacement: the
// normal SM policy delete path would otherwise free both generations later.
// MongoDB cleanup is best effort, like HandleDeleteSmPolicyContextRequest.
func (creation *smPolicyCreation) commit() {
	creation.committed = true
	if creation.previousPolicy == nil {
		return
	}

	newGroups := make([]int32, 0, len(creation.allocated))
	newIDs := make(map[int64]struct{}, len(creation.allocated))
	for _, id := range creation.allocated {
		newGroups = append(newGroups, int32(id))
		newIDs[id] = struct{}{}
	}
	if len(newGroups) == 0 {
		delete(creation.ue.RatingGroupData, creation.policyID)
	} else {
		creation.ue.RatingGroupData[creation.policyID] = newGroups
	}

	for _, oldGroup := range creation.previousGroups {
		if _, reused := newIDs[int64(oldGroup)]; reused {
			// Never free a group still owned by the replacement, even when
			// a pre-existing allocator/map inconsistency caused reuse.
			continue
		}
		if err := mongoapi.RestfulAPIDeleteMany(chargingDataColl, bson.M{
			"ratingGroup": oldGroup,
		}); err != nil {
			// Retain the allocator reservation if a stale charging copy
			// could not be removed; reusing this ID would be unsafe.
			logger.SmPolicyLog.Errorf("Failed to clean up replaced SM policy rating group %d: %v", oldGroup, err)
			continue
		}
		creation.generator.FreeID(int64(oldGroup))
	}
}
