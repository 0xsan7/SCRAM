package score

import (
	"github.com/0xsan7/scram/internal/model"
	"testing"
)

func TestAuditBetterScorecardCannotIncreaseRisk(t *testing.T) {
	low, high := New(), New()
	low.SetMaintenance(0, 10, 0, "", "")
	high.SetMaintenance(10, 10, 0, "", "")
	if high.maintenancePoints(model.Component{}) >= low.maintenancePoints(model.Component{}) {
		t.Fatal("better repository practices increased the maintenance risk contribution")
	}
}
