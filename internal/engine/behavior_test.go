package engine

import (
	"testing"
	"time"

	"github.com/Beatrix-labs/argus/internal/models"
)

func TestBehaviorTracker_Analyze(t *testing.T) {
	bt := NewBehaviorTracker(3, 1*time.Minute)
	ip := "192.168.1.1"
	
	now := time.Date(2023, 1, 1, 10, 0, 0, 0, time.UTC)

	// First error
	ev1 := models.LogEvent{IP: ip, StatusCode: 404, Timestamp: now}
	if alert := bt.Analyze(ev1); alert != nil {
		t.Errorf("expected no alert on first error")
	}

	// Second error
	ev2 := models.LogEvent{IP: ip, StatusCode: 404, Timestamp: now.Add(10 * time.Second)}
	if alert := bt.Analyze(ev2); alert != nil {
		t.Errorf("expected no alert on second error")
	}

	// Third error (threshold reached)
	ev3 := models.LogEvent{IP: ip, StatusCode: 404, Timestamp: now.Add(20 * time.Second)}
	alert := bt.Analyze(ev3)
	if alert == nil {
		t.Errorf("expected alert on third error")
	} else if alert.RuleName != "Behavioral_Anomaly_Fuzzing" {
		t.Errorf("expected Behavioral_Anomaly_Fuzzing rule, got %s", alert.RuleName)
	}

	// Fourth error (should be reset)
	ev4 := models.LogEvent{IP: ip, StatusCode: 404, Timestamp: now.Add(30 * time.Second)}
	if alert := bt.Analyze(ev4); alert != nil {
		t.Errorf("expected no alert after reset")
	}
}

func TestBehaviorTracker_Cleanup(t *testing.T) {
	bt := NewBehaviorTracker(3, 1*time.Minute)
	ip := "192.168.1.1"
	now := time.Date(2023, 1, 1, 10, 0, 0, 0, time.UTC)

	bt.Analyze(models.LogEvent{IP: ip, StatusCode: 404, Timestamp: now})
	
	if len(bt.ipData) != 1 {
		t.Errorf("expected 1 entry in ipData, got %d", len(bt.ipData))
	}

	// Trigger cleanup with a timestamp far in the future
	future := now.Add(2 * time.Minute)
	bt.Analyze(models.LogEvent{IP: "1.1.1.1", StatusCode: 404, Timestamp: future})

	if _, exists := bt.ipData[ip]; exists {
		t.Errorf("expected IP %s to be cleaned up", ip)
	}
}
