package engine

import (
	"sync"
	"time"

	"github.com/Beatrix-labs/argus/internal/models"
)

// IPStats tracks the behavior of a single IP address.
type IPStats struct {
	ErrorCount int
	LastSeen   time.Time
}

// BehaviorTracker is a stateful engine that monitors IP behavior over time.
type BehaviorTracker struct {
	mu          sync.RWMutex
	ipData      map[string]*IPStats
	threshold   int           // How many errors before alerting
	timeWindow  time.Duration // How long to remember the errors
	lastCleanup time.Time     // Last time we performed a bulk cleanup
}

// NewBehaviorTracker initializes the tracker.
func NewBehaviorTracker(threshold int, window time.Duration) *BehaviorTracker {
	return &BehaviorTracker{
		ipData:     make(map[string]*IPStats),
		threshold:  threshold,
		timeWindow: window,
	}
}

// Analyze evaluates if an IP is exhibiting malicious behavior (e.g., Fuzzing/Bruteforce)
func (bt *BehaviorTracker) Analyze(event models.LogEvent) *models.Alert {
	// We only care about client errors (4xx) or server errors (5xx) for this behavior
	if event.StatusCode < 400 {
		return nil
	}

	bt.mu.Lock()
	defer bt.mu.Unlock()

	// Periodic lazy cleanup based on log timestamps (every 1000 events or 10 min log-time)
	if event.Timestamp.Sub(bt.lastCleanup) > bt.timeWindow || bt.lastCleanup.IsZero() {
		bt.cleanup(event.Timestamp)
		bt.lastCleanup = event.Timestamp
	}

	stats, exists := bt.ipData[event.IP]
	if !exists {
		bt.ipData[event.IP] = &IPStats{
			ErrorCount: 1,
			LastSeen:   event.Timestamp,
		}
		return nil
	}

	// Reset counter if the time window has passed (based on log time)
	if event.Timestamp.Sub(stats.LastSeen) > bt.timeWindow {
		stats.ErrorCount = 1
	} else {
		stats.ErrorCount++
	}
	
	stats.LastSeen = event.Timestamp

	// Trigger alert if the threshold is breached
	if stats.ErrorCount >= bt.threshold {
		// Reset to prevent spamming the same alert every millisecond
		stats.ErrorCount = 0 
		
		return &models.Alert{
			Event:       event,
			RuleName:    "Behavioral_Anomaly_Fuzzing",
			Description: "High rate of HTTP errors detected. Possible Directory Fuzzing or Brute Force attack.",
			Severity:    "Critical",
		}
	}

	return nil
}

// cleanup removes stale IP data based on the provided current time (usually from logs).
func (bt *BehaviorTracker) cleanup(now time.Time) {
	for ip, stats := range bt.ipData {
		if now.Sub(stats.LastSeen) > bt.timeWindow {
			delete(bt.ipData, ip)
		}
	}
}
