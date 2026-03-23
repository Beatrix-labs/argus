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
// It uses a RWMutex to ensure blazing fast, thread-safe concurrent map access.
type BehaviorTracker struct {
	mu          sync.RWMutex
	ipData      map[string]*IPStats
	threshold   int           // How many errors before alerting
	timeWindow  time.Duration // How long to remember the errors
}

// NewBehaviorTracker initializes the tracker and starts a background Goroutine
// to clean up stale IP data, preventing memory leaks in production environments.
func NewBehaviorTracker(threshold int, window time.Duration) *BehaviorTracker {
	bt := &BehaviorTracker{
		ipData:     make(map[string]*IPStats),
		threshold:  threshold,
		timeWindow: window,
	}

	// Start the background sweeper (Classic Senior Go pattern)
	go bt.startSweeper()

	return bt
}

// Analyze evaluates if an IP is exhibiting malicious behavior (e.g., Fuzzing/Bruteforce)
func (bt *BehaviorTracker) Analyze(event models.LogEvent) *models.Alert {
	// We only care about client errors (4xx) or server errors (5xx) for this behavior
	if event.StatusCode < 400 {
		return nil
	}

	bt.mu.Lock()
	defer bt.mu.Unlock()

	stats, exists := bt.ipData[event.IP]
	if !exists {
		bt.ipData[event.IP] = &IPStats{
			ErrorCount: 1,
			LastSeen:   event.Timestamp,
		}
		return nil
	}

	// Reset counter if the time window has passed
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

// startSweeper runs periodically to delete inactive IPs from RAM.
func (bt *BehaviorTracker) startSweeper() {
	ticker := time.NewTicker(bt.timeWindow)
	for range ticker.C {
		bt.mu.Lock()
		now := time.Now()
		for ip, stats := range bt.ipData {
			if now.Sub(stats.LastSeen) > bt.timeWindow {
				delete(bt.ipData, ip)
			}
		}
		bt.mu.Unlock()
	}
}
