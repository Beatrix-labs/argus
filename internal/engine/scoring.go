package engine

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/Beatrix-labs/argus/internal/models"
)

type ScoreStats struct {
	TotalScore int       `json:"total_score"`
	LastSeen   time.Time `json:"last_seen"`
}

type ScoringEngine struct {
	mu             sync.RWMutex
	ipScores       map[string]*ScoreStats
	threshold      int
	window         time.Duration
	weightSQLi     int
	weightBrute    int
	weightPathTrav int
	lastCleanup    time.Time
	scoreFile      string
	whitelist      map[string]bool
}

func NewScoringEngine(threshold int, window time.Duration, wSQLi, wBrute, wPathTrav int, scoreFile string, whitelist []string) *ScoringEngine {
	if threshold == 0 {
		threshold = 10
	}
	if window == 0 {
		window = 60 * time.Second
	}
	if wSQLi == 0 {
		wSQLi = 5
	}
	if wBrute == 0 {
		wBrute = 2
	}
	if wPathTrav == 0 {
		wPathTrav = 4
	}

	wlMap := make(map[string]bool)
	for _, ip := range whitelist {
		wlMap[ip] = true
	}

	se := &ScoringEngine{
		ipScores:       make(map[string]*ScoreStats),
		threshold:      threshold,
		window:         window,
		weightSQLi:     wSQLi,
		weightBrute:    wBrute,
		weightPathTrav: wPathTrav,
		lastCleanup:    time.Now(),
		scoreFile:      scoreFile,
		whitelist:      wlMap,
	}

	if scoreFile != "" {
		se.LoadScores()
	}

	return se
}

func (se *ScoringEngine) AddScore(alert *models.Alert) (int, bool) {
	ip := alert.Event.IP

	se.mu.RLock()
	if se.whitelist[ip] {
		se.mu.RUnlock()
		return 0, false
	}
	se.mu.RUnlock()

	se.mu.Lock()
	defer se.mu.Unlock()

	now := time.Now()

	// Lazy cleanup every 5 minutes
	if now.Sub(se.lastCleanup) > 5*time.Minute {
		se.cleanup(now)
		se.lastCleanup = now
	}

	stats, exists := se.ipScores[ip]
	if !exists || now.Sub(stats.LastSeen) > se.window {
		stats = &ScoreStats{
			TotalScore: 0,
			LastSeen:   now,
		}
		se.ipScores[ip] = stats
	}

	weight := 1 // default
	switch alert.RuleName {
	case "SQL_Injection", "Cross_Site_Scripting_XSS":
		weight = se.weightSQLi
	case "Behavioral_Anomaly_Fuzzing":
		weight = se.weightBrute
	case "Local_File_Inclusion":
		weight = se.weightPathTrav
	}

	stats.TotalScore += weight
	stats.LastSeen = now

	finalScore := stats.TotalScore
	triggered := false
	if stats.TotalScore >= se.threshold {
		triggered = true
		stats.TotalScore = 0 // Reset after trigger
	}

	return finalScore, triggered
}

func (se *ScoringEngine) LoadScores() {
	if se.scoreFile == "" {
		return
	}

	bytes, err := os.ReadFile(se.scoreFile)
	if err != nil {
		return
	}

	se.mu.Lock()
	defer se.mu.Unlock()
	_ = json.Unmarshal(bytes, &se.ipScores)
}

func (se *ScoringEngine) SaveScores() {
	if se.scoreFile == "" {
		return
	}

	se.mu.RLock()
	defer se.mu.RUnlock()

	bytes, err := json.MarshalIndent(se.ipScores, "", "  ")
	if err != nil {
		return
	}

	_ = os.WriteFile(se.scoreFile, bytes, 0644)
}

func (se *ScoringEngine) cleanup(now time.Time) {
	for ip, stats := range se.ipScores {
		if now.Sub(stats.LastSeen) > se.window {
			delete(se.ipScores, ip)
		}
	}
}

func (se *ScoringEngine) GetScore(ip string) int {
	se.mu.RLock()
	defer se.mu.RUnlock()

	if stats, exists := se.ipScores[ip]; exists {
		return stats.TotalScore
	}
	return 0
}
