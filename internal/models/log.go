package models

import "time"

// LogEvent represents a single log line (e.g. from Nginx/Apache)
type LogEvent struct {
	Timestamp  time.Time
	IP         string
	Method     string
	Path       string
	StatusCode int
	UserAgent  string
	Raw        string
}

// Alerts represent threats that Argus has successfully detected.
type Alert struct {
	Event       LogEvent
	RuleName    string
	Description string
	Severity    string
}
