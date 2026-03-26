package output

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/Beatrix-labs/argus/internal/models"
)

// SIEMAlert is a special data structure for JSON format.
type SIEMAlert struct {
	Timestamp   time.Time `json:"timestamp"`
	RuleName    string    `json:"rule_name"`
	Severity    string    `json:"severity"`
	TargetIP    string    `json:"target_ip"`
	Path        string    `json:"malicious_path"`
	Description string    `json:"description"`
}

// JSONLogger is a secure and very fast "printing machine".
type JSONLogger struct {
	file    *os.File
	encoder *json.Encoder
	mu      sync.Mutex
}

// NewJSONLogger opens (or creates) a new JSON log file.
func NewJSONLogger(filepath string) (*JSONLogger, error) {
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &JSONLogger{
		file:    file,
		encoder: json.NewEncoder(file), 
	}, nil
}

// LogAlert receives detected threats and prints them to a file.
func (l *JSONLogger) LogAlert(alert *models.Alert) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Move data from Argus Alert to SIEM Alert format
	jsonAlert := SIEMAlert{
		Timestamp:   alert.Event.Timestamp,
		RuleName:    alert.RuleName,
		Severity:    alert.Severity,
		TargetIP:    alert.Event.IP,
		Path:        alert.Event.Path,
		Description: alert.Description,
	}

	// Print directly to file
	return l.encoder.Encode(jsonAlert)
}

// Close must be called when Argus is shut down to prevent file corruption.
func (l *JSONLogger) Close() error {
	return l.file.Close()
}
