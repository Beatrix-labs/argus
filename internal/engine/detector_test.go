package engine

import (
	"regexp"
	"testing"

	"github.com/Beatrix-labs/argus/internal/models"
)

func TestDetector_Analyze(t *testing.T) {
	rules := []Rule{
		{
			Name:       "SQL_Injection",
			PatternStr: "(?i)(SELECT|UNION|INSERT)",
			Target:     TargetPath,
		},
	}
	// Pre-compile rules as LoadRules would do
	for i := range rules {
		rules[i].Pattern = regexp.MustCompile(rules[i].PatternStr)
	}

	detector := NewDetector(rules)

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"Normal path", "/index.php", false},
		{"SQLi attempt", "/search?q=SELECT+*+FROM+users", true},
		{"Encoded SQLi", "/search?q=%53%45%4C%45%43%54+*+FROM+users", true},
		{"HPP attempt", "/search?id=1&id=2", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := models.LogEvent{Path: tt.path}
			alert := detector.Analyze(event)
			if (alert != nil) != tt.expected {
				t.Errorf("Analyze() alert = %v, expected %v", alert != nil, tt.expected)
			}
		})
	}
}
