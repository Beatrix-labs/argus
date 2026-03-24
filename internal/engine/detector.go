package engine

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Beatrix-labs/argus/internal/models"
)

// TargetField defines which part of the log the rule should scan.
type TargetField string

const (
	TargetPath      TargetField = "PATH"
	TargetUserAgent TargetField = "USER_AGENT"
)

// Rule represents a single attack signature/pattern.
type Rule struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Severity    string      `json:"severity"`
	PatternStr  string      `json:"pattern"` // Raw string from JSON
	Target      TargetField `json:"target"`
	Pattern     *regexp.Regexp // Compiled at runtime (Anti-bloat)
}

// Detector is the core engine struct that holds loaded rules.
type Detector struct {
	rules []Rule
}

func LoadRules(dir string) ([]Rule, error) {
	var compiledRules []Rule


	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules folder %w", err)
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			path := filepath.Join(dir, file.Name())
			bytes, err := os.ReadFile(path)
			if err != nil {
				fmt.Printf("[!] Warning: Unable to read rule file %s\n", file.Name())
				continue
			}

			var fileRules []Rule
			if err := json.Unmarshal(bytes, &fileRules); err != nil {
				fmt.Printf("[!] Warning: JSON format is corrupted in the file %s: %v\n", file.Name(), err)
				continue
			}

			for _, r := range fileRules {
				compiled, err := regexp.Compile(r.PatternStr)
				if err != nil {
					fmt.Printf("[!] Warning: Regex error in rule '%s', this rule is skipped!\n", r.Name)
					continue
				}
				r.Pattern = compiled
				compiledRules = append(compiledRules, r)
			}
		}
	}

	if len(compiledRules) == 0 {
		return nil, fmt.Errorf("no valid rules found in folder %s", dir)
	}

	fmt.Printf("[*] Argus Engine: Successfully loaded %d rules from %s\n", len(compiledRules), dir)
	return compiledRules, nil
}

// NewDetector initializes a new Detection Engine with loaded rules.
func NewDetector(loadedRules []Rule) *Detector {
	return &Detector{
		rules: loadedRules,
	}
}

// Analyze inspects a single LogEvent against native checks and dynamic regex rules.
func (d *Detector) Analyze(event models.LogEvent) *models.Alert {
	if event.Path == "" || event.Path == "/" {
		return nil
	}

	// NATIVE HPP DETECTION (Zero ReDoS Risk)
	parsedURL, err := url.ParseRequestURI(event.Path)
	if err == nil {
		queryParams := parsedURL.Query()
		for _, values := range queryParams {
			if len(values) > 1 {
				return &models.Alert{
					Event:       event,
					RuleName:    "HTTP_Parameter_Pollution",
					Description: "Detected multiple identical URL parameters bypassing WAF (Native Check)",
					Severity:    "Medium",
				}
			}
		}
	}

	// URL DECODING & REGEX ENGINE
	decodedPath, err := url.QueryUnescape(event.Path)
	if err != nil {
		decodedPath = event.Path
	}

	for _, rule := range d.rules {
		var targetString string

		switch rule.Target {
		case TargetPath:
			targetString = decodedPath
		case TargetUserAgent:
			targetString = strings.TrimSpace(event.UserAgent)
		default:
			continue
		}

		if targetString == "" {
			continue
		}

		// Fast Regex Execution
		if rule.Pattern.MatchString(targetString) {
			return &models.Alert{
				Event:       event,
				RuleName:    rule.Name,
				Description: rule.Description,
				Severity:    rule.Severity,
			}
		}
	}

	return nil
}
