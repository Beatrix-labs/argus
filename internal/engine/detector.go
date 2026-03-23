package engine

import (
	"net/url"
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
	Name        string
	Description string
	Severity    string // "Low", "Medium", "High", "Critical"
	Pattern     *regexp.Regexp
	Target      TargetField
}

// DefaultRules contains highly optimized, industry-standard threat signatures.
// Note: HPP detection is removed from Regex and moved to Native code for ReDoS protection!
var DefaultRules = []Rule{
	{
		Name:        "Cross_Site_Scripting_XSS",
		Description: "Detects XSS payload injections (scripts, event handlers)",
		Severity:    "High",
		Pattern:     regexp.MustCompile(`(?i)(<script>|<\/script>|on(load|error|mouseover|click|focus)=|javascript:)`),
		Target:      TargetPath,
	},
	{
		Name:        "SQL_Injection",
		Description: "Detects common SQL injection syntax and boolean-based payloads",
		Severity:    "Critical",
		Pattern:     regexp.MustCompile(`(?i)(UNION\s+SELECT|SELECT\s+.*\s+FROM|INSERT\s+INTO|UPDATE\s+.*\s+SET|' OR '1'='1|--\s*$)`),
		Target:      TargetPath,
	},
	{
		Name:        "Local_File_Inclusion",
		Description: "Detects Path Traversal / Directory climbing attempts",
		Severity:    "Critical",
		Pattern:     regexp.MustCompile(`(?i)(\.\./\.\./|\.\.%2F|/etc/passwd|/windows/win\.ini|cmd\.exe)`),
		Target:      TargetPath,
	},
	{
		Name:        "Malicious_Scanner_Bot",
		Description: "Detects automated vulnerability scanners in the User-Agent header",
		Severity:    "Low",
		Pattern:     regexp.MustCompile(`(?i)(sqlmap|nikto|nmap|zgrab|masscan|dirb|gobuster)`),
		Target:      TargetUserAgent,
	},
}

// Detector is the core engine struct that holds loaded rules.
type Detector struct {
	rules []Rule
}

// NewDetector initializes a new Detection Engine.
func NewDetector(customRules []Rule) *Detector {
	if len(customRules) == 0 {
		customRules = DefaultRules
	}
	return &Detector{
		rules: customRules,
	}
}

// Analyze inspects a single LogEvent against native checks and regex rules.
func (d *Detector) Analyze(event models.LogEvent) *models.Alert {
	if event.Path == "" || event.Path == "/" {
		return nil
	}

	// NATIVE HPP DETECTION (Zero ReDoS Risk)	// Instead of using dangerous backreference Regex, we use Go's native URL parser.
	// It parses the path and checks if any query parameter key appears more than once.
	parsedURL, err := url.ParseRequestURI(event.Path)
	if err == nil {
		queryParams := parsedURL.Query()
		for _, values := range queryParams {
			// If a single parameter key has multiple values, it's an HPP attack!
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
