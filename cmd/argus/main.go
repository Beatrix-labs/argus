package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Beatrix-labs/argus/internal/config"
	"github.com/Beatrix-labs/argus/internal/engine"
	"github.com/Beatrix-labs/argus/internal/output"
	"github.com/Beatrix-labs/argus/internal/remediation"
)

// main is the entry point of the Argus IDS/IPS.
func main() {
	// Define command-line flags for flexibility in production environments.
	logFilePath := flag.String("file", "", "Path to the log file to analyze (leave empty to read from stdin)")
	rulesDirPath := flag.String("rules", "rules", "Path to the directory containing JSON rules")
	jsonOutPath := flag.String("json", "argus_alerts.json", "Path to save JSON alerts for SIEM")
	flag.Parse()

	// ---------------------------------------------------------
	// CONFIGURATION LOADING
	// ---------------------------------------------------------
	cfg, err := config.LoadConfig("configs/argus.yml")
	
	errorThreshold := 5
	windowDuration := 1 * time.Minute
	banFilePath := "banned_ips.txt" // Default fallback

	if err != nil {
		fmt.Printf("[!] Warning: Could not load config file, using defaults: %v\n", err)
	} else {
		fmt.Println("[*] Argus Config loaded successfully!")
		if cfg.Engine.Behavioral.ErrorThreshold > 0 {
			errorThreshold = cfg.Engine.Behavioral.ErrorThreshold
		}
		if cfg.Engine.Behavioral.WindowSeconds > 0 {
			windowDuration = time.Duration(cfg.Engine.Behavioral.WindowSeconds) * time.Second
		}
		if cfg.Action.BanFile != "" {
			banFilePath = cfg.Action.BanFile
		}
	}

	// ---------------------------------------------------------
	// DYNAMIC RULES LOADING (ENTERPRISE FEATURE)
	// ---------------------------------------------------------
	fmt.Printf("[*] Loading dynamic rules from directory: %s...\n", *rulesDirPath)
	loadedRules, err := engine.LoadRules(*rulesDirPath)
	if err != nil {
		fmt.Printf("[!] Warning: Failed to load rules from %s: %v\n", *rulesDirPath, err)
		fmt.Println("[!] Argus will continue to run using Native WAF & Behavioral Engine.")
	}

	// ---------------------------------------------------------
	// ENGINE INITIALIZATION
	// ---------------------------------------------------------
	detector := engine.NewDetector(loadedRules) 
	behaviorTracker := engine.NewBehaviorTracker(errorThreshold, windowDuration)

	fmt.Println("[*] Argus IDS engine initialized successfully.")
	fmt.Printf("[*] Behavioral thresholds: %d errors / %v\n", errorThreshold, windowDuration)
	if len(loadedRules) > 0 {
		fmt.Printf("[*] %d Signature modules active.\n", len(loadedRules))
	}

	// ---------------------------------------------------------
	// ENTERPRISE MODULES (JSON SIEM & IPS REMEDIATION)
	// ---------------------------------------------------------
	// 1. JSON Logger
	jsonLogger, err := output.NewJSONLogger(*jsonOutPath)
	if err != nil {
		fmt.Printf("[!] Warning: Failed to create JSON Log file: %v\n", err)
	} else {
		defer jsonLogger.Close()
		fmt.Printf("[*] Enterprise JSON Logging is active -> %s\n", *jsonOutPath)
	}

	// 2. Automatic IP Banning Engine
	ipsEngine, err := remediation.NewBanner(banFilePath)
	if err != nil {
		fmt.Printf("[!] Warning: Failed to initialize IPS Engine: %v\n", err)
	} else {
		fmt.Printf("[*] Enterprise IPS is active -> Banning to %s\n", banFilePath)
	}

	// ---------------------------------------------------------
	// INPUT ROUTING
	// ---------------------------------------------------------
	var input *os.File

	if *logFilePath != "" {
		input, err = os.Open(*logFilePath)
		if err != nil {
			log.Fatalf("[!] Fatal error opening log file: %v\n", err)
		}
		defer input.Close()
		fmt.Printf("[*] Analyzing log file: %s\n", *logFilePath)
	} else {
		input = os.Stdin
		fmt.Println("[*] Listening on standard input (stdin)...")
	}

	fmt.Println("[*] Waiting for log data...\n--------------------------------------------------")

	// ---------------------------------------------------------
	// PIPELINE EXECUTION
	// ---------------------------------------------------------
	scanner := bufio.NewScanner(input)
	
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var linesProcessed uint64

	for scanner.Scan() {
		linesProcessed++
		rawLine := scanner.Text()

		event, err := engine.ParseLogLine(rawLine)
		if err != nil {
			continue 
		}

		// Phase 1: Signature Analysis
		alert := detector.Analyze(event)

		// Phase 2: Behavioral Analysis
		if alert == nil {
			alert = behaviorTracker.Analyze(event)
		}

		// Phase 3: Action / Alert
		if alert != nil {
			fmt.Printf("[!] THREAT DETECTED: %s\n", alert.RuleName)
			fmt.Printf("    Severity: %s\n", alert.Severity)
			fmt.Printf("    Target IP: %s\n", alert.Event.IP)
			fmt.Printf("    Malicious Path: %s\n", alert.Event.Path)
			fmt.Printf("    Description: %s\n", alert.Description)

			// Action A: Send to JSON
			if jsonLogger != nil {
				if err := jsonLogger.LogAlert(alert); err != nil {
					fmt.Printf("[!] Error writing to JSON log: %v\n", err)
				}
			}

			// Action B: Automatic Ban IP
			if ipsEngine != nil {
				if err := ipsEngine.BanIP(alert.Event.IP); err != nil {
					fmt.Printf("[!] IPS Error: Could not ban IP %s: %v\n", alert.Event.IP, err)
				} else {
					fmt.Printf("[+] IPS Action: Target IP %s has been BLOCKED!\n", alert.Event.IP)
				}
			}
			
			fmt.Println("--------------------------------------------------")
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("[!] Error reading input stream: %v\n", err)
	}

	fmt.Printf("[*] Analysis complete. Total lines processed: %d\n", linesProcessed)
}
