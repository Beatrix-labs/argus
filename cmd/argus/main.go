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
)

// main is the entry point of the Argus IDS.
// It initializes the detection engine and begins reading the specified log stream.
func main() {
	// Define command-line flags for flexibility in production environments.
	logFilePath := flag.String("file", "", "Path to the log file to analyze (leave empty to read from stdin)")
	flag.Parse()

	// ---------------------------------------------------------
	// CONFIGURATION LOADING
	// ---------------------------------------------------------
	cfg, err := config.LoadConfig("configs/argus.yml")
	
	// Set default values in case config loading fails
	errorThreshold := 5
	windowDuration := 1 * time.Minute

	if err != nil {
		fmt.Printf("[!] Warning: Could not load config file, using defaults: %v\n", err)
	} else {
		fmt.Println("[*] Argus Config loaded successfully!")
		// Override defaults with values from argus.yml
		if cfg.Engine.Behavioral.ErrorThreshold > 0 {
			errorThreshold = cfg.Engine.Behavioral.ErrorThreshold
		}
		if cfg.Engine.Behavioral.WindowSeconds > 0 {
			windowDuration = time.Duration(cfg.Engine.Behavioral.WindowSeconds) * time.Second
		}
	}

	// ---------------------------------------------------------
	// ENGINE INITIALIZATION
	// ---------------------------------------------------------
	detector := engine.NewDetector(nil) // Future: Pass cfg.Engine.Signature here
	behaviorTracker := engine.NewBehaviorTracker(errorThreshold, windowDuration)

	fmt.Println("[*] Argus IDS engine initialized successfully.")
	fmt.Printf("[*] Behavioral thresholds: %d errors / %v\n", errorThreshold, windowDuration)
	fmt.Println("[*] Signature modules active.")

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
		// Fallback to standard input for piping logs (e.g., tail -f)
		input = os.Stdin
		fmt.Println("[*] Listening on standard input (stdin)...")
	}

	fmt.Println("[*] Waiting for log data...\n--------------------------------------------------")

	// ---------------------------------------------------------
	// PIPELINE EXECUTION
	// ---------------------------------------------------------
	scanner := bufio.NewScanner(input)
	
	// Security Measure: 1MB buffer to prevent crashes from massive URLs
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var linesProcessed uint64

	for scanner.Scan() {
		linesProcessed++
		rawLine := scanner.Text()

		event, err := engine.ParseLogLine(rawLine)
		if err != nil {
			continue // Skip unrecognized formats silently
		}

		// Phase 1: Signature Analysis
		alert := detector.Analyze(event)

		// Phase 2: Behavioral Analysis (if no signature match)
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
			fmt.Println("--------------------------------------------------")
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("[!] Error reading input stream: %v\n", err)
	}

	fmt.Printf("[*] Analysis complete. Total lines processed: %d\n", linesProcessed)
}
