package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Beatrix-labs/argus/internal/engine"
)

// main is the entry point of the Argus IDS.
// It initializes the detection engine and begins reading the specified log stream.
func main() {
	// Define command-line flags for flexibility in production environments.
	logFilePath := flag.String("file", "", "Path to the log file to analyze (leave empty to read from stdin)")
	flag.Parse()

	// Initialize the Detection Engine with default, highly-optimized rules.
	detector := engine.NewDetector(nil)
	behaviorTracker := engine.NewBehaviorTracker(5, 1*time.Minute)
	fmt.Println("[*] Argus IDS engine initialized successfully.")
	fmt.Println("[*] Signature & Behavioral modules active.")

	// Determine the input source: a static file or standard input (pipe).
	var input *os.File
	var err error

	if *logFilePath != "" {
		// Open the file in read-only mode for safety and performance.
		input, err = os.Open(*logFilePath)
		if err != nil {
			log.Fatalf("[!] Fatal error opening log file: %v\n", err)
		}
		defer input.Close()
		fmt.Printf("[*] Analyzing log file: %s\n", *logFilePath)
	} else {
		// Fallback to standard input. This allows piping logs directly from tools like 'tail -f'.
		// Example: tail -f /var/log/nginx/access.log | ./argus
		input = os.Stdin
		fmt.Println("[*] Listening on standard input (stdin)...")
	}

	fmt.Println("[*] Waiting for log data...\n--------------------------------------------------")

	// Use bufio.Scanner for high-performance, line-by-line reading with minimal memory footprint.
	scanner := bufio.NewScanner(input)

	// Security/Stability Measure: Increase the scanner buffer size to 1MB.
	// This prevents the scanner from crashing if an attacker sends an abnormally long URL payload.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024) 

	var linesProcessed uint64

	// The core processing loop - engineered to be extremely fast.
	for scanner.Scan() {
		linesProcessed++
		rawLine := scanner.Text()

		// Step 1: Parse the raw text into a structured LogEvent.
		event, err := engine.ParseLogLine(rawLine)
		if err != nil {
			// Skip unrecognized log formats silently to maintain high processing throughput.
			continue
		}

		// Step 2: Feed the structured event to the Detection Engine.
		alert := detector.Analyze(event)

		if alert == nil {
			alert = behaviorTracker.Analyze(event)
		}

		if alert != nil {
			// Threat detected! Print a detailed alert to the console.
			// In a full production setup, this could trigger a webhook to Telegram or Phalanx (IPS).
			fmt.Printf("[!] THREAT DETECTED: %s\n", alert.RuleName)
			fmt.Printf("    Severity: %s\n", alert.Severity)
			fmt.Printf("    Target IP: %s\n", alert.Event.IP)
			fmt.Printf("    Malicious Path: %s\n", alert.Event.Path)
			fmt.Printf("    Description: %s\n", alert.Description)
			fmt.Println("--------------------------------------------------")
		}
	}

	// Handle potential scanner errors gracefully.
	if err := scanner.Err(); err != nil {
		log.Fatalf("[!] Error reading input stream: %v\n", err)
	}

	fmt.Printf("[*] Analysis complete. Total lines processed: %d\n", linesProcessed)
}
