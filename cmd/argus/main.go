package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/Beatrix-labs/argus/internal/config"
	"github.com/Beatrix-labs/argus/internal/engine"
	"github.com/Beatrix-labs/argus/internal/models"
	"github.com/Beatrix-labs/argus/internal/output"
	"github.com/Beatrix-labs/argus/internal/remediation"
)

const (
	defaultErrorThreshold = 5
	defaultWindowDuration = 1 * time.Minute
)

func main() {
	logFilePath := flag.String("file", "", "Path to the log file to analyze (leave empty to read from stdin)")
	rulesDirPath := flag.String("rules", "rules", "Path to the directory containing JSON rules")
	jsonOutPath := flag.String("json", "argus_alerts.json", "Path to save JSON alerts for SIEM")
	workers := flag.Int("workers", runtime.NumCPU(), "Number of parallel workers for processing")
	flag.Parse()

	// 1. CONFIGURATION
	cfg, err := config.LoadConfig("configs/argus.yml")
	
	errorThreshold := defaultErrorThreshold
	windowDuration := defaultWindowDuration
	banFilePath := "banned_ips.txt"

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

	// 2. RULES
	loadedRules, err := engine.LoadRules(*rulesDirPath)
	if err != nil {
		fmt.Printf("[!] Warning: Failed to load rules: %v\n", err)
	}

	// 3. ENGINES
	detector := engine.NewDetector(loadedRules) 
	behaviorTracker := engine.NewBehaviorTracker(errorThreshold, windowDuration)
	
	jsonLogger, err := output.NewJSONLogger(*jsonOutPath)
	if err == nil {
		defer jsonLogger.Close()
		fmt.Printf("[*] JSON Logging: %s\n", *jsonOutPath)
	}

	ipsEngine, err := remediation.NewBanner(banFilePath)
	if err == nil {
		fmt.Printf("[*] IPS Engine: %s\n", banFilePath)
	}

	// 4. INPUT SOURCE
	var input *os.File
	if *logFilePath != "" {
		input, err = os.Open(*logFilePath)
		if err != nil {
			log.Fatalf("[!] Fatal: %v\n", err)
		}
		defer input.Close()
	} else {
		input = os.Stdin
	}

	// 5. PARALLEL PIPELINE
	fmt.Printf("[*] Initializing pipeline with %d workers...\n", *workers)
	
	linesChan := make(chan string, *workers*10)
	var wg sync.WaitGroup
	var linesProcessed uint64
	var mu sync.Mutex // For updating shared stats/outputs if needed

	// Start Workers
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rawLine := range linesChan {
				event, err := engine.ParseLogLine(rawLine)
				if err != nil {
					continue 
				}

				// Sequence: Signature -> Behavior
				alert := detector.Analyze(event)
				if alert == nil {
					alert = behaviorTracker.Analyze(event)
				}

				if alert != nil {
					handleAlert(alert, jsonLogger, ipsEngine, &mu)
				}
			}
		}()
	}

	// Producer
	scanner := bufio.NewScanner(input)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	start := time.Now()
	for scanner.Scan() {
		linesProcessed++
		linesChan <- scanner.Text()
	}
	close(linesChan)
	wg.Wait()

	if err := scanner.Err(); err != nil {
		log.Printf("[!] Error reading input: %v\n", err)
	}

	elapsed := time.Since(start)
	fmt.Printf("\n[*] Analysis complete.\n")
	fmt.Printf("    Lines processed: %d\n", linesProcessed)
	fmt.Printf("    Time elapsed:    %v\n", elapsed)
	if linesProcessed > 0 && elapsed > 0 {
		fmt.Printf("    Throughput:      %.0f lines/sec\n", float64(linesProcessed)/elapsed.Seconds())
	}
}

func handleAlert(alert *models.Alert, logger *output.JSONLogger, ips *remediation.Banner, mu *sync.Mutex) {
	mu.Lock()
	defer mu.Unlock()

	fmt.Printf("[!] THREAT: %s [%s] from %s on %s\n", alert.RuleName, alert.Severity, alert.Event.IP, alert.Event.Path)

	if logger != nil {
		_ = logger.LogAlert(alert)
	}

	if ips != nil {
		if err := ips.BanIP(alert.Event.IP); err == nil {
			// Only print ban message if it's a new ban (IPS handles internal check)
		}
	}
}
