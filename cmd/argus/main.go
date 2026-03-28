package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
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
	dryRun := flag.Bool("dry-run", false, "Simulate blocking without executing firewall commands")
	tailMode := flag.Bool("tail", false, "Continuously tail the log file (requires -file)")
	flag.Parse()

	// 1. CONFIGURATION
	cfg, err := config.LoadConfig("configs/argus.yml")
	
	errorThreshold := defaultErrorThreshold
	windowDuration := defaultWindowDuration
	banFilePath := "banned_ips.txt"

	// Scoring defaults
	scoreThreshold := 10
	scoreWindow := 60 * time.Second
	wSQLi, wBrute, wPathTrav := 5, 2, 4
	ttl1, ttl2 := 60, 1440
	useIPTables := true
	var whitelist []string
	var scoreFile string
	var customRegex *regexp.Regexp

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
		if cfg.Engine.Scoring.Threshold > 0 {
			scoreThreshold = cfg.Engine.Scoring.Threshold
		}
		if cfg.Engine.Scoring.WindowSeconds > 0 {
			scoreWindow = time.Duration(cfg.Engine.Scoring.WindowSeconds) * time.Second
		}
		if cfg.Engine.Scoring.WeightSQLi > 0 {
			wSQLi = cfg.Engine.Scoring.WeightSQLi
		}
		if cfg.Engine.Scoring.WeightBrute > 0 {
			wBrute = cfg.Engine.Scoring.WeightBrute
		}
		if cfg.Engine.Scoring.WeightPathTrav > 0 {
			wPathTrav = cfg.Engine.Scoring.WeightPathTrav
		}
		if cfg.Action.TTLLevel1 > 0 {
			ttl1 = cfg.Action.TTLLevel1
		}
		if cfg.Action.TTLLevel2 > 0 {
			ttl2 = cfg.Action.TTLLevel2
		}
		if cfg.Action.UseIPTables {
			useIPTables = true
		} else {
			useIPTables = false
		}
		if cfg.Action.DryRun {
			*dryRun = true
		}
		whitelist = cfg.Engine.Scoring.Whitelist
		scoreFile = cfg.Engine.Scoring.ScoreFile
		if cfg.LogSource.CustomLogRegex != "" {
			customRegex, err = regexp.Compile(cfg.LogSource.CustomLogRegex)
			if err != nil {
				fmt.Printf("[!] Warning: Invalid custom log regex: %v. Using default.\n", err)
			}
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
	scoringEngine := engine.NewScoringEngine(scoreThreshold, scoreWindow, wSQLi, wBrute, wPathTrav, scoreFile, whitelist)
	
	jsonLogger, err := output.NewJSONLogger(*jsonOutPath)
	if err == nil {
		defer jsonLogger.Close()
		fmt.Printf("[*] JSON Logging: %s\n", *jsonOutPath)
	}

	ipsEngine, err := remediation.NewBanner(banFilePath, *dryRun, useIPTables, ttl1, ttl2, whitelist)
	if err != nil {
		fmt.Printf("[!] Warning: IPS Engine failed to initialize: %v\n", err)
	} else {
		defer ipsEngine.Stop()
		fmt.Printf("[*] IPS Engine Initialized (Dry-Run: %v, Mode: %s)\n", *dryRun, map[bool]string{true: "iptables", false: "nftables"}[useIPTables])
	}

	// 4. REMEDIATION WORKER (Non-Blocking Queue)
	remediationChan := make(chan string, 1000)
	var remWg sync.WaitGroup
	remWg.Add(1)
	go func() {
		defer remWg.Done()
		for ip := range remediationChan {
			if ipsEngine != nil {
				_ = ipsEngine.BanIP(ip)
			}
		}
	}()

	// 5. INPUT SOURCE
	var input io.Reader
	if *logFilePath != "" {
		f, err := os.Open(*logFilePath)
		if err != nil {
			log.Fatalf("[!] Fatal: %v\n", err)
		}
		defer f.Close()
		input = f
		if *tailMode {
			// Seek to end if tailing
			_, _ = f.Seek(0, io.SeekEnd)
		}
	} else {
		input = os.Stdin
	}

	// 6. PARALLEL PIPELINE
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
				event, err := engine.ParseLogLine(rawLine, customRegex)
				if err != nil {
					continue 
				}

				// Sequence: Signature -> Behavior
				alert := detector.Analyze(event)
				if alert == nil {
					alert = behaviorTracker.Analyze(event)
				}

				if alert != nil {
					handleAlert(alert, jsonLogger, scoringEngine, remediationChan, &mu, scoreThreshold)
				}
			}
		}()
	}

	// Handle Graceful Shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	done := make(chan bool)
	go func() {
		<-sigChan
		fmt.Println("\n[*] Shutting down gracefully...")
		scoringEngine.SaveScores()
		close(linesChan)
		done <- true
	}()

	// Producer
	start := time.Now()
	if *tailMode && *logFilePath != "" {
		go func() {
			reader := bufio.NewReader(input)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					if err == io.EOF {
						time.Sleep(500 * time.Millisecond)
						continue
					}
					break
				}
				atomic.AddUint64(&linesProcessed, 1)
				linesChan <- line
			}
		}()
		<-done
	} else {
		scanner := bufio.NewScanner(input)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			atomic.AddUint64(&linesProcessed, 1)
			linesChan <- scanner.Text()
		}
		close(linesChan)
		if err := scanner.Err(); err != nil {
			log.Printf("[!] Error reading input: %v\n", err)
		}
	}

	wg.Wait()
	close(remediationChan)
	remWg.Wait()
	scoringEngine.SaveScores()

	elapsed := time.Since(start)
	fmt.Printf("\n[*] Analysis complete.\n")
	fmt.Printf("    Lines processed: %d\n", atomic.LoadUint64(&linesProcessed))
	fmt.Printf("    Time elapsed:    %v\n", elapsed)
	if linesProcessed > 0 && elapsed > 0 {
		fmt.Printf("    Throughput:      %.0f lines/sec\n", float64(linesProcessed)/elapsed.Seconds())
	}
}

func handleAlert(alert *models.Alert, logger *output.JSONLogger, scoring *engine.ScoringEngine, remChan chan string, mu *sync.Mutex, threshold int) {
	currentScore, triggered := scoring.AddScore(alert)
	
	action := "MONITORING"
	if triggered {
		action = "BANNED"
	}

	mu.Lock()
	fmt.Printf("[ALERT] [%s] [%s] - Score: %d/%d - ACTION: %s\n", 
		alert.RuleName, alert.Event.IP, currentScore, threshold, action)
	mu.Unlock()

	if logger != nil {
		_ = logger.LogAlert(alert)
	}

	if triggered {
		remChan <- alert.Event.IP
	}
}
