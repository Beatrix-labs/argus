package remediation

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type BanLevel int

const (
	Level1 BanLevel = 1 // 1 Hour
	Level2 BanLevel = 2 // 24 Hours
)

type BanInfo struct {
	IP        string
	ExpiresAt time.Time
	Level     BanLevel
}

// Banner is an active IPS engine.
type Banner struct {
	filePath    string
	dryRun      bool
	useIPTables bool
	mu          sync.RWMutex
	bannedCache map[string]*BanInfo
	ttlLevel1   time.Duration
	ttlLevel2   time.Duration
	stopChan    chan struct{}
	whitelist   map[string]bool
}

// NewBanner initializes the IPS engine.
func NewBanner(filePath string, dryRun bool, useIPTables bool, ttl1, ttl2 int, whitelist []string) (*Banner, error) {
	wlMap := make(map[string]bool)
	for _, ip := range whitelist {
		wlMap[ip] = true
	}

	b := &Banner{
		filePath:    filePath,
		dryRun:      dryRun,
		useIPTables: useIPTables,
		bannedCache: make(map[string]*BanInfo),
		ttlLevel1:   time.Duration(ttl1) * time.Minute,
		ttlLevel2:   time.Duration(ttl2) * time.Minute,
		stopChan:    make(chan struct{}),
		whitelist:   wlMap,
	}

	if b.ttlLevel1 == 0 {
		b.ttlLevel1 = 1 * time.Hour
	}
	if b.ttlLevel2 == 0 {
		b.ttlLevel2 = 24 * time.Hour
	}

	// Load existing bans
	b.loadBans()

	// Permission check if not dry-run
	if !dryRun && runtime.GOOS == "linux" {
		if err := b.checkPermissions(); err != nil {
			return nil, fmt.Errorf("permission check failed: %w (root/sudo required for firewall actions)", err)
		}
	}

	// Start auto-unban cleaner
	go b.startCleaner()

	return b, nil
}

func (b *Banner) loadBans() {
	file, err := os.Open(b.filePath)
	if err != nil {
		return // File might not exist yet
	}
	defer file.Close()

	var validBans []*BanInfo
	now := time.Now()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			continue
		}

		ip := parts[0]
		expiresAt, err := time.Parse(time.RFC3339, parts[1])
		if err != nil {
			continue
		}
		levelInt, _ := strconv.Atoi(parts[2])

		if now.Before(expiresAt) {
			info := &BanInfo{
				IP:        ip,
				ExpiresAt: expiresAt,
				Level:     BanLevel(levelInt),
			}
			b.bannedCache[ip] = info
			validBans = append(validBans, info)
		}
	}

	if len(validBans) > 0 {
		fmt.Printf("[*] Loaded %d active bans from %s\n", len(validBans), b.filePath)
	}
}

func (b *Banner) saveAllBans() {
	b.mu.RLock()
	defer b.mu.RUnlock()

	file, err := os.Create(b.filePath)
	if err != nil {
		return
	}
	defer file.Close()

	for _, info := range b.bannedCache {
		fmt.Fprintf(file, "%s,%s,%d\n", info.IP, info.ExpiresAt.Format(time.RFC3339), info.Level)
	}
}

func (b *Banner) checkPermissions() error {
	cmd := exec.Command("sudo", "-n", "iptables", "-L", "INPUT")
	if b.useIPTables {
		if err := cmd.Run(); err != nil {
			// Fallback check for nftables
			cmd = exec.Command("sudo", "-n", "nft", "list", "ruleset")
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("neither iptables nor nftables accessible with sudo")
			}
			b.useIPTables = false
		}
	}
	return nil
}

// BanIP handles the blocking logic.
func (b *Banner) BanIP(ip string) error {
	b.mu.RLock()
	if b.whitelist[ip] {
		b.mu.RUnlock()
		return nil
	}
	b.mu.RUnlock()

	b.mu.Lock()
	defer b.mu.Unlock()

	info, exists := b.bannedCache[ip]
	level := Level1
	duration := b.ttlLevel1

	if exists {
		if info.Level == Level1 {
			level = Level2
			duration = b.ttlLevel2
		} else {
			// Already at Level 2, just refresh
			level = Level2
			duration = b.ttlLevel2
		}
	}

	expiresAt := time.Now().Add(duration)
	b.bannedCache[ip] = &BanInfo{
		IP:        ip,
		ExpiresAt: expiresAt,
		Level:     level,
	}

	if b.dryRun {
		log.Printf("[DRY-RUN] [IPS] Banning %s for %v (Level %d)\n", ip, duration, level)
		return nil
	}

	log.Printf("[IPS] ACTION: BANNED %s for %v (Level %d)\n", ip, duration, level)
	return b.execBan(ip, expiresAt, level)
}

func (b *Banner) execBan(ip string, expiresAt time.Time, level BanLevel) error {
	isIPv6 := strings.Contains(ip, ":")

	if b.useIPTables {
		binary := "iptables"
		if isIPv6 {
			binary = "ip6tables"
		}

		// Check if already exists to avoid duplicates
		checkCmd := exec.Command("sudo", binary, "-C", "INPUT", "-s", ip, "-j", "DROP")
		if err := checkCmd.Run(); err == nil {
			// Rule already exists
			return nil
		}

		// iptables -A INPUT -s [IP] -j DROP
		cmd := exec.Command("sudo", binary, "-A", "INPUT", "-s", ip, "-j", "DROP")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("firewall error: %s (%v)", string(output), err)
		}
	} else {
		family := "ip"
		if isIPv6 {
			family = "ip6"
		}
		// nft add rule filter input ip saddr [IP] drop
		cmd := exec.Command("sudo", "nft", "add", "rule", "inet", "filter", "input", family, "saddr", ip, "drop")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("firewall error: %s (%v)", string(output), err)
		}
	}

	// Also append to file for persistence
	file, err := os.OpenFile(b.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer file.Close()
		fmt.Fprintf(file, "%s,%s,%d\n", ip, expiresAt.Format(time.RFC3339), level)
	}

	return nil
}

func (b *Banner) UnbanIP(ip string) error {
	if b.dryRun {
		log.Printf("[DRY-RUN] [IPS] Unbanning %s\n", ip)
		return nil
	}

	isIPv6 := strings.Contains(ip, ":")
	var cmd *exec.Cmd

	if b.useIPTables {
		binary := "iptables"
		if isIPv6 {
			binary = "ip6tables"
		}
		cmd = exec.Command("sudo", binary, "-D", "INPUT", "-s", ip, "-j", "DROP")
	} else {
		family := "ip"
		if isIPv6 {
			family = "ip6"
		}
		cmd = exec.Command("sudo", "nft", "delete", "rule", "inet", "filter", "input", family, "saddr", ip, "drop")
	}

	log.Printf("[IPS] ACTION: UNBANNED %s (TTL Expired)\n", ip)
	_ = cmd.Run() // Ignore error if already unbanned
	return nil
}

func (b *Banner) startCleaner() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.cleanExpired()
		case <-b.stopChan:
			return
		}
	}
}

func (b *Banner) Stop() {
	close(b.stopChan)
	b.saveAllBans()
}

func (b *Banner) cleanExpired() {
	b.mu.Lock()
	now := time.Now()
	var toUnban []string

	for ip, info := range b.bannedCache {
		if now.After(info.ExpiresAt) {
			toUnban = append(toUnban, ip)
		}
	}

	for _, ip := range toUnban {
		delete(b.bannedCache, ip)
	}
	b.mu.Unlock()

	for _, ip := range toUnban {
		_ = b.UnbanIP(ip)
	}
}
