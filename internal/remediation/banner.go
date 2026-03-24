package remediation

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Banner is a smart IPS engine.
// It uses an in-memory cache to remember banned IPs, preventing duplicate file writes.
type Banner struct {
	filePath    string
	mu          sync.RWMutex      // RWMutex is highly optimized for frequent reads
	bannedCache map[string]bool // O(1) Time Complexity caching
}

// NewBanner initializes the IPS engine and loads existing IPs from the disk.
func NewBanner(filePath string) (*Banner, error) {
	b := &Banner{
		filePath:    filePath,
		bannedCache: make(map[string]bool),
	}

	// Smart Feature: Load past bans on startup to maintain security state
	if err := b.loadExisting(); err != nil {
		return nil, err
	}

	return b, nil
}

// loadExisting reads the banned_ips.txt into RAM to prevent future redundant writes.
func (b *Banner) loadExisting() error {
	file, err := os.Open(b.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist yet, which is fine on first run
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			b.bannedCache[ip] = true
		}
	}
	return scanner.Err()
}

// BanIP safely checks and writes a malicious IP to the blacklist without bloating the file.
func (b *Banner) BanIP(ip string) error {
	// PHASE 1: Fast Cache Check (Read Lock)
	// Check memory first. If already banned, reject immediately without touching the disk.
	b.mu.RLock()
	if b.bannedCache[ip] {
		b.mu.RUnlock()
		return nil // IP is already blacklisted
	}
	b.mu.RUnlock()

	// PHASE 2: Safe File Writing (Write Lock)
	b.mu.Lock()
	defer b.mu.Unlock()

	// Double-check to prevent Race Conditions during concurrent attacks
	if b.bannedCache[ip] {
		return nil
	}

	// Open file, write, and close rapidly so firewall daemons (like Fail2Ban) can read it concurrently
	file, err := os.OpenFile(b.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open ban file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(ip + "\n"); err != nil {
		return fmt.Errorf("failed to write to ban file: %w", err)
	}

	// Save to memory cache
	b.bannedCache[ip] = true

	return nil
}
