package remediation

import (
	"os"
	"testing"
	"time"
)

func TestBanner_Persistence(t *testing.T) {
	tempFile := "test_banned_ips.txt"
	defer os.Remove(tempFile)

	// 1. Setup - Create a banner and add an IP
	b, err := NewBanner(tempFile, true, true, 60, 1440)
	if err != nil {
		t.Fatalf("Failed to create banner: %v", err)
	}

	ip := "1.2.3.4"
	err = b.BanIP(ip)
	if err != nil {
		t.Fatalf("Failed to ban IP: %v", err)
	}

	// 2. Stop and Save
	b.Stop()

	// 3. Create a new banner and check if IP is loaded
	b2, err := NewBanner(tempFile, true, true, 60, 1440)
	if err != nil {
		t.Fatalf("Failed to create second banner: %v", err)
	}

	b2.mu.RLock()
	info, exists := b2.bannedCache[ip]
	b2.mu.RUnlock()

	if !exists {
		t.Errorf("IP %s was not loaded from file", ip)
	}

	if info.Level != Level1 {
		t.Errorf("Expected Level 1, got %v", info.Level)
	}

	if time.Now().After(info.ExpiresAt) {
		t.Errorf("IP %s should not be expired yet", ip)
	}
}

func TestBanner_LevelUp(t *testing.T) {
	tempFile := "test_banned_ips_levelup.txt"
	defer os.Remove(tempFile)

	b, _ := NewBanner(tempFile, true, true, 60, 1440)
	ip := "8.8.8.8"

	// Ban 1
	_ = b.BanIP(ip)
	if b.bannedCache[ip].Level != Level1 {
		t.Errorf("Expected Level 1, got %v", b.bannedCache[ip].Level)
	}

	// Ban 2 (Repeated offense)
	_ = b.BanIP(ip)
	if b.bannedCache[ip].Level != Level2 {
		t.Errorf("Expected Level 2, got %v", b.bannedCache[ip].Level)
	}
}
