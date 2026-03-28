package engine

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Beatrix-labs/argus/internal/models"
)

var (
	logRegex      = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^\"]+"\s+(\d+)\s+\S+(?:\s+"[^"]*"\s+"([^"]*)")?`)
	ErrInvalidLog = errors.New("invalid or unmatched log format")
)

func ParseLogLine(rawLine string, customRegex *regexp.Regexp) (models.LogEvent, error) {
	rawLine = strings.TrimSpace(rawLine)
	if rawLine == "" {
		return models.LogEvent{}, ErrInvalidLog
	}

	activeRegex := logRegex
	if customRegex != nil {
		activeRegex = customRegex
	}

	matches := activeRegex.FindStringSubmatch(rawLine)
	if len(matches) < 6 {
		return models.LogEvent{}, ErrInvalidLog
	}

	parsedTime, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[2])
	if err != nil {
		return models.LogEvent{}, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	statusCode, _ := strconv.Atoi(matches[5])

	userAgent := ""
	if len(matches) >= 7 {
		userAgent = matches[6]
	}

	return models.LogEvent{
		Timestamp:  parsedTime,
		IP:         matches[1],
		Method:     matches[3],
		Path:       matches[4],
		StatusCode: statusCode,
		UserAgent:  userAgent,
		Raw:        rawLine,
	}, nil
}
