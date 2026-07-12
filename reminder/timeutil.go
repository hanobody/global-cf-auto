package reminder

import (
	"math"
	"strings"
	"time"
)

func parseDate(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func parseTimeValue(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	layouts := []string{time.RFC3339, "2006-01-02", "2006-01-02 15:04:05"}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func daysUntil(t time.Time, now time.Time) int {
	if t.IsZero() {
		return 0
	}
	if now.IsZero() {
		now = time.Now()
	}
	return int(math.Ceil(t.Sub(now).Hours() / 24))
}

func dateWithin(raw string, days int, now time.Time) bool {
	t, ok := parseDate(raw)
	if !ok {
		return false
	}
	return daysUntil(t, now) <= days
}

func timeWithin(raw string, days int, now time.Time) bool {
	t, ok := parseTimeValue(raw)
	if !ok {
		return false
	}
	return daysUntil(t, now) <= days
}

func dateString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}

func timeString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func ParseTimeValue(raw string) (time.Time, bool) {
	return parseTimeValue(raw)
}

func DaysUntil(t time.Time, now time.Time) int {
	return daysUntil(t, now)
}
