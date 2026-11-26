package httpapi

import (
	"time"
)

const timeLayout = time.RFC3339

// formatTime renders every timestamp in UTC so responses are identical no
// matter which timezone the server or the database driver assumes.
func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// timeDuration adapts time.Duration so handlers can build request structs
// without importing time at the call site.
type timeDuration time.Duration

func (d timeDuration) Duration() time.Duration { return time.Duration(d) }

func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	return time.ParseDuration(s)
}
