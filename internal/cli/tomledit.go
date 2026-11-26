package cli

import "strings"

// replaceSection swaps one TOML table for replacement text. Everything before
// the header and from the next header onwards is preserved verbatim.
func replaceSection(document, header, replacement string) string {
	lines := strings.Split(document, "\n")
	var out []string
	replaced := false
	inside := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		isHeader := strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")
		if isHeader {
			if trimmed == header {
				if !replaced {
					out = append(out, strings.Split(strings.TrimRight(replacement, "\n"), "\n")...)
					replaced = true
				}
				inside = true
				continue
			}
			inside = false
		}
		if inside {
			continue
		}
		out = append(out, line)
	}
	if !replaced {
		out = append(out, "", strings.TrimRight(replacement, "\n"))
	}
	return strings.Join(out, "\n")
}
