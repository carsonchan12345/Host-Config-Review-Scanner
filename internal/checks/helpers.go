package checks

import (
	"regexp"
	"strings"
)

// parseOrValues splits a value_data string on " || " into alternatives.
func parseOrValues(valueData string) []string {
	parts := strings.Split(valueData, "||")
	var result []string
	for _, p := range parts {
		v := strings.TrimSpace(p)
		v = strings.Trim(v, "\"")
		if v != "" {
			result = append(result, v)
		}
	}
	if len(result) == 0 {
		result = append(result, strings.Trim(strings.TrimSpace(valueData), "\""))
	}
	return result
}

// parseAndValues splits a value_data string on " && " into required values.
func parseAndValues(valueData string) []string {
	parts := strings.Split(valueData, "&&")
	var result []string
	for _, p := range parts {
		v := strings.TrimSpace(p)
		v = strings.Trim(v, "\"")
		result = append(result, v)
	}
	return result
}

// matchesExpect checks if any line of output matches the given regex pattern.
func matchesExpect(output, pattern string) bool {
	if pattern == "" {
		return true
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		// Fall back to literal match
		return strings.Contains(output, pattern)
	}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}
