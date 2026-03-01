//go:build windows

package checks

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"host-config-review-scanner/internal/parser"
)

// AuditPolicyChecker handles AUDIT_POLICY_SUBCATEGORY type checks on Windows.
type AuditPolicyChecker struct{}

func (a *AuditPolicyChecker) Execute(item parser.CustomItem) Result {
	if item.AuditPolicySubcategory == "" {
		return Result{Status: StatusError, Output: "audit_policy_subcategory not specified"}
	}

	// Query the audit policy using auditpol.exe
	actual, err := getAuditPolicySetting(item.AuditPolicySubcategory)
	if err != nil {
		return Result{
			Status: StatusError,
			Output: fmt.Sprintf("failed to query audit policy for '%s': %v", item.AuditPolicySubcategory, err),
		}
	}

	expected := strings.TrimSpace(strings.Trim(item.ValueData, "\""))

	// Normalize for comparison
	actualNorm := normalizeAuditSetting(actual)
	expectedNorm := normalizeAuditSetting(expected)

	if actualNorm == expectedNorm {
		return Result{
			Status: StatusPass,
			Output: fmt.Sprintf("Audit '%s' = '%s' (expected: '%s')", item.AuditPolicySubcategory, actual, expected),
		}
	}

	// Check if actual is a superset (e.g., "Success and Failure" satisfies "Success")
	if isAuditSuperset(actualNorm, expectedNorm) {
		return Result{
			Status: StatusPass,
			Output: fmt.Sprintf("Audit '%s' = '%s' (contains expected: '%s')", item.AuditPolicySubcategory, actual, expected),
		}
	}

	return Result{
		Status: StatusFail,
		Output: fmt.Sprintf("Audit '%s' = '%s' (expected: '%s')", item.AuditPolicySubcategory, actual, expected),
	}
}

func getAuditPolicySetting(subcategory string) (string, error) {
	cmd := exec.Command("auditpol.exe", "/get", "/subcategory:"+subcategory)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("auditpol: %v, stderr: %s", err, stderr.String())
	}

	// Parse the output to find the setting
	output := stdout.String()
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "System") || strings.HasPrefix(line, "Category") {
			continue
		}
		// The output format is:  Subcategory_Name     Setting
		if strings.Contains(strings.ToLower(line), strings.ToLower(subcategory)) {
			// Extract the setting (last column)
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// The setting is the last 1-3 words (e.g., "Success and Failure", "Success", "No Auditing")
				setting := extractAuditSetting(line, subcategory)
				return setting, nil
			}
		}
	}

	return "", fmt.Errorf("subcategory '%s' not found in auditpol output", subcategory)
}

func extractAuditSetting(line, subcategory string) string {
	// The setting comes after the subcategory name
	lower := strings.ToLower(line)
	subLower := strings.ToLower(subcategory)
	idx := strings.Index(lower, subLower)
	if idx >= 0 {
		rest := strings.TrimSpace(line[idx+len(subcategory):])
		return rest
	}
	// Fallback: return last few words
	fields := strings.Fields(line)
	if len(fields) >= 3 && (fields[len(fields)-1] == "Failure" || fields[len(fields)-1] == "Auditing") {
		if fields[len(fields)-2] == "and" || fields[len(fields)-2] == "No" {
			return strings.Join(fields[len(fields)-3:], " ")
		}
		return fields[len(fields)-1]
	}
	if len(fields) >= 1 {
		return fields[len(fields)-1]
	}
	return ""
}

func normalizeAuditSetting(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "  ", " ")
	return s
}

func isAuditSuperset(actual, expected string) bool {
	// "success and failure" contains both "success" and "failure"
	if actual == "success and failure" {
		return expected == "success" || expected == "failure"
	}
	return false
}
