//go:build windows

package checks

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"host-config-review-scanner/internal/parser"
)

// LockoutPolicyChecker handles LOCKOUT_POLICY type checks on Windows.
type LockoutPolicyChecker struct{}

func (l *LockoutPolicyChecker) Execute(item parser.CustomItem) Result {
	if item.LockoutPolicy == "" {
		return Result{Status: StatusError, Output: "lockout_policy field not specified"}
	}

	actual, err := getLockoutPolicySetting(item.LockoutPolicy)
	if err != nil {
		return Result{
			Status: StatusError,
			Output: fmt.Sprintf("failed to query lockout policy '%s': %v", item.LockoutPolicy, err),
		}
	}

	return compareNumericOrString(actual, item.ValueData, item.LockoutPolicy, item.ValueType)
}

// PasswordPolicyChecker handles PASSWORD_POLICY type checks on Windows.
type PasswordPolicyChecker struct{}

func (p *PasswordPolicyChecker) Execute(item parser.CustomItem) Result {
	if item.PasswordPolicy == "" {
		return Result{Status: StatusError, Output: "password_policy field not specified"}
	}

	actual, err := getPasswordPolicySetting(item.PasswordPolicy)
	if err != nil {
		return Result{
			Status: StatusError,
			Output: fmt.Sprintf("failed to query password policy '%s': %v", item.PasswordPolicy, err),
		}
	}

	return compareNumericOrString(actual, item.ValueData, item.PasswordPolicy, item.ValueType)
}

// BannerChecker handles BANNER_CHECK type checks on Windows.
type BannerChecker struct{}

func (b *BannerChecker) Execute(item parser.CustomItem) Result {
	// Banner checks typically read from registry
	// Delegate to registry check with the banner-specific keys
	regChecker := &RegistryChecker{}

	if item.RegKey != "" {
		return regChecker.Execute(item)
	}

	return Result{
		Status: StatusSkip,
		Output: "BANNER_CHECK: no reg_key specified, cannot verify",
	}
}

// AnonymousSIDChecker handles ANONYMOUS_SID_SETTING type checks on Windows.
type AnonymousSIDChecker struct{}

func (a *AnonymousSIDChecker) Execute(item parser.CustomItem) Result {
	// This typically checks registry settings related to anonymous SID translation
	regChecker := &RegistryChecker{}

	if item.RegKey != "" {
		return regChecker.Execute(item)
	}

	return Result{
		Status: StatusSkip,
		Output: "ANONYMOUS_SID_SETTING: no reg_key specified",
	}
}

// --- Helper functions for security policy ---

func getLockoutPolicySetting(policyName string) (string, error) {
	return getNetAccountsSetting(policyName)
}

func getPasswordPolicySetting(policyName string) (string, error) {
	return getNetAccountsSetting(policyName)
}

func getNetAccountsSetting(settingName string) (string, error) {
	cmd := exec.Command("net", "accounts")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("net accounts: %v, stderr: %s", err, stderr.String())
	}

	output := stdout.String()
	lines := strings.Split(output, "\n")

	// Map of known policy names to the label in 'net accounts' output
	labelMap := map[string]string{
		"LOCKOUT_DURATION":          "Lockout duration",
		"LOCKOUT_THRESHOLD":         "Lockout threshold",
		"LOCKOUT_OBSERVATION_WINDOW": "Lockout observation window",
		"MINIMUM_PASSWORD_AGE":      "Minimum password age",
		"MAXIMUM_PASSWORD_AGE":      "Maximum password age",
		"MINIMUM_PASSWORD_LENGTH":   "Minimum password length",
		"PASSWORD_HISTORY_SIZE":     "Length of password history maintained",
		"FORCE_LOGOFF_TIME":         "Force user logoff how long after time expires",
	}

	lookupLabel := settingName
	if mapped, ok := labelMap[strings.ToUpper(settingName)]; ok {
		lookupLabel = mapped
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), strings.ToLower(lookupLabel)) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	return "", fmt.Errorf("setting '%s' not found in net accounts output", settingName)
}

func compareNumericOrString(actual, valueData, policyName, valueType string) Result {
	expected := parseOrValues(valueData)

	// Try numeric comparison first
	actNum, actErr := strconv.Atoi(strings.TrimSpace(actual))

	for _, exp := range expected {
		exp = strings.TrimSpace(exp)

		if actErr == nil {
			expNum, expErr := strconv.Atoi(exp)
			if expErr == nil && actNum == expNum {
				return Result{
					Status: StatusPass,
					Output: fmt.Sprintf("%s = %s (expected: %s)", policyName, actual, valueData),
				}
			}
		}

		// String comparison
		if strings.EqualFold(actual, exp) {
			return Result{
				Status: StatusPass,
				Output: fmt.Sprintf("%s = '%s' (expected: %s)", policyName, actual, valueData),
			}
		}
	}

	return Result{
		Status: StatusFail,
		Output: fmt.Sprintf("%s = '%s' (expected: %s)", policyName, actual, valueData),
	}
}
