//go:build windows

package checks

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"

	"host-config-review-scanner/internal/parser"
)

// RegistryChecker handles REGISTRY_SETTING type checks on Windows.
type RegistryChecker struct{}

func (r *RegistryChecker) Execute(item parser.CustomItem) Result {
	if item.RegKey == "" || item.RegItem == "" {
		return Result{Status: StatusError, Output: "reg_key or reg_item not specified"}
	}

	// Parse the hive and subkey
	hive, subkey, err := parseRegPath(item.RegKey)
	if err != nil {
		return Result{Status: StatusError, Output: err.Error()}
	}

	// Open the registry key
	key, err := registry.OpenKey(hive, subkey, registry.READ)
	if err != nil {
		if strings.EqualFold(item.RegOption, "CAN_NOT_BE_NULL") {
			return Result{
				Status: StatusFail,
				Output: fmt.Sprintf("registry key not found: %s (required by CAN_NOT_BE_NULL)", item.RegKey),
			}
		}
		return Result{
			Status: StatusFail,
			Output: fmt.Sprintf("registry key not found: %s (%v)", item.RegKey, err),
		}
	}
	defer key.Close()

	// Read the value based on value_type
	switch strings.ToUpper(item.ValueType) {
	case "POLICY_DWORD":
		return checkDwordValue(key, item)
	case "POLICY_TEXT":
		return checkTextValue(key, item)
	default:
		// Try DWORD first, then string
		return checkDwordValue(key, item)
	}
}

func checkDwordValue(key registry.Key, item parser.CustomItem) Result {
	val, _, err := key.GetIntegerValue(item.RegItem)
	if err != nil {
		// Try string value as fallback
		sval, _, serr := key.GetStringValue(item.RegItem)
		if serr != nil {
			if strings.EqualFold(item.RegOption, "CAN_NOT_BE_NULL") {
				return Result{
					Status: StatusFail,
					Output: fmt.Sprintf("registry value '%s' not found in %s (required by CAN_NOT_BE_NULL)", item.RegItem, item.RegKey),
				}
			}
			return Result{
				Status: StatusFail,
				Output: fmt.Sprintf("could not read registry value '%s': %v", item.RegItem, err),
			}
		}
		// Try to parse string as integer
		ival, perr := strconv.ParseUint(sval, 10, 64)
		if perr != nil {
			return Result{
				Status: StatusFail,
				Output: fmt.Sprintf("expected DWORD, got string '%s' for %s\\%s", sval, item.RegKey, item.RegItem),
			}
		}
		val = ival
	}

	actual := fmt.Sprintf("%d", val)

	// Check against expected values (supports || for OR)
	expected := parseOrValues(item.ValueData)
	for _, exp := range expected {
		exp = strings.TrimSpace(exp)
		if exp == actual {
			return Result{
				Status: StatusPass,
				Output: fmt.Sprintf("%s\\%s = %s (expected: %s)", item.RegKey, item.RegItem, actual, item.ValueData),
			}
		}
		// Try numeric comparison
		expNum, err := strconv.ParseUint(exp, 10, 64)
		if err == nil && expNum == val {
			return Result{
				Status: StatusPass,
				Output: fmt.Sprintf("%s\\%s = %s (expected: %s)", item.RegKey, item.RegItem, actual, item.ValueData),
			}
		}
	}

	return Result{
		Status: StatusFail,
		Output: fmt.Sprintf("%s\\%s = %s (expected: %s)", item.RegKey, item.RegItem, actual, item.ValueData),
	}
}

func checkTextValue(key registry.Key, item parser.CustomItem) Result {
	val, _, err := key.GetStringValue(item.RegItem)
	if err != nil {
		if strings.EqualFold(item.RegOption, "CAN_NOT_BE_NULL") {
			return Result{
				Status: StatusFail,
				Output: fmt.Sprintf("registry value '%s' not found in %s (required by CAN_NOT_BE_NULL)", item.RegItem, item.RegKey),
			}
		}
		return Result{
			Status: StatusFail,
			Output: fmt.Sprintf("could not read registry value '%s': %v", item.RegItem, err),
		}
	}

	// CHECK_REGEX mode: treat value_data as a regex
	if strings.EqualFold(item.CheckTypeField, "CHECK_REGEX") {
		re, rerr := regexp.Compile(item.ValueData)
		if rerr != nil {
			return Result{
				Status: StatusError,
				Output: fmt.Sprintf("invalid regex in value_data: %v", rerr),
			}
		}
		if re.MatchString(val) {
			return Result{
				Status: StatusPass,
				Output: fmt.Sprintf("%s\\%s = '%s' matches regex '%s'", item.RegKey, item.RegItem, val, item.ValueData),
			}
		}
		return Result{
			Status: StatusFail,
			Output: fmt.Sprintf("%s\\%s = '%s' does not match regex '%s'", item.RegKey, item.RegItem, val, item.ValueData),
		}
	}

	// Exact match with OR support
	expected := parseOrValues(item.ValueData)
	for _, exp := range expected {
		if exp == val {
			return Result{
				Status: StatusPass,
				Output: fmt.Sprintf("%s\\%s = '%s' (expected: %s)", item.RegKey, item.RegItem, val, item.ValueData),
			}
		}
	}

	return Result{
		Status: StatusFail,
		Output: fmt.Sprintf("%s\\%s = '%s' (expected: %s)", item.RegKey, item.RegItem, val, item.ValueData),
	}
}

func parseRegPath(regPath string) (registry.Key, string, error) {
	// Split at first backslash
	parts := strings.SplitN(regPath, `\`, 2)
	if len(parts) < 2 {
		return 0, "", fmt.Errorf("invalid registry path: %s", regPath)
	}

	hiveStr := strings.ToUpper(parts[0])
	subkey := parts[1]

	var hive registry.Key
	switch hiveStr {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		hive = registry.LOCAL_MACHINE
	case "HKCU", "HKEY_CURRENT_USER":
		hive = registry.CURRENT_USER
	case "HKU", "HKEY_USERS":
		hive = registry.USERS
	case "HKCR", "HKEY_CLASSES_ROOT":
		hive = registry.CLASSES_ROOT
	case "HKCC", "HKEY_CURRENT_CONFIG":
		hive = registry.CURRENT_CONFIG
	default:
		return 0, "", fmt.Errorf("unknown registry hive: %s", hiveStr)
	}

	return hive, subkey, nil
}
