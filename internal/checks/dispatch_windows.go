//go:build windows

package checks

// getChecker returns the appropriate checker for the given check type on Windows.
func getChecker(checkType string) Checker {
	switch checkType {
	case "REGISTRY_SETTING":
		return &RegistryChecker{}
	case "USER_RIGHTS_POLICY":
		return &UserRightsChecker{}
	case "WMI_POLICY":
		return &WMIChecker{}
	case "AUDIT_POLICY_SUBCATEGORY":
		return &AuditPolicyChecker{}
	case "LOCKOUT_POLICY":
		return &LockoutPolicyChecker{}
	case "PASSWORD_POLICY":
		return &PasswordPolicyChecker{}
	case "BANNER_CHECK":
		return &BannerChecker{}
	case "ANONYMOUS_SID_SETTING":
		return &AnonymousSIDChecker{}
	// Linux types — not supported on Windows
	case "CMD_EXEC", "FILE_CONTENT_CHECK", "FILE_CONTENT_CHECK_NOT":
		return &UnsupportedPlatformChecker{Platform: "Windows", CheckType: checkType}
	default:
		return nil
	}
}
