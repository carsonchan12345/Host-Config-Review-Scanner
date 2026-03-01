//go:build linux

package checks

// getChecker returns the appropriate checker for the given check type on Linux.
func getChecker(checkType string) Checker {
	switch checkType {
	case "CMD_EXEC":
		return &CmdExecChecker{}
	case "FILE_CONTENT_CHECK":
		return &FileContentChecker{}
	case "FILE_CONTENT_CHECK_NOT":
		return &FileContentCheckNotChecker{}
	// Windows types — not supported on Linux
	case "REGISTRY_SETTING", "USER_RIGHTS_POLICY", "WMI_POLICY",
		"AUDIT_POLICY_SUBCATEGORY", "LOCKOUT_POLICY", "PASSWORD_POLICY",
		"BANNER_CHECK", "ANONYMOUS_SID_SETTING":
		return &UnsupportedPlatformChecker{Platform: "Linux", CheckType: checkType}
	default:
		return nil
	}
}
