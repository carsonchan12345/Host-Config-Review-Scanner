package checks

import (
	"host-config-review-scanner/internal/parser"
)

// UnsupportedPlatformChecker returns SKIP for checks not applicable to the current OS.
type UnsupportedPlatformChecker struct {
	Platform  string
	CheckType string
}

func (u *UnsupportedPlatformChecker) Execute(item parser.CustomItem) Result {
	return Result{
		Status: StatusSkip,
		Output: u.CheckType + " is not supported on " + u.Platform,
	}
}
