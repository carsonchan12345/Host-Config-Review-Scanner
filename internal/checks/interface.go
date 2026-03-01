package checks

import (
	"host-config-review-scanner/internal/parser"
)

// Status constants for check results.
const (
	StatusPass    = "PASSED"
	StatusFail    = "FAILED"
	StatusWarning = "WARNING"
	StatusError   = "ERROR"
	StatusSkip    = "SKIPPED"
)

// Result represents the outcome of executing a single check.
type Result struct {
	Status string // PASSED, FAILED, WARNING, ERROR, SKIPPED
	Output string // Collected stdout/details from the check
	Err    error  // Non-nil if check execution itself errored
}

// Checker is the interface for all check implementations.
type Checker interface {
	Execute(item parser.CustomItem) Result
}

// Dispatch selects the appropriate checker for a CustomItem and runs it.
func Dispatch(item parser.CustomItem) Result {
	checker := getChecker(item.Type)
	if checker == nil {
		return Result{
			Status: StatusSkip,
			Output: "unsupported check type: " + item.Type,
		}
	}
	return checker.Execute(item)
}
