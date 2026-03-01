package executor

import (
	"fmt"
	"log"
	"time"

	"host-config-review-scanner/internal/checks"
	"host-config-review-scanner/internal/parser"
)

// CheckResult holds the outcome of a single check for reporting.
type CheckResult struct {
	Description string
	Status      string // PASSED, FAILED, WARNING, ERROR, SKIPPED
	Info        string
	Solution    string
	Reference   string
	SeeAlso     string
	Output      string // Command output or comparison details
	CheckType   string // The type of check (CMD_EXEC, REGISTRY_SETTING, etc.)
	Duration    time.Duration
}

// ExecuteOptions controls executor behavior.
type ExecuteOptions struct {
	Verbose bool // Print per-check results to stdout
	Force   bool // Bypass all condition evaluations (treat as true)
}

// Execute walks the parsed audit AST and runs all checks, collecting results.
func Execute(audit *parser.AuditFile, opts ExecuteOptions) []CheckResult {
	var results []CheckResult
	executeNodes(audit.Nodes, &results, opts)
	return results
}

func executeNodes(nodes []parser.Node, results *[]CheckResult, opts ExecuteOptions) {
	for _, node := range nodes {
		switch n := node.(type) {
		case *parser.CustomItem:
			res := executeCustomItem(n, opts)
			*results = append(*results, res)
		case *parser.ReportItem:
			res := CheckResult{
				Description: n.Description,
				Status:      n.Status,
				Info:        n.Info,
				Solution:    n.Solution,
				Reference:   n.Reference,
				SeeAlso:     n.SeeAlso,
				CheckType:   "report",
			}
			*results = append(*results, res)
			if opts.Verbose {
				printResult(res)
			}
		case *parser.IfBlock:
			executeIfBlock(n, results, opts)
		}
	}
}

func executeCustomItem(item *parser.CustomItem, opts ExecuteOptions) CheckResult {
	start := time.Now()
	result := checks.Dispatch(*item)
	dur := time.Since(start)

	cr := CheckResult{
		Description: item.Description,
		Status:      result.Status,
		Info:        item.Info,
		Solution:    item.Solution,
		Reference:   item.Reference,
		SeeAlso:     item.SeeAlso,
		Output:      result.Output,
		CheckType:   item.Type,
		Duration:    dur,
	}

	if result.Err != nil {
		cr.Status = checks.StatusError
		cr.Output = result.Err.Error()
	}

	if opts.Verbose {
		printResult(cr)
	}

	return cr
}

func executeIfBlock(ifBlock *parser.IfBlock, results *[]CheckResult, opts ExecuteOptions) {
	conditionPassed := evaluateCondition(ifBlock.Condition, opts)

	if ifBlock.Condition.AutoFailed {
		// auto:"FAILED" semantics:
		// If ALL condition items PASS → emit <then> block (PASSED results)
		// If ANY condition item FAILS → the block is implicitly FAILED (or run <else> if present)
		if conditionPassed {
			executeNodes(ifBlock.Then, results, opts)
		} else {
			if len(ifBlock.Else) > 0 {
				executeNodes(ifBlock.Else, results, opts)
			}
			// If no <else>, the items in <condition> already recorded failure
		}
	} else {
		// Standard <if> semantics
		if conditionPassed {
			executeNodes(ifBlock.Then, results, opts)
		} else {
			if len(ifBlock.Else) > 0 {
				executeNodes(ifBlock.Else, results, opts)
			}
		}
	}
}

func evaluateCondition(cond parser.Condition, opts ExecuteOptions) bool {
	if opts.Force {
		if opts.Verbose {
			log.Printf("[FORCE] Bypassing condition evaluation (treating as PASS)")
		}
		return true
	}

	if len(cond.Items) == 0 {
		return true
	}

	switch cond.Type {
	case "AND":
		for _, item := range cond.Items {
			result := checks.Dispatch(item)
			if opts.Verbose {
				log.Printf("[CONDITION] %s: %s", item.Description, result.Status)
			}
			if result.Status != checks.StatusPass {
				return false
			}
		}
		return true

	case "OR":
		for _, item := range cond.Items {
			result := checks.Dispatch(item)
			if opts.Verbose {
				log.Printf("[CONDITION] %s: %s", item.Description, result.Status)
			}
			if result.Status == checks.StatusPass {
				return true
			}
		}
		return false

	default:
		// Treat unknown as AND
		for _, item := range cond.Items {
			result := checks.Dispatch(item)
			if result.Status != checks.StatusPass {
				return false
			}
		}
		return true
	}
}

func printResult(cr CheckResult) {
	icon := "?"
	switch cr.Status {
	case checks.StatusPass:
		icon = "✓"
	case checks.StatusFail:
		icon = "✗"
	case checks.StatusWarning:
		icon = "⚠"
	case checks.StatusError:
		icon = "!"
	case checks.StatusSkip:
		icon = "→"
	}

	desc := cr.Description
	if len(desc) > 80 {
		desc = desc[:77] + "..."
	}

	if cr.Duration > 0 {
		fmt.Printf("  [%s] %s (%s, %v)\n", icon, desc, cr.Status, cr.Duration.Round(time.Millisecond))
	} else {
		fmt.Printf("  [%s] %s (%s)\n", icon, desc, cr.Status)
	}
}
