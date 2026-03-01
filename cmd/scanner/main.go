package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"host-config-review-scanner/internal/executor"
	"host-config-review-scanner/internal/parser"
	"host-config-review-scanner/internal/report"
)

func main() {
	ruleFile := flag.String("rule", "", "Path to the .audit rule file (required)")
	outputFile := flag.String("output", "report.html", "Path for the HTML report output")
	verbose := flag.Bool("verbose", false, "Print per-check results to stdout")
	force := flag.Bool("force", false, "Bypass condition/version checks (run all checks regardless of OS/version guards)")
	flag.Parse()

	if *ruleFile == "" {
		fmt.Fprintln(os.Stderr, "Error: -rule flag is required")
		fmt.Fprintln(os.Stderr, "Usage: scanner -rule <path/to/file.audit> [-output report.html] [-verbose] [-force]")
		os.Exit(1)
	}

	// Check that rule file exists
	if _, err := os.Stat(*ruleFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: rule file not found: %s\n", *ruleFile)
		os.Exit(1)
	}

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║           Host Configuration Review Scanner                 ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Phase 1: Parse
	fmt.Printf("→ Parsing rule file: %s\n", *ruleFile)
	parseStart := time.Now()
	audit, err := parser.Parse(*ruleFile)
	if err != nil {
		log.Fatalf("Failed to parse rule file: %v", err)
	}
	parseDur := time.Since(parseStart)

	fmt.Printf("  Rule: %s\n", audit.Metadata.DisplayName)
	fmt.Printf("  Type: %s (spec: %s %s %s)\n", audit.CheckType, audit.Metadata.SpecType, audit.Metadata.SpecName, audit.Metadata.SpecVersion)
	fmt.Printf("  Variables: %d defined\n", len(audit.Variables))
	fmt.Printf("  Parsed in %v\n", parseDur.Round(time.Millisecond))

	nodeCount := countNodes(audit.Nodes)
	fmt.Printf("  Nodes: %d (checks + conditions + reports)\n", nodeCount)
	if *force {
		fmt.Println("  ⚠ Force mode: all condition/version guards will be bypassed")
	}
	fmt.Println()

	// Phase 2: Execute
	fmt.Println("→ Running checks...")
	execStart := time.Now()
	results := executor.Execute(audit, executor.ExecuteOptions{
		Verbose: *verbose,
		Force:   *force,
	})
	execDur := time.Since(execStart)

	// Count results
	var passed, failed, warning, errored, skipped int
	for _, r := range results {
		switch r.Status {
		case "PASSED":
			passed++
		case "FAILED":
			failed++
		case "WARNING":
			warning++
		case "ERROR":
			errored++
		case "SKIPPED":
			skipped++
		}
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  RESULTS: %d total | %d passed | %d failed | %d warning | %d error | %d skipped\n",
		len(results), passed, failed, warning, errored, skipped)
	fmt.Printf("  Scan completed in %v\n", execDur.Round(time.Millisecond))
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Phase 3: Report
	fmt.Printf("→ Generating report: %s\n", *outputFile)
	totalDur := parseDur + execDur
	if err := report.GenerateHTML(*outputFile, audit, results, totalDur); err != nil {
		log.Fatalf("Failed to generate report: %v", err)
	}
	fmt.Printf("  Report saved to: %s\n", *outputFile)
	fmt.Println()
	fmt.Println("Done.")
}

func countNodes(nodes []parser.Node) int {
	count := 0
	for _, n := range nodes {
		count++
		switch v := n.(type) {
		case *parser.IfBlock:
			count += len(v.Condition.Items)
			count += countNodes(v.Then)
			count += countNodes(v.Else)
		}
	}
	return count
}
