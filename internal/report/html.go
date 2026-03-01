package report

import (
	"fmt"
	"html"
	"os"
	"runtime"
	"strings"
	"time"

	"host-config-review-scanner/internal/executor"
	"host-config-review-scanner/internal/parser"
)

// GenerateHTML writes a self-contained HTML report to the given file path.
func GenerateHTML(outputPath string, audit *parser.AuditFile, results []executor.CheckResult, scanDuration time.Duration) error {
	hostname, _ := os.Hostname()

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
	total := len(results)

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write HTML
	fmt.Fprintf(f, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Host Config Review - %s</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6;padding:20px}
.container{max-width:1200px;margin:0 auto}
h1{font-size:1.8rem;margin-bottom:8px;color:#f8fafc}
.meta{color:#94a3b8;font-size:0.9rem;margin-bottom:24px}
.meta span{margin-right:16px}
.summary{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
.summary-card{padding:16px 24px;border-radius:8px;text-align:center;min-width:120px}
.summary-card .count{font-size:2rem;font-weight:700}
.summary-card .label{font-size:0.8rem;text-transform:uppercase;letter-spacing:0.5px;opacity:0.8}
.card-pass{background:#065f46;border:1px solid #10b981}
.card-fail{background:#7f1d1d;border:1px solid #ef4444}
.card-warn{background:#78350f;border:1px solid #f59e0b}
.card-error{background:#581c87;border:1px solid #a855f7}
.card-skip{background:#1e293b;border:1px solid #475569}
.card-total{background:#1e3a5f;border:1px solid #3b82f6}
.progress-bar{height:8px;border-radius:4px;background:#1e293b;margin-bottom:24px;overflow:hidden;display:flex}
.progress-bar .seg-pass{background:#10b981}
.progress-bar .seg-fail{background:#ef4444}
.progress-bar .seg-warn{background:#f59e0b}
.progress-bar .seg-error{background:#a855f7}
.progress-bar .seg-skip{background:#475569}
.filters{margin-bottom:16px;display:flex;gap:8px;flex-wrap:wrap}
.filter-btn{padding:6px 14px;border:1px solid #334155;border-radius:4px;background:#1e293b;color:#e2e8f0;cursor:pointer;font-size:0.85rem;transition:all 0.2s}
.filter-btn:hover{background:#334155}
.filter-btn.active{background:#3b82f6;border-color:#3b82f6}
table{width:100%%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden}
th{padding:12px 16px;text-align:left;background:#0f172a;color:#94a3b8;font-size:0.8rem;text-transform:uppercase;letter-spacing:0.5px}
td{padding:12px 16px;border-top:1px solid #334155;vertical-align:top}
tr.row-pass{border-left:3px solid #10b981}
tr.row-fail{border-left:3px solid #ef4444}
tr.row-warn{border-left:3px solid #f59e0b}
tr.row-error{border-left:3px solid #a855f7}
tr.row-skip{border-left:3px solid #475569}
.badge{padding:2px 8px;border-radius:3px;font-size:0.75rem;font-weight:600;display:inline-block}
.badge-pass{background:#065f46;color:#6ee7b7}
.badge-fail{background:#7f1d1d;color:#fca5a5}
.badge-warn{background:#78350f;color:#fcd34d}
.badge-error{background:#581c87;color:#d8b4fe}
.badge-skip{background:#1e293b;color:#94a3b8;border:1px solid #475569}
.details-toggle{cursor:pointer;color:#60a5fa;font-size:0.85rem;text-decoration:underline}
.details-content{display:none;margin-top:8px;padding:12px;background:#0f172a;border-radius:4px;font-size:0.85rem;white-space:pre-wrap;word-break:break-word;max-height:400px;overflow-y:auto}
.details-content.open{display:block}
.type-tag{font-size:0.7rem;color:#94a3b8;background:#334155;padding:1px 6px;border-radius:3px;display:inline-block;margin-left:8px}
.search-box{width:100%%;padding:10px 16px;border:1px solid #334155;border-radius:6px;background:#0f172a;color:#e2e8f0;font-size:0.9rem;margin-bottom:16px}
.search-box:focus{outline:none;border-color:#3b82f6}
</style>
</head>
<body>
<div class="container">
<h1>Host Configuration Review Report</h1>
<div class="meta">
<span>Host: <strong>%s</strong></span>
<span>OS: <strong>%s/%s</strong></span>
<span>Scan: <strong>%s</strong></span>
<span>Duration: <strong>%s</strong></span>
<span>Rule: <strong>%s</strong></span>
</div>
`,
		html.EscapeString(audit.Metadata.DisplayName),
		html.EscapeString(hostname),
		runtime.GOOS, runtime.GOARCH,
		time.Now().Format("2006-01-02 15:04:05"),
		scanDuration.Round(time.Millisecond).String(),
		html.EscapeString(audit.Metadata.DisplayName),
	)

	// Summary cards
	pctPass := 0.0
	pctFail := 0.0
	pctWarn := 0.0
	pctErr := 0.0
	pctSkip := 0.0
	if total > 0 {
		pctPass = float64(passed) / float64(total) * 100
		pctFail = float64(failed) / float64(total) * 100
		pctWarn = float64(warning) / float64(total) * 100
		pctErr = float64(errored) / float64(total) * 100
		pctSkip = float64(skipped) / float64(total) * 100
	}

	fmt.Fprintf(f, `<div class="summary">
<div class="summary-card card-total"><div class="count">%d</div><div class="label">Total</div></div>
<div class="summary-card card-pass"><div class="count">%d</div><div class="label">Passed (%.0f%%)</div></div>
<div class="summary-card card-fail"><div class="count">%d</div><div class="label">Failed (%.0f%%)</div></div>
<div class="summary-card card-warn"><div class="count">%d</div><div class="label">Warning (%.0f%%)</div></div>
<div class="summary-card card-error"><div class="count">%d</div><div class="label">Error (%.0f%%)</div></div>
<div class="summary-card card-skip"><div class="count">%d</div><div class="label">Skipped (%.0f%%)</div></div>
</div>
`,
		total,
		passed, pctPass,
		failed, pctFail,
		warning, pctWarn,
		errored, pctErr,
		skipped, pctSkip,
	)

	// Progress bar
	fmt.Fprintf(f, `<div class="progress-bar">
<div class="seg-pass" style="width:%.1f%%"></div>
<div class="seg-fail" style="width:%.1f%%"></div>
<div class="seg-warn" style="width:%.1f%%"></div>
<div class="seg-error" style="width:%.1f%%"></div>
<div class="seg-skip" style="width:%.1f%%"></div>
</div>
`, pctPass, pctFail, pctWarn, pctErr, pctSkip)

	// Search and filters
	fmt.Fprintf(f, `<input type="text" class="search-box" id="searchBox" placeholder="Search checks..." onkeyup="filterTable()">
<div class="filters">
<button class="filter-btn active" onclick="setFilter('all',this)">All (%d)</button>
<button class="filter-btn" onclick="setFilter('PASSED',this)">Passed (%d)</button>
<button class="filter-btn" onclick="setFilter('FAILED',this)">Failed (%d)</button>
<button class="filter-btn" onclick="setFilter('WARNING',this)">Warning (%d)</button>
<button class="filter-btn" onclick="setFilter('ERROR',this)">Error (%d)</button>
<button class="filter-btn" onclick="setFilter('SKIPPED',this)">Skipped (%d)</button>
</div>
`, total, passed, failed, warning, errored, skipped)

	// Results table
	fmt.Fprintf(f, `<table id="resultsTable">
<thead><tr><th>#</th><th>Check</th><th>Status</th><th>Type</th><th>Details</th></tr></thead>
<tbody>
`)

	for i, r := range results {
		rowClass := statusRowClass(r.Status)
		badgeClass := statusBadgeClass(r.Status)

		desc := html.EscapeString(r.Description)
		output := html.EscapeString(r.Output)
		info := html.EscapeString(r.Info)
		solution := html.EscapeString(r.Solution)

		detailParts := []string{}
		if output != "" {
			detailParts = append(detailParts, "<strong>Output:</strong>\n"+output)
		}
		if info != "" {
			detailParts = append(detailParts, "<strong>Info:</strong>\n"+info)
		}
		if solution != "" {
			detailParts = append(detailParts, "<strong>Solution:</strong>\n"+solution)
		}
		if r.Reference != "" {
			detailParts = append(detailParts, "<strong>Reference:</strong>\n"+html.EscapeString(r.Reference))
		}
		details := strings.Join(detailParts, "\n\n")

		fmt.Fprintf(f, `<tr class="%s" data-status="%s">
<td>%d</td>
<td>%s</td>
<td><span class="badge %s">%s</span></td>
<td><span class="type-tag">%s</span></td>
<td>`,
			rowClass, r.Status,
			i+1,
			desc,
			badgeClass, r.Status,
			html.EscapeString(r.CheckType),
		)

		if details != "" {
			fmt.Fprintf(f, `<span class="details-toggle" onclick="toggleDetails(this)">Show details</span>
<div class="details-content">%s</div>`, details)
		}

		fmt.Fprintf(f, `</td></tr>
`)
	}

	fmt.Fprintf(f, `</tbody></table>
`)

	// JavaScript
	fmt.Fprintf(f, `<script>
var currentFilter='all';
function setFilter(status,btn){
  currentFilter=status;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  filterTable();
}
function filterTable(){
  var search=document.getElementById('searchBox').value.toLowerCase();
  var rows=document.querySelectorAll('#resultsTable tbody tr');
  rows.forEach(function(row){
    var status=row.getAttribute('data-status');
    var text=row.textContent.toLowerCase();
    var showFilter=(currentFilter==='all'||status===currentFilter);
    var showSearch=(!search||text.indexOf(search)>=0);
    row.style.display=(showFilter&&showSearch)?'':'none';
  });
}
function toggleDetails(el){
  var content=el.nextElementSibling;
  content.classList.toggle('open');
  el.textContent=content.classList.contains('open')?'Hide details':'Show details';
}
</script>
</div>
</body>
</html>
`)

	return nil
}

func statusRowClass(status string) string {
	switch status {
	case "PASSED":
		return "row-pass"
	case "FAILED":
		return "row-fail"
	case "WARNING":
		return "row-warn"
	case "ERROR":
		return "row-error"
	case "SKIPPED":
		return "row-skip"
	default:
		return ""
	}
}

func statusBadgeClass(status string) string {
	switch status {
	case "PASSED":
		return "badge-pass"
	case "FAILED":
		return "badge-fail"
	case "WARNING":
		return "badge-warn"
	case "ERROR":
		return "badge-error"
	case "SKIPPED":
		return "badge-skip"
	default:
		return ""
	}
}
