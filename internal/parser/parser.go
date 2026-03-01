package parser

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Parse reads an .audit file and returns the parsed AuditFile structure.
func Parse(filename string) (*AuditFile, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading audit file: %w", err)
	}

	af := &AuditFile{
		Variables: make(map[string]string),
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	// 1. Extract ui_metadata from comment lines
	af.Metadata, af.Variables = extractMetadata(lines)

	// 2. Strip comment and signature lines, build clean content for structural parsing
	cleanLines := stripComments(lines)
	cleanContent := strings.Join(cleanLines, "\n")

	// 3. Parse check_type
	af.CheckType, af.Version = parseCheckType(cleanContent)

	// 4. Parse group_policy (Windows only)
	af.GroupPolicy = parseGroupPolicy(cleanContent)

	// 5. Perform variable substitution on the clean content
	for varName, varDefault := range af.Variables {
		cleanContent = strings.ReplaceAll(cleanContent, "@"+varName+"@", varDefault)
	}

	// 6. Tokenize and parse the structural tree
	tokens := tokenize(cleanContent)
	af.Nodes = parseNodes(tokens)

	return af, nil
}

// --- Metadata Extraction ---

type uiMetadataXML struct {
	DisplayName   string         `xml:"display_name"`
	Spec          specXML        `xml:"spec"`
	Labels        string         `xml:"labels"`
	BenchmarkRefs string         `xml:"benchmark_refs"`
	Variables     variablesXML   `xml:"variables"`
}

type specXML struct {
	Type    string `xml:"type"`
	Name    string `xml:"name"`
	Profile string `xml:"profile"`
	Version string `xml:"version"`
	Link    string `xml:"link"`
}

type variablesXML struct {
	Variables []variableXML `xml:"variable"`
}

type variableXML struct {
	Name        string `xml:"name"`
	Default     string `xml:"default"`
	Description string `xml:"description"`
	Info        string `xml:"info"`
	ValueType   string `xml:"value_type"`
}

func extractMetadata(lines []string) (AuditMetadata, map[string]string) {
	meta := AuditMetadata{}
	vars := make(map[string]string)

	// Find and extract #<ui_metadata> ... #</ui_metadata>
	var inMeta bool
	var metaLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "#<ui_metadata>" {
			inMeta = true
			metaLines = append(metaLines, "<ui_metadata>")
			continue
		}
		if trimmed == "#</ui_metadata>" {
			metaLines = append(metaLines, "</ui_metadata>")
			inMeta = false
			continue
		}
		if inMeta {
			// Strip leading #
			stripped := strings.TrimPrefix(trimmed, "#")
			metaLines = append(metaLines, stripped)
		}
	}

	if len(metaLines) == 0 {
		return meta, vars
	}

	xmlContent := strings.Join(metaLines, "\n")
	var parsed uiMetadataXML
	if err := xml.Unmarshal([]byte(xmlContent), &parsed); err != nil {
		// Best effort — return what we have
		return meta, vars
	}

	meta.DisplayName = parsed.DisplayName
	meta.SpecType = parsed.Spec.Type
	meta.SpecName = parsed.Spec.Name
	meta.SpecProfile = parsed.Spec.Profile
	meta.SpecVersion = parsed.Spec.Version
	meta.SpecLink = parsed.Spec.Link
	meta.Labels = parsed.Labels
	meta.BenchmarkRefs = parsed.BenchmarkRefs

	for _, v := range parsed.Variables.Variables {
		vars[v.Name] = v.Default
	}

	return meta, vars
}

// --- Line Cleaning ---

func stripComments(lines []string) []string {
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip signature lines and comment lines
		if strings.HasPrefix(trimmed, "#TRUSTED") || strings.HasPrefix(trimmed, "#TRUST-RSA") {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		result = append(result, line)
	}
	return result
}

// --- check_type and group_policy parsing ---

var checkTypeRe = regexp.MustCompile(`<check_type\s*:\s*"([^"]+)"(?:\s+version\s*:\s*"([^"]+)")?\s*>`)
var groupPolicyRe = regexp.MustCompile(`<group_policy\s*:\s*"([^"]+)"\s*>`)

func parseCheckType(content string) (string, string) {
	m := checkTypeRe.FindStringSubmatch(content)
	if m == nil {
		return "", ""
	}
	ct := m[1]
	ver := ""
	if len(m) > 2 {
		ver = m[2]
	}
	return ct, ver
}

func parseGroupPolicy(content string) string {
	m := groupPolicyRe.FindStringSubmatch(content)
	if m == nil {
		return ""
	}
	return m[1]
}

// --- Tokenizer ---

type tokenType int

const (
	tokOpenCheckType tokenType = iota
	tokCloseCheckType
	tokOpenGroupPolicy
	tokCloseGroupPolicy
	tokOpenIf
	tokCloseIf
	tokOpenCondition
	tokCloseCondition
	tokOpenThen
	tokCloseThen
	tokOpenElse
	tokCloseElse
	tokOpenCustomItem
	tokCloseCustomItem
	tokOpenReport
	tokCloseReport
	tokKeyValue
)

type token struct {
	Type  tokenType
	Key   string // for key-value pairs
	Value string // for key-value pairs or tag attributes
	Attrs map[string]string
}

func tokenize(content string) []token {
	var tokens []token

	scanner := bufio.NewScanner(strings.NewReader(content))
	var inBlock bool            // inside <custom_item> or <report>
	var currentKey string
	var currentValue strings.Builder
	var inQuotedValue bool

	flushKV := func() {
		if currentKey != "" {
			tokens = append(tokens, token{Type: tokKeyValue, Key: currentKey, Value: strings.TrimSpace(currentValue.String())})
			currentKey = ""
			currentValue.Reset()
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" && !inQuotedValue {
			continue
		}

		// If we're in a multi-line quoted value, accumulate until closing quote
		if inQuotedValue {
			// Check if this line contains the closing quote
			closingIdx := findClosingQuote(currentValue.String() + "\n" + line, len(currentValue.String()) + 1)
			if closingIdx >= 0 {
				// The closing quote is at closingIdx in the concatenated string
				remaining := line
				localIdx := closingIdx - len(currentValue.String()) - 1
				if localIdx >= 0 && localIdx < len(remaining) {
					currentValue.WriteString("\n")
					currentValue.WriteString(remaining[:localIdx])
					inQuotedValue = false
					flushKV()
				} else {
					currentValue.WriteString("\n")
					currentValue.WriteString(line)
					inQuotedValue = false
					flushKV()
				}
			} else {
				currentValue.WriteString("\n")
				currentValue.WriteString(line)
			}
			continue
		}

		// Check for structural tags
		if !inBlock {
			if strings.HasPrefix(trimmed, "<check_type") {
				tokens = append(tokens, token{Type: tokOpenCheckType, Attrs: parseTagAttrs(trimmed)})
				continue
			}
			if trimmed == "</check_type>" {
				tokens = append(tokens, token{Type: tokCloseCheckType})
				continue
			}
			if strings.HasPrefix(trimmed, "<group_policy") {
				tokens = append(tokens, token{Type: tokOpenGroupPolicy, Attrs: parseTagAttrs(trimmed)})
				continue
			}
			if trimmed == "</group_policy>" {
				tokens = append(tokens, token{Type: tokCloseGroupPolicy})
				continue
			}
			if trimmed == "<if>" {
				tokens = append(tokens, token{Type: tokOpenIf})
				continue
			}
			if trimmed == "</if>" {
				tokens = append(tokens, token{Type: tokCloseIf})
				continue
			}
			if strings.HasPrefix(trimmed, "<condition") {
				tokens = append(tokens, token{Type: tokOpenCondition, Attrs: parseTagAttrs(trimmed)})
				continue
			}
			if trimmed == "</condition>" {
				tokens = append(tokens, token{Type: tokCloseCondition})
				continue
			}
			if trimmed == "<then>" {
				tokens = append(tokens, token{Type: tokOpenThen})
				continue
			}
			if trimmed == "</then>" {
				tokens = append(tokens, token{Type: tokCloseThen})
				continue
			}
			if trimmed == "<else>" {
				tokens = append(tokens, token{Type: tokOpenElse})
				continue
			}
			if trimmed == "</else>" {
				tokens = append(tokens, token{Type: tokCloseElse})
				continue
			}
			if trimmed == "<custom_item>" {
				tokens = append(tokens, token{Type: tokOpenCustomItem})
				inBlock = true
				continue
			}
			if strings.HasPrefix(trimmed, "<report") {
				tokens = append(tokens, token{Type: tokOpenReport, Attrs: parseTagAttrs(trimmed)})
				inBlock = true
				continue
			}
			continue
		}

		// Inside a block — parse key:value pairs or closing tags
		if trimmed == "</custom_item>" {
			flushKV()
			tokens = append(tokens, token{Type: tokCloseCustomItem})
			inBlock = false
			continue
		}
		if trimmed == "</report>" {
			flushKV()
			tokens = append(tokens, token{Type: tokCloseReport})
			inBlock = false
			continue
		}

		// Try to parse a key : value pair
		if idx := findKVSeparator(trimmed); idx > 0 {
			flushKV()
			currentKey = strings.TrimSpace(trimmed[:idx])
			valPart := strings.TrimSpace(trimmed[idx+1:])

			// Check if value is a quoted string
			if strings.HasPrefix(valPart, "\"") {
				// Find the closing quote, accounting for escaped quotes
				inner := valPart[1:]
				closeIdx := findUnescapedQuote(inner)
				if closeIdx >= 0 {
					// Single-line quoted value
					currentValue.WriteString(inner[:closeIdx])
					flushKV()
				} else {
					// Multi-line quoted value
					currentValue.WriteString(inner)
					inQuotedValue = true
				}
			} else {
				// Unquoted value (e.g., CAN_NOT_BE_NULL, CMD_EXEC, etc.)
				currentValue.WriteString(valPart)
				flushKV()
			}
		} else {
			// Continuation of a value (shouldn't happen often outside of quoted strings)
			if currentKey != "" {
				currentValue.WriteString("\n")
				currentValue.WriteString(trimmed)
			}
		}
	}

	return tokens
}

// findKVSeparator finds the index of the first ':' that looks like a key-value separator.
// In our format, keys are identifiers (alphanumeric + underscore) followed by whitespace and ':'.
func findKVSeparator(line string) int {
	// Match pattern: word_chars spaces : space+ value
	re := regexp.MustCompile(`^(\w+)\s+:\s`)
	m := re.FindStringIndex(line)
	if m == nil {
		// Also try without space before colon: "word:"
		re2 := regexp.MustCompile(`^(\w+)\s*:\s`)
		m2 := re2.FindStringIndex(line)
		if m2 == nil {
			return -1
		}
		idx := strings.Index(line[m2[0]:m2[1]], ":")
		return m2[0] + idx
	}
	idx := strings.Index(line[m[0]:m[1]], ":")
	return m[0] + idx
}

// findUnescapedQuote finds the first unescaped " in s.
func findUnescapedQuote(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			// Count preceding backslashes
			numBackslashes := 0
			for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
				numBackslashes++
			}
			if numBackslashes%2 == 0 {
				return i
			}
		}
	}
	return -1
}

// findClosingQuote finds the closing quote in the accumulated string.
func findClosingQuote(s string, startFrom int) int {
	for i := startFrom; i < len(s); i++ {
		if s[i] == '"' {
			numBackslashes := 0
			for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
				numBackslashes++
			}
			if numBackslashes%2 == 0 {
				return i
			}
		}
	}
	return -1
}

var tagAttrRe = regexp.MustCompile(`(\w+)\s*:\s*"([^"]*)"`)

func parseTagAttrs(tag string) map[string]string {
	attrs := make(map[string]string)
	matches := tagAttrRe.FindAllStringSubmatch(tag, -1)
	for _, m := range matches {
		attrs[m[1]] = m[2]
	}
	// Also check for auto attribute
	autoRe := regexp.MustCompile(`auto\s*:\s*"([^"]*)"`)
	am := autoRe.FindStringSubmatch(tag)
	if am != nil {
		attrs["auto"] = am[1]
	}
	return attrs
}

// --- AST Builder ---

type tokenStream struct {
	tokens []token
	pos    int
}

func (ts *tokenStream) peek() *token {
	if ts.pos >= len(ts.tokens) {
		return nil
	}
	return &ts.tokens[ts.pos]
}

func (ts *tokenStream) next() *token {
	if ts.pos >= len(ts.tokens) {
		return nil
	}
	t := &ts.tokens[ts.pos]
	ts.pos++
	return t
}

func (ts *tokenStream) expect(tt tokenType) *token {
	t := ts.next()
	if t == nil || t.Type != tt {
		return nil
	}
	return t
}

func parseNodes(tokens []token) []Node {
	ts := &tokenStream{tokens: tokens}
	// Skip to the content inside check_type (and group_policy if present)
	skipToContent(ts)
	return parseNodeList(ts)
}

func skipToContent(ts *tokenStream) {
	for {
		t := ts.peek()
		if t == nil {
			return
		}
		if t.Type == tokOpenCheckType || t.Type == tokOpenGroupPolicy {
			ts.next()
			continue
		}
		return
	}
}

func parseNodeList(ts *tokenStream) []Node {
	var nodes []Node
	for {
		t := ts.peek()
		if t == nil {
			return nodes
		}
		switch t.Type {
		case tokOpenIf:
			node := parseIfBlock(ts)
			if node != nil {
				nodes = append(nodes, node)
			}
		case tokOpenCustomItem:
			node := parseCustomItem(ts)
			if node != nil {
				nodes = append(nodes, node)
			}
		case tokOpenReport:
			node := parseReportItem(ts)
			if node != nil {
				nodes = append(nodes, node)
			}
		case tokCloseThen, tokCloseElse, tokCloseCondition, tokCloseIf,
			tokCloseCheckType, tokCloseGroupPolicy:
			return nodes
		default:
			ts.next() // skip unexpected token
		}
	}
}

func parseIfBlock(ts *tokenStream) *IfBlock {
	ts.expect(tokOpenIf) // consume <if>

	ifBlock := &IfBlock{}

	// Parse condition
	t := ts.peek()
	if t != nil && t.Type == tokOpenCondition {
		ifBlock.Condition = parseCondition(ts)
	}

	// Parse then
	t = ts.peek()
	if t != nil && t.Type == tokOpenThen {
		ts.next() // consume <then>
		ifBlock.Then = parseNodeList(ts)
		ts.expect(tokCloseThen)
	}

	// Parse else (optional)
	t = ts.peek()
	if t != nil && t.Type == tokOpenElse {
		ts.next() // consume <else>
		ifBlock.Else = parseNodeList(ts)
		ts.expect(tokCloseElse)
	}

	ts.expect(tokCloseIf) // consume </if>
	return ifBlock
}

func parseCondition(ts *tokenStream) Condition {
	t := ts.next() // consume <condition>
	cond := Condition{}

	if t.Attrs != nil {
		cond.Type = t.Attrs["type"]
		if v, ok := t.Attrs["auto"]; ok && strings.EqualFold(v, "FAILED") {
			cond.AutoFailed = true
		}
	}
	if cond.Type == "" {
		cond.Type = "AND"
	}

	// Parse custom_items inside condition
	for {
		pt := ts.peek()
		if pt == nil || pt.Type == tokCloseCondition {
			break
		}
		if pt.Type == tokOpenCustomItem {
			item := parseCustomItem(ts)
			if item != nil {
				cond.Items = append(cond.Items, *item)
			}
		} else {
			ts.next() // skip
		}
	}
	ts.expect(tokCloseCondition)
	return cond
}

func parseCustomItem(ts *tokenStream) *CustomItem {
	ts.next() // consume <custom_item>
	item := &CustomItem{
		Extra: make(map[string]string),
	}

	for {
		t := ts.peek()
		if t == nil || t.Type == tokCloseCustomItem {
			break
		}
		if t.Type != tokKeyValue {
			ts.next()
			continue
		}
		ts.next()
		setCustomItemField(item, t.Key, unescapeAuditString(t.Value))
	}
	ts.expect(tokCloseCustomItem)
	return item
}

func parseReportItem(ts *tokenStream) *ReportItem {
	t := ts.next() // consume <report type:"...">
	report := &ReportItem{}
	if t.Attrs != nil {
		report.Status = t.Attrs["type"]
	}

	for {
		pt := ts.peek()
		if pt == nil || pt.Type == tokCloseReport {
			break
		}
		if pt.Type != tokKeyValue {
			ts.next()
			continue
		}
		ts.next()
		val := unescapeAuditString(pt.Value)
		switch strings.ToLower(pt.Key) {
		case "description":
			report.Description = val
		case "info":
			report.Info = val
		case "solution":
			report.Solution = val
		case "reference":
			report.Reference = val
		case "see_also":
			report.SeeAlso = val
		case "show_output":
			report.ShowOutput = strings.EqualFold(val, "YES")
		}
	}
	ts.expect(tokCloseReport)
	return report
}

func setCustomItemField(item *CustomItem, key, value string) {
	switch strings.ToLower(key) {
	case "type":
		item.Type = strings.TrimSpace(value)
	case "description":
		item.Description = value
	case "info":
		item.Info = value
	case "solution":
		item.Solution = value
	case "reference":
		item.Reference = value
	case "see_also":
		item.SeeAlso = value
	case "cmd":
		item.Cmd = value
	case "expect":
		item.Expect = value
	case "file":
		item.File = value
	case "regex":
		item.Regex = value
	case "value_type":
		item.ValueType = strings.TrimSpace(value)
	case "value_data":
		item.ValueData = value
	case "reg_key":
		item.RegKey = value
	case "reg_item":
		item.RegItem = value
	case "reg_option":
		item.RegOption = strings.TrimSpace(value)
	case "check_type":
		item.CheckTypeField = strings.TrimSpace(value)
	case "right_type":
		item.RightType = strings.TrimSpace(value)
	case "wmi_namespace":
		item.WMINamespace = value
	case "wmi_request":
		item.WMIRequest = value
	case "wmi_attribute":
		item.WMIAttribute = value
	case "wmi_key":
		item.WMIKey = value
	case "audit_policy_subcategory":
		item.AuditPolicySubcategory = value
	case "lockout_policy":
		item.LockoutPolicy = value
	case "password_policy":
		item.PasswordPolicy = value
	case "banner_type":
		item.BannerType = value
	default:
		item.Extra[key] = value
	}
}

// unescapeAuditString handles common escape sequences in .audit string values.
func unescapeAuditString(s string) string {
	// The audit format uses escape sequences within double-quoted values:
	// \" -> "   (escaped double quote)
	// \' -> '   (escaped single quote)
	// \\ -> \   (escaped backslash)
	// Process character by character to handle sequences properly.
	var result strings.Builder
	result.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\':
				result.WriteByte('\\')
				i += 2
			case '"':
				result.WriteByte('"')
				i += 2
			case '\'':
				result.WriteByte('\'')
				i += 2
			default:
				// Keep other escape sequences as-is (e.g., \n, \t, \s for regex)
				result.WriteByte(s[i])
				i++
			}
		} else {
			result.WriteByte(s[i])
			i++
		}
	}
	return result.String()
}
