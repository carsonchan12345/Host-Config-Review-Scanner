package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Metadata extraction tests ---

func TestExtractMetadata_Basic(t *testing.T) {
	lines := []string{
		"#<ui_metadata>",
		"#<display_name>Test Audit</display_name>",
		"#<spec>",
		"#  <type>CIS</type>",
		"#  <name>Test OS</name>",
		"#  <profile>L1</profile>",
		"#  <version>1.0.0</version>",
		"#  <link>https://example.com</link>",
		"#</spec>",
		"#<labels>agent,test</labels>",
		"#<variables>",
		"#  <variable>",
		"#    <name>MY_VAR</name>",
		"#    <default>hello</default>",
		"#    <description>Test var</description>",
		"#    <info>Test info</info>",
		"#    <value_type>STRING</value_type>",
		"#  </variable>",
		"#</variables>",
		"#</ui_metadata>",
	}

	meta, vars := extractMetadata(lines)

	if meta.DisplayName != "Test Audit" {
		t.Errorf("DisplayName = %q, want %q", meta.DisplayName, "Test Audit")
	}
	if meta.SpecType != "CIS" {
		t.Errorf("SpecType = %q, want %q", meta.SpecType, "CIS")
	}
	if meta.SpecName != "Test OS" {
		t.Errorf("SpecName = %q, want %q", meta.SpecName, "Test OS")
	}
	if meta.SpecProfile != "L1" {
		t.Errorf("SpecProfile = %q, want %q", meta.SpecProfile, "L1")
	}
	if meta.SpecVersion != "1.0.0" {
		t.Errorf("SpecVersion = %q, want %q", meta.SpecVersion, "1.0.0")
	}
	if meta.Labels != "agent,test" {
		t.Errorf("Labels = %q, want %q", meta.Labels, "agent,test")
	}
	if v, ok := vars["MY_VAR"]; !ok || v != "hello" {
		t.Errorf("vars[MY_VAR] = %q, want %q", v, "hello")
	}
}

func TestExtractMetadata_Empty(t *testing.T) {
	lines := []string{"# just a comment", "# another comment"}
	meta, vars := extractMetadata(lines)
	if meta.DisplayName != "" {
		t.Errorf("expected empty DisplayName, got %q", meta.DisplayName)
	}
	if len(vars) != 0 {
		t.Errorf("expected no variables, got %d", len(vars))
	}
}

// --- Tag attribute parsing tests ---

func TestParseTagAttrs(t *testing.T) {
	tests := []struct {
		tag  string
		want map[string]string
	}{
		{
			`<check_type:"Unix">`,
			map[string]string{"check_type": "Unix"},
		},
		{
			`<check_type:"Windows" version:"2">`,
			map[string]string{"check_type": "Windows", "version": "2"},
		},
		{
			`<condition type:"AND">`,
			map[string]string{"type": "AND"},
		},
		{
			`<condition auto:"FAILED" type:"AND">`,
			map[string]string{"auto": "FAILED", "type": "AND"},
		},
		{
			`<report type:"PASSED">`,
			map[string]string{"type": "PASSED"},
		},
	}

	for _, tt := range tests {
		attrs := parseTagAttrs(tt.tag)
		for k, v := range tt.want {
			if attrs[k] != v {
				t.Errorf("parseTagAttrs(%q)[%q] = %q, want %q", tt.tag, k, attrs[k], v)
			}
		}
	}
}

// --- Quote finding tests ---

func TestFindUnescapedQuote(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{`hello"`, 5},
		{`hello`, -1},
		{`he\"llo"`, 7},
		{`he\\"llo`, 4},   // \\ then " → the " is unescaped
		{`he\\\"llo"`, 9}, // \\\" → escaped quote, then "llo" has unescaped at 9
	}

	for _, tt := range tests {
		got := findUnescapedQuote(tt.input)
		if got != tt.want {
			t.Errorf("findUnescapedQuote(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

// --- Key-value separator tests ---

func TestFindKVSeparator(t *testing.T) {
	tests := []struct {
		line string
		want int
	}{
		{"type        : CMD_EXEC", 12},
		{"description : \"some text\"", 12},
		{"cmd         : \"#!/bin/bash\"", 12},
		{"no separator here", -1},
		{"reg_option  : CAN_NOT_BE_NULL", 12},
	}

	for _, tt := range tests {
		got := findKVSeparator(tt.line)
		if tt.want >= 0 && got < 0 {
			t.Errorf("findKVSeparator(%q) = %d, want >= 0", tt.line, got)
		}
		if tt.want < 0 && got >= 0 {
			t.Errorf("findKVSeparator(%q) = %d, want < 0", tt.line, got)
		}
	}
}

// --- Full parse integration tests ---

func TestParse_SimpleUnix(t *testing.T) {
	content := `#<ui_metadata>
#<display_name>Test Unix</display_name>
#<spec>
#  <type>CIS</type>
#  <name>Test</name>
#  <profile>L1</profile>
#  <version>1.0</version>
#  <link>https://example.com</link>
#</spec>
#<variables>
#  <variable>
#    <name>MYVAR</name>
#    <default>testval</default>
#    <description>d</description>
#    <info>i</info>
#    <value_type>STRING</value_type>
#  </variable>
#</variables>
#</ui_metadata>

<check_type:"Unix">

<custom_item>
  type        : CMD_EXEC
  description : "Test command check"
  cmd         : "echo hello"
  expect      : "hello"
</custom_item>

<custom_item>
  type        : FILE_CONTENT_CHECK
  description : "Test file check"
  file        : "/etc/hostname"
  regex       : ".*"
  expect      : ".*"
</custom_item>

</check_type>
`
	tmpFile := writeTempFile(t, content)
	audit, err := Parse(tmpFile)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if audit.CheckType != "Unix" {
		t.Errorf("CheckType = %q, want %q", audit.CheckType, "Unix")
	}
	if audit.Metadata.DisplayName != "Test Unix" {
		t.Errorf("DisplayName = %q, want %q", audit.Metadata.DisplayName, "Test Unix")
	}
	if v := audit.Variables["MYVAR"]; v != "testval" {
		t.Errorf("MYVAR = %q, want %q", v, "testval")
	}
	if len(audit.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(audit.Nodes))
	}

	// First node: CMD_EXEC
	item1, ok := audit.Nodes[0].(*CustomItem)
	if !ok {
		t.Fatalf("node 0 is %T, want *CustomItem", audit.Nodes[0])
	}
	if item1.Type != "CMD_EXEC" {
		t.Errorf("node 0 type = %q, want CMD_EXEC", item1.Type)
	}
	if item1.Cmd != "echo hello" {
		t.Errorf("node 0 cmd = %q, want %q", item1.Cmd, "echo hello")
	}

	// Second node: FILE_CONTENT_CHECK
	item2, ok := audit.Nodes[1].(*CustomItem)
	if !ok {
		t.Fatalf("node 1 is %T, want *CustomItem", audit.Nodes[1])
	}
	if item2.Type != "FILE_CONTENT_CHECK" {
		t.Errorf("node 1 type = %q, want FILE_CONTENT_CHECK", item2.Type)
	}
}

func TestParse_SimpleWindows(t *testing.T) {
	content := `
<check_type:"Windows" version:"2">
<group_policy:"Test Policy">

<custom_item>
  type        : REGISTRY_SETTING
  description : "Test registry check"
  value_type  : POLICY_DWORD
  value_data  : "1"
  reg_key     : "HKLM\Software\Test"
  reg_item    : "Value1"
  reg_option  : CAN_NOT_BE_NULL
</custom_item>

<custom_item>
  type        : USER_RIGHTS_POLICY
  description : "Test user rights"
  value_type  : USER_RIGHT
  value_data  : ""
  right_type  : SeTrustedCredManAccessPrivilege
</custom_item>

</group_policy>
</check_type>
`
	tmpFile := writeTempFile(t, content)
	audit, err := Parse(tmpFile)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if audit.CheckType != "Windows" {
		t.Errorf("CheckType = %q, want %q", audit.CheckType, "Windows")
	}
	if audit.Version != "2" {
		t.Errorf("Version = %q, want %q", audit.Version, "2")
	}
	if audit.GroupPolicy != "Test Policy" {
		t.Errorf("GroupPolicy = %q, want %q", audit.GroupPolicy, "Test Policy")
	}
	if len(audit.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(audit.Nodes))
	}

	reg, ok := audit.Nodes[0].(*CustomItem)
	if !ok {
		t.Fatalf("node 0 is %T, want *CustomItem", audit.Nodes[0])
	}
	if reg.Type != "REGISTRY_SETTING" {
		t.Errorf("node 0 type = %q, want REGISTRY_SETTING", reg.Type)
	}
	if reg.RegKey != `HKLM\Software\Test` {
		t.Errorf("node 0 reg_key = %q", reg.RegKey)
	}
	if reg.RegOption != "CAN_NOT_BE_NULL" {
		t.Errorf("node 0 reg_option = %q, want CAN_NOT_BE_NULL", reg.RegOption)
	}

	ur, ok := audit.Nodes[1].(*CustomItem)
	if !ok {
		t.Fatalf("node 1 is %T, want *CustomItem", audit.Nodes[1])
	}
	if ur.Type != "USER_RIGHTS_POLICY" {
		t.Errorf("node 1 type = %q, want USER_RIGHTS_POLICY", ur.Type)
	}
	if ur.RightType != "SeTrustedCredManAccessPrivilege" {
		t.Errorf("node 1 right_type = %q", ur.RightType)
	}
}

func TestParse_IfCondition(t *testing.T) {
	content := `
<check_type:"Unix">

<if>
  <condition type:"AND">
    <custom_item>
      type        : CMD_EXEC
      description : "Guard check"
      cmd         : "echo yes"
      expect      : "yes"
    </custom_item>
  </condition>

  <then>
    <custom_item>
      type        : CMD_EXEC
      description : "Guarded check"
      cmd         : "echo guarded"
      expect      : "guarded"
    </custom_item>
  </then>

  <else>
    <report type:"WARNING">
      description : "Not applicable"
      info        : "Guard failed"
    </report>
  </else>
</if>

</check_type>
`
	tmpFile := writeTempFile(t, content)
	audit, err := Parse(tmpFile)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(audit.Nodes) != 1 {
		t.Fatalf("expected 1 node (if block), got %d", len(audit.Nodes))
	}

	ifBlock, ok := audit.Nodes[0].(*IfBlock)
	if !ok {
		t.Fatalf("node 0 is %T, want *IfBlock", audit.Nodes[0])
	}

	if ifBlock.Condition.Type != "AND" {
		t.Errorf("condition type = %q, want AND", ifBlock.Condition.Type)
	}
	if len(ifBlock.Condition.Items) != 1 {
		t.Fatalf("expected 1 condition item, got %d", len(ifBlock.Condition.Items))
	}
	if ifBlock.Condition.Items[0].Description != "Guard check" {
		t.Errorf("condition item desc = %q", ifBlock.Condition.Items[0].Description)
	}
	if len(ifBlock.Then) != 1 {
		t.Fatalf("expected 1 then node, got %d", len(ifBlock.Then))
	}
	if len(ifBlock.Else) != 1 {
		t.Fatalf("expected 1 else node, got %d", len(ifBlock.Else))
	}

	report, ok := ifBlock.Else[0].(*ReportItem)
	if !ok {
		t.Fatalf("else node is %T, want *ReportItem", ifBlock.Else[0])
	}
	if report.Status != "WARNING" {
		t.Errorf("report status = %q, want WARNING", report.Status)
	}
}

func TestParse_AutoFailed(t *testing.T) {
	content := `
<check_type:"Unix">

<if>
  <condition auto:"FAILED" type:"AND">
    <custom_item>
      type        : CMD_EXEC
      description : "Sub-check 1"
      cmd         : "echo pass"
      expect      : "pass"
    </custom_item>
    <custom_item>
      type        : CMD_EXEC
      description : "Sub-check 2"
      cmd         : "echo pass"
      expect      : "pass"
    </custom_item>
  </condition>

  <then>
    <report type:"PASSED">
      description : "All sub-checks passed"
    </report>
  </then>
</if>

</check_type>
`
	tmpFile := writeTempFile(t, content)
	audit, err := Parse(tmpFile)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(audit.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(audit.Nodes))
	}

	ifBlock, ok := audit.Nodes[0].(*IfBlock)
	if !ok {
		t.Fatalf("node is %T, want *IfBlock", audit.Nodes[0])
	}

	if !ifBlock.Condition.AutoFailed {
		t.Error("expected AutoFailed = true")
	}
	if len(ifBlock.Condition.Items) != 2 {
		t.Errorf("expected 2 condition items, got %d", len(ifBlock.Condition.Items))
	}
}

func TestParse_NestedIf(t *testing.T) {
	content := `
<check_type:"Unix">

<if>
  <condition type:"AND">
    <custom_item>
      type        : CMD_EXEC
      description : "Outer guard"
      cmd         : "echo yes"
      expect      : "yes"
    </custom_item>
  </condition>

  <then>
    <custom_item>
      type        : CMD_EXEC
      description : "Outer then check"
      cmd         : "echo ok"
      expect      : "ok"
    </custom_item>
  </then>

  <else>
    <if>
      <condition auto:"FAILED" type:"AND">
        <custom_item>
          type        : CMD_EXEC
          description : "Inner condition"
          cmd         : "echo inner"
          expect      : "inner"
        </custom_item>
      </condition>

      <then>
        <report type:"PASSED">
          description : "Inner passed"
        </report>
      </then>
    </if>
  </else>
</if>

</check_type>
`
	tmpFile := writeTempFile(t, content)
	audit, err := Parse(tmpFile)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	ifBlock := audit.Nodes[0].(*IfBlock)
	if len(ifBlock.Else) != 1 {
		t.Fatalf("expected 1 else node, got %d", len(ifBlock.Else))
	}

	innerIf, ok := ifBlock.Else[0].(*IfBlock)
	if !ok {
		t.Fatalf("else[0] is %T, want *IfBlock", ifBlock.Else[0])
	}
	if !innerIf.Condition.AutoFailed {
		t.Error("inner condition should have AutoFailed = true")
	}
}

func TestParse_VariableSubstitution(t *testing.T) {
	content := `#<ui_metadata>
#<display_name>Test</display_name>
#<spec>
#  <type>CIS</type>
#  <name>Test</name>
#  <profile>L1</profile>
#  <version>1.0</version>
#  <link>https://example.com</link>
#</spec>
#<variables>
#  <variable>
#    <name>PLATFORM_VERSION</name>
#    <default>^13</default>
#    <description>Version</description>
#    <info>Version</info>
#    <value_type>STRING</value_type>
#  </variable>
#</variables>
#</ui_metadata>

<check_type:"Unix">

<custom_item>
  type        : FILE_CONTENT_CHECK
  description : "Version check"
  file        : "/etc/version"
  regex       : "@PLATFORM_VERSION@"
  expect      : "@PLATFORM_VERSION@"
</custom_item>

</check_type>
`
	tmpFile := writeTempFile(t, content)
	audit, err := Parse(tmpFile)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	item := audit.Nodes[0].(*CustomItem)
	// Variable @PLATFORM_VERSION@ should be substituted with ^13
	if !strings.Contains(item.Regex, "^13") {
		t.Errorf("variable not substituted in regex: %q", item.Regex)
	}
	if !strings.Contains(item.Expect, "^13") {
		t.Errorf("variable not substituted in expect: %q", item.Expect)
	}
}

func TestParse_WMIPolicy(t *testing.T) {
	content := `
<check_type:"Windows" version:"2">
<group_policy:"Test">

<custom_item>
  type          : WMI_POLICY
  description   : "Check domain role"
  value_type    : POLICY_DWORD
  value_data    : 2 || 3
  wmi_namespace : "root/CIMV2"
  wmi_request   : "select DomainRole from Win32_ComputerSystem"
  wmi_attribute : "DomainRole"
  wmi_key       : "DomainRole"
</custom_item>

</group_policy>
</check_type>
`
	tmpFile := writeTempFile(t, content)
	audit, err := Parse(tmpFile)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(audit.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(audit.Nodes))
	}

	item := audit.Nodes[0].(*CustomItem)
	if item.Type != "WMI_POLICY" {
		t.Errorf("type = %q, want WMI_POLICY", item.Type)
	}
	if item.WMINamespace != "root/CIMV2" {
		t.Errorf("wmi_namespace = %q", item.WMINamespace)
	}
	if item.WMIRequest != "select DomainRole from Win32_ComputerSystem" {
		t.Errorf("wmi_request = %q", item.WMIRequest)
	}
	if item.ValueData != "2 || 3" {
		t.Errorf("value_data = %q, want %q", item.ValueData, "2 || 3")
	}
}

func TestParse_AuditPolicy(t *testing.T) {
	content := `
<check_type:"Windows" version:"2">
<group_policy:"Test">

<custom_item>
  type                     : AUDIT_POLICY_SUBCATEGORY
  description              : "Audit Account Lockout"
  value_type               : AUDIT_SET
  value_data               : "Failure"
  audit_policy_subcategory : "Account Lockout"
</custom_item>

</group_policy>
</check_type>
`
	tmpFile := writeTempFile(t, content)
	audit, err := Parse(tmpFile)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	item := audit.Nodes[0].(*CustomItem)
	if item.Type != "AUDIT_POLICY_SUBCATEGORY" {
		t.Errorf("type = %q, want AUDIT_POLICY_SUBCATEGORY", item.Type)
	}
	if item.AuditPolicySubcategory != "Account Lockout" {
		t.Errorf("subcategory = %q, want %q", item.AuditPolicySubcategory, "Account Lockout")
	}
	if item.ValueData != "Failure" {
		t.Errorf("value_data = %q, want %q", item.ValueData, "Failure")
	}
}

func TestParse_MultiLineCmd(t *testing.T) {
	content := `
<check_type:"Unix">

<custom_item>
  type        : CMD_EXEC
  description : "Multi-line script"
  cmd         : "#!/bin/bash
echo line1
echo line2
echo done"
  expect      : "done"
</custom_item>

</check_type>
`
	tmpFile := writeTempFile(t, content)
	audit, err := Parse(tmpFile)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	item := audit.Nodes[0].(*CustomItem)
	if !strings.Contains(item.Cmd, "echo line1") {
		t.Errorf("multi-line cmd missing content: %q", item.Cmd)
	}
	if !strings.Contains(item.Cmd, "echo done") {
		t.Errorf("multi-line cmd missing tail: %q", item.Cmd)
	}
}

func TestParse_ReportItem(t *testing.T) {
	content := `
<check_type:"Unix">

<report type:"PASSED">
  description : "Benchmark applies"
  info        : "The target matches"
  see_also    : "https://example.com"
  show_output : YES
</report>

</check_type>
`
	tmpFile := writeTempFile(t, content)
	audit, err := Parse(tmpFile)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(audit.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(audit.Nodes))
	}

	report, ok := audit.Nodes[0].(*ReportItem)
	if !ok {
		t.Fatalf("node is %T, want *ReportItem", audit.Nodes[0])
	}
	if report.Status != "PASSED" {
		t.Errorf("status = %q, want PASSED", report.Status)
	}
	if report.Description != "Benchmark applies" {
		t.Errorf("description = %q", report.Description)
	}
	if !report.ShowOutput {
		t.Error("expected ShowOutput = true")
	}
}

// --- Helper ---

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.audit")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	return path
}
