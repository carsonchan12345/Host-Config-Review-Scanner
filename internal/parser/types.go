package parser

// AuditFile represents a fully parsed .audit file.
type AuditFile struct {
	CheckType   string            // "Unix" or "Windows"
	Version     string            // e.g. "2" for Windows
	GroupPolicy string            // Windows only: group policy name
	Metadata    AuditMetadata     // parsed from #<ui_metadata>
	Variables   map[string]string // variable name -> default value
	Nodes       []Node            // top-level nodes (items, ifs, reports)
}

// AuditMetadata holds the display metadata parsed from #<ui_metadata>.
type AuditMetadata struct {
	DisplayName    string
	SpecType       string
	SpecName       string
	SpecProfile    string
	SpecVersion    string
	SpecLink       string
	Labels         string
	BenchmarkRefs  string
}

// Node is any element in the audit file's execution tree.
type Node interface {
	nodeType() string
}

// IfBlock represents a conditional <if> block.
type IfBlock struct {
	Condition Condition
	Then      []Node
	Else      []Node
}

func (i *IfBlock) nodeType() string { return "if" }

// Condition represents a <condition> element with AND/OR logic.
type Condition struct {
	Type       string // "AND" or "OR"
	AutoFailed bool   // if true, condition uses auto:"FAILED" semantics
	Items      []CustomItem
}

// CustomItem represents a <custom_item> check block.
type CustomItem struct {
	// Common fields
	Type        string // CMD_EXEC, FILE_CONTENT_CHECK, FILE_CONTENT_CHECK_NOT, REGISTRY_SETTING, etc.
	Description string
	Info        string
	Solution    string
	Reference   string
	SeeAlso     string

	// Linux: CMD_EXEC
	Cmd    string
	Expect string

	// Linux: FILE_CONTENT_CHECK / FILE_CONTENT_CHECK_NOT
	File  string
	Regex string
	// Expect is reused from above

	// Windows: common
	ValueType string // POLICY_DWORD, POLICY_TEXT, USER_RIGHT, AUDIT_SET
	ValueData string

	// Windows: REGISTRY_SETTING
	RegKey    string
	RegItem   string
	RegOption string
	CheckTypeField string // CHECK_REGEX, CHECK_GREATER_THAN, etc. (distinct from outer Type)

	// Windows: USER_RIGHTS_POLICY
	RightType string

	// Windows: WMI_POLICY
	WMINamespace string
	WMIRequest   string
	WMIAttribute string
	WMIKey       string

	// Windows: AUDIT_POLICY_SUBCATEGORY
	AuditPolicySubcategory string

	// Windows: LOCKOUT_POLICY
	LockoutPolicy string

	// Windows: PASSWORD_POLICY
	PasswordPolicy string

	// Windows: BANNER_CHECK
	BannerType string

	// Windows: ANONYMOUS_SID_SETTING
	// (uses ValueType + ValueData)

	// Additional / catch-all for unhandled fields
	Extra map[string]string
}

func (c *CustomItem) nodeType() string { return "custom_item" }

// ReportItem represents a <report type:"..."> block (static result, no check executed).
type ReportItem struct {
	Status      string // PASSED, FAILED, WARNING
	Description string
	Info        string
	Solution    string
	Reference   string
	SeeAlso     string
	ShowOutput  bool
}

func (r *ReportItem) nodeType() string { return "report" }
