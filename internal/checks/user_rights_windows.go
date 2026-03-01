//go:build windows

package checks

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"host-config-review-scanner/internal/parser"
	"golang.org/x/sys/windows"
)

// UserRightsChecker handles USER_RIGHTS_POLICY type checks on Windows.
type UserRightsChecker struct{}

var (
	modadvapi32          = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy    = modadvapi32.NewProc("LsaOpenPolicy")
	procLsaClose         = modadvapi32.NewProc("LsaClose")
	procLsaEnumAcctsRight = modadvapi32.NewProc("LsaEnumerateAccountsWithUserRight")
	procLsaFreeMemory    = modadvapi32.NewProc("LsaFreeMemory")
)

// LSA_UNICODE_STRING for interop with Windows LSA APIs.
type lsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// LSA_OBJECT_ATTRIBUTES for LsaOpenPolicy
type lsaObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// LSA_ENUMERATION_INFORMATION
type lsaEnumerationInformation struct {
	Sid *windows.SID
}

func (u *UserRightsChecker) Execute(item parser.CustomItem) Result {
	if item.RightType == "" {
		return Result{Status: StatusError, Output: "right_type not specified"}
	}

	// Get accounts that hold the specified right
	accounts, err := getAccountsWithRight(item.RightType)
	if err != nil {
		return Result{
			Status: StatusError,
			Output: fmt.Sprintf("failed to enumerate accounts for %s: %v", item.RightType, err),
		}
	}

	// Parse expected value_data
	expectedData := strings.TrimSpace(item.ValueData)

	// Empty value_data means no accounts should hold this right
	if expectedData == "" || expectedData == "\"\"" {
		if len(accounts) == 0 {
			return Result{
				Status: StatusPass,
				Output: fmt.Sprintf("%s: no accounts assigned (expected empty)", item.RightType),
			}
		}
		return Result{
			Status: StatusFail,
			Output: fmt.Sprintf("%s: found accounts %v (expected none)", item.RightType, accounts),
		}
	}

	// Check for AND (&&) or OR (||)
	if strings.Contains(expectedData, "&&") {
		return checkUserRightsAnd(item.RightType, accounts, expectedData)
	}
	if strings.Contains(expectedData, "||") {
		return checkUserRightsOr(item.RightType, accounts, expectedData)
	}

	// Single value — exact match of account list
	expected := strings.Trim(expectedData, "\"")
	expectedAccounts := []string{expected}
	return matchAccountList(item.RightType, accounts, expectedAccounts, false)
}

func checkUserRightsAnd(rightType string, actual []string, valueData string) Result {
	required := parseAndValues(valueData)
	return matchAccountList(rightType, actual, required, false)
}

func checkUserRightsOr(rightType string, actual []string, valueData string) Result {
	alternatives := parseOrValues(valueData)
	// OR: at least one expected set must match
	for _, alt := range alternatives {
		altAccounts := []string{strings.TrimSpace(alt)}
		res := matchAccountList(rightType, actual, altAccounts, true)
		if res.Status == StatusPass {
			return res
		}
	}
	return Result{
		Status: StatusFail,
		Output: fmt.Sprintf("%s: actual accounts %v do not match any of: %s", rightType, actual, valueData),
	}
}

func matchAccountList(rightType string, actual, expected []string, anyMatch bool) Result {
	actualLower := make(map[string]bool)
	for _, a := range actual {
		actualLower[strings.ToLower(a)] = true
	}

	allFound := true
	for _, exp := range expected {
		exp = strings.TrimSpace(exp)
		if exp == "" {
			continue
		}
		if !actualLower[strings.ToLower(exp)] {
			allFound = false
			break
		}
	}

	if allFound {
		return Result{
			Status: StatusPass,
			Output: fmt.Sprintf("%s: accounts %v match expected %v", rightType, actual, expected),
		}
	}

	return Result{
		Status: StatusFail,
		Output: fmt.Sprintf("%s: accounts %v do not match expected %v", rightType, actual, expected),
	}
}

func getAccountsWithRight(rightName string) ([]string, error) {
	// Open LSA policy
	var policyHandle uintptr
	var objAttrs lsaObjectAttributes
	objAttrs.Length = uint32(unsafe.Sizeof(objAttrs))

	ret, _, _ := procLsaOpenPolicy.Call(
		0, // local system
		uintptr(unsafe.Pointer(&objAttrs)),
		0x00000800, // POLICY_LOOKUP_NAMES
		uintptr(unsafe.Pointer(&policyHandle)),
	)
	if ntStatus := ntStatusToError(ret); ntStatus != nil {
		return nil, fmt.Errorf("LsaOpenPolicy: %v", ntStatus)
	}
	defer procLsaClose.Call(policyHandle)

	// Convert right name to LSA_UNICODE_STRING
	rightUTF16, err := syscall.UTF16PtrFromString(rightName)
	if err != nil {
		return nil, err
	}
	rightStr := lsaUnicodeString{
		Length:        uint16(len(rightName) * 2),
		MaximumLength: uint16((len(rightName) + 1) * 2),
		Buffer:        rightUTF16,
	}

	// Enumerate accounts
	var enumBuffer unsafe.Pointer
	var countReturned uint32

	ret, _, _ = procLsaEnumAcctsRight.Call(
		policyHandle,
		uintptr(unsafe.Pointer(&rightStr)),
		uintptr(unsafe.Pointer(&enumBuffer)),
		uintptr(unsafe.Pointer(&countReturned)),
	)

	if ret == 0xC0000034 { // STATUS_OBJECT_NAME_NOT_FOUND — no accounts
		return []string{}, nil
	}
	if ret == 0xC00000BB { // STATUS_NO_MORE_ENTRIES
		return []string{}, nil
	}
	if ntStatus := ntStatusToError(ret); ntStatus != nil {
		return nil, fmt.Errorf("LsaEnumerateAccountsWithUserRight: %v (0x%X)", ntStatus, ret)
	}
	defer procLsaFreeMemory.Call(uintptr(enumBuffer))

	// Parse the results
	var accounts []string
	sids := unsafe.Slice((*lsaEnumerationInformation)(enumBuffer), countReturned)
	for _, info := range sids {
		if info.Sid != nil {
			name, domain, err := lookupSID(info.Sid)
			if err != nil {
				accounts = append(accounts, info.Sid.String())
			} else {
				if domain != "" {
					accounts = append(accounts, domain+"\\"+name)
				} else {
					accounts = append(accounts, name)
				}
			}
		}
	}

	return accounts, nil
}

func lookupSID(sid *windows.SID) (name, domain string, err error) {
	var nameLen, domLen uint32 = 128, 128
	var accType uint32
	nameBuf := make([]uint16, nameLen)
	domBuf := make([]uint16, domLen)

	err = windows.LookupAccountSid(
		nil,
		sid,
		&nameBuf[0],
		&nameLen,
		&domBuf[0],
		&domLen,
		&accType,
	)
	if err != nil {
		return "", "", err
	}

	return syscall.UTF16ToString(nameBuf[:nameLen]), syscall.UTF16ToString(domBuf[:domLen]), nil
}

func ntStatusToError(ntStatus uintptr) error {
	if ntStatus == 0 {
		return nil
	}
	return fmt.Errorf("NTSTATUS 0x%X", ntStatus)
}
