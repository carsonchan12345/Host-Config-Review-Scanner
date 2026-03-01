//go:build windows

package checks

import (
	"fmt"
	"strings"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"

	"host-config-review-scanner/internal/parser"
)

// WMIChecker handles WMI_POLICY type checks on Windows.
type WMIChecker struct{}

func (w *WMIChecker) Execute(item parser.CustomItem) Result {
	if item.WMIRequest == "" {
		return Result{Status: StatusError, Output: "wmi_request not specified"}
	}

	namespace := item.WMINamespace
	if namespace == "" {
		namespace = "root/CIMV2"
	}
	// Windows WMI namespace uses backslashes
	namespace = strings.ReplaceAll(namespace, "/", `\`)

	value, err := queryWMI(namespace, item.WMIRequest, item.WMIAttribute)
	if err != nil {
		return Result{
			Status: StatusError,
			Output: fmt.Sprintf("WMI query failed: %v", err),
		}
	}

	// Compare against expected value_data
	expected := parseOrValues(item.ValueData)
	for _, exp := range expected {
		if strings.EqualFold(strings.TrimSpace(exp), strings.TrimSpace(value)) {
			return Result{
				Status: StatusPass,
				Output: fmt.Sprintf("WMI %s = %s (expected: %s)", item.WMIAttribute, value, item.ValueData),
			}
		}
	}

	return Result{
		Status: StatusFail,
		Output: fmt.Sprintf("WMI %s = %s (expected: %s)", item.WMIAttribute, value, item.ValueData),
	}
}

func queryWMI(namespace, query, attribute string) (string, error) {
	// Initialize COM
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		// May already be initialized
		oleErr, ok := err.(*ole.OleError)
		if !ok || oleErr.Code() != 0x00000001 { // S_FALSE = already initialized
			// Try apartment threaded
			ole.CoUninitialize()
			if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
				oleErr2, ok := err.(*ole.OleError)
				if !ok || (oleErr2.Code() != 0x00000001 && oleErr2.Code() != 0) {
					return "", fmt.Errorf("CoInitializeEx: %v", err)
				}
			}
		}
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return "", fmt.Errorf("creating WbemLocator: %v", err)
	}
	defer unknown.Release()

	wmi, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return "", fmt.Errorf("QueryInterface: %v", err)
	}
	defer wmi.Release()

	// Connect to namespace
	serviceRaw, err := oleutil.CallMethod(wmi, "ConnectServer", ".", namespace)
	if err != nil {
		return "", fmt.Errorf("ConnectServer to %s: %v", namespace, err)
	}
	service := serviceRaw.ToIDispatch()
	defer service.Release()

	// Execute query
	resultRaw, err := oleutil.CallMethod(service, "ExecQuery", query)
	if err != nil {
		return "", fmt.Errorf("ExecQuery '%s': %v", query, err)
	}
	result := resultRaw.ToIDispatch()
	defer result.Release()

	// Get count
	countVar, err := oleutil.GetProperty(result, "Count")
	if err != nil {
		return "", fmt.Errorf("getting Count: %v", err)
	}
	count := int(countVar.Val)

	if count == 0 {
		return "", fmt.Errorf("WMI query returned no results")
	}

	// Get first item
	itemRaw, err := oleutil.CallMethod(result, "ItemIndex", 0)
	if err != nil {
		return "", fmt.Errorf("ItemIndex(0): %v", err)
	}
	wmiItem := itemRaw.ToIDispatch()
	defer wmiItem.Release()

	// Get the attribute value
	propVal, err := oleutil.GetProperty(wmiItem, attribute)
	if err != nil {
		return "", fmt.Errorf("getting property '%s': %v", attribute, err)
	}

	return fmt.Sprintf("%v", propVal.Value()), nil
}
