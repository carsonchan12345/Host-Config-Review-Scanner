//go:build linux

package checks

import (
	"bufio"
	"os"
	"regexp"

	"host-config-review-scanner/internal/parser"
)

// FileContentChecker handles FILE_CONTENT_CHECK type (Linux).
type FileContentChecker struct{}

func (f *FileContentChecker) Execute(item parser.CustomItem) Result {
	return fileContentCheck(item, false)
}

// FileContentCheckNotChecker handles FILE_CONTENT_CHECK_NOT type (Linux).
type FileContentCheckNotChecker struct{}

func (f *FileContentCheckNotChecker) Execute(item parser.CustomItem) Result {
	return fileContentCheck(item, true)
}

func fileContentCheck(item parser.CustomItem, notCheck bool) Result {
	if item.File == "" {
		return Result{Status: StatusError, Output: "no file specified"}
	}

	file, err := os.Open(item.File)
	if err != nil {
		if os.IsNotExist(err) {
			if notCheck {
				return Result{Status: StatusPass, Output: "file does not exist: " + item.File}
			}
			return Result{Status: StatusFail, Output: "file does not exist: " + item.File}
		}
		return Result{Status: StatusError, Output: "error opening file: " + err.Error()}
	}
	defer file.Close()

	regexPattern := item.Regex
	if regexPattern == "" {
		regexPattern = item.Expect
	}

	regexRe, err := regexp.Compile(regexPattern)
	if err != nil {
		return Result{Status: StatusError, Output: "invalid regex pattern: " + err.Error()}
	}

	var expectRe *regexp.Regexp
	if item.Expect != "" && item.Expect != regexPattern {
		expectRe, err = regexp.Compile(item.Expect)
		if err != nil {
			return Result{Status: StatusError, Output: "invalid expect pattern: " + err.Error()}
		}
	} else {
		expectRe = regexRe
	}

	scanner := bufio.NewScanner(file)
	var foundMatch bool
	var matchedLine string

	for scanner.Scan() {
		line := scanner.Text()
		if regexRe.MatchString(line) {
			if expectRe.MatchString(line) {
				foundMatch = true
				matchedLine = line
				break
			}
		}
	}

	if notCheck {
		// FILE_CONTENT_CHECK_NOT: PASS if no match found
		if foundMatch {
			return Result{Status: StatusFail, Output: "found unwanted match: " + matchedLine}
		}
		return Result{Status: StatusPass, Output: "no match found (expected for NOT check)"}
	}

	// FILE_CONTENT_CHECK: PASS if match found
	if foundMatch {
		return Result{Status: StatusPass, Output: "matched: " + matchedLine}
	}
	return Result{Status: StatusFail, Output: "no matching line found in " + item.File}
}
