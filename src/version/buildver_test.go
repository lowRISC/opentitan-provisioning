// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package buildver_test implements unit tests for the buildver package.
package buildver_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/lowRISC/opentitan-provisioning/src/version/buildver"
)

func TestVersion(t *testing.T) {
	// Sanity check to make sure the Formatted version string contains non-empty
	// param values.
	matchRe := "Version:\\s.+?-.+?\\sHost:\\s.+?\\sUser:\\s.+?\\sTimestamp:\\s\\S+?"
	re, err := regexp.Compile(matchRe)
	if err != nil {
		t.Fatalf("Error compiling version regexp %q: %v", matchRe, err)
	}
	verStr := buildver.FormattedStr()
	fmt.Printf("version = %v\n", verStr)
	if !re.MatchString(verStr) {
		t.Fatalf("Error expected regexp: %q, got: %q", matchRe, verStr)
	}
}
