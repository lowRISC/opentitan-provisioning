// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package grpconn

import (
	"crypto/tls"
	"testing"
)

func TestApplyMLKEMConfig(t *testing.T) {
	tests := []struct {
		name           string
		enableMLKEM    bool
		expectMinVer   uint16
		expectCurve    bool
	}{
		{
			name:           "Disabled",
			enableMLKEM:    false,
			expectMinVer:   0, // Default 0 means allow lower versions (implementation dependent, usually 1.0 or 1.2)
			expectCurve:    false,
		},
		{
			name:           "Enabled",
			enableMLKEM:    true,
			expectMinVer:   tls.VersionTLS13,
			expectCurve:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{EnableMLKEMTLS: tc.enableMLKEM}
			tlsConfig := &tls.Config{}
			
			cfg.applyMLKEMConfig(tlsConfig)

			if tc.enableMLKEM {
				if tlsConfig.MinVersion != tc.expectMinVer {
					t.Errorf("Expected MinVersion %v, got %v", tc.expectMinVer, tlsConfig.MinVersion)
				}

				found := false
				for _, curve := range tlsConfig.CurvePreferences {
					if curve == tls.X25519MLKEM768 {
						found = true
						break
					}
				}
				if !tc.expectCurve {
					t.Errorf("Expected MLKEM curve to be present")
				} else if !found {
					t.Errorf("Expected MLKEM curve to be present")
				}
			} else {
				// When disabled, we expect no changes to the default (empty) tlsConfig
				if tlsConfig.MinVersion != 0 {
					t.Errorf("Expected MinVersion 0, got %v", tlsConfig.MinVersion)
				}
				if len(tlsConfig.CurvePreferences) > 0 {
					t.Errorf("Expected no CurvePreferences, got %v", tlsConfig.CurvePreferences)
				}
			}
		})
	}
}
