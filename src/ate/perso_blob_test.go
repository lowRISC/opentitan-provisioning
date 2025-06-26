// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
package ate

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// Test data mirroring ate_perso_blob_test.cc
var (
	testDeviceID = &DeviceIDBytes{
		Raw: [kDeviceIDSize]byte{
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
	}
	testSignature = &EndorseCertSignature{
		Raw: [kWasHmacSignatureSize]byte{
			0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
	}
	testTbsCert = EndorseCertRequest{
		KeyLabel: "testkey1",
		Tbs:      bytes.Repeat([]byte{0x44}, 128),
	}
	testCert = EndorseCertResponse{
		KeyLabel: "testkey1",
		Cert:     bytes.Repeat([]byte{0x33}, 128),
	}
)

func TestUnpackPersoBlobSuccess(t *testing.T) {
	testPersoBlob := &PersoBlob{
		DeviceID:     testDeviceID,
		Signature:    testSignature,
		X509TbsCerts: []EndorseCertRequest{testTbsCert},
		X509Certs:    []EndorseCertResponse{testCert},
	}
	blobBytes, err := BuildPersoBlob(testPersoBlob)
	if err != nil {
		t.Fatalf("BuildPersoBlob() failed: %v", err)
	}

	unpacked, err := UnpackPersoBlob(blobBytes)
	if err != nil {
		t.Fatalf("UnpackPersoBlob() failed: %v", err)
	}

	if diff := cmp.Diff(testDeviceID, unpacked.DeviceID); diff != "" {
		t.Errorf("Unpacked DeviceID mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(testSignature, unpacked.Signature); diff != "" {
		t.Errorf("Unpacked Signature mismatch (-want +got):\n%s", diff)
	}

	if got, want := len(unpacked.X509TbsCerts), 1; got != want {
		t.Fatalf("got %d TBS certs, want %d", got, want)
	}
	if diff := cmp.Diff(testTbsCert, unpacked.X509TbsCerts[0]); diff != "" {
		t.Errorf("Unpacked TBS Cert mismatch (-want +got):\n%s", diff)
	}

	if got, want := len(unpacked.X509Certs), 1; got != want {
		t.Fatalf("got %d X509 certs, want %d", got, want)
	}
	if diff := cmp.Diff(testCert, unpacked.X509Certs[0]); diff != "" {
		t.Errorf("Unpacked X509 Cert mismatch (-want +got):\n%s", diff)
	}
	if got, want := len(unpacked.Seeds), 0; got != want {
		t.Errorf("got %d seeds, want %d", got, want)
	}
}

func TestUnpackPersoBlobErrors(t *testing.T) {
	testCases := []struct {
		name      string
		blob      []byte
		expectErr string
	}{
		{
			name:      "nil blob",
			blob:      nil,
			expectErr: "invalid personalization blob: empty",
		},
		{
			name:      "empty blob",
			blob:      []byte{},
			expectErr: "invalid personalization blob: empty",
		},
		{
			name:      "blob too large",
			blob:      make([]byte, kPersoBlobMaxSize+1),
			expectErr: "blob size 8193 exceeds max 8192",
		},
		{
			name:      "incomplete header",
			blob:      []byte{0x01},
			expectErr: "remaining buffer too small for object header",
		},
		{
			name: "object size exceeds buffer",
			// Header says size is 10, but we only have 2 bytes
			blob:      []byte{0x00, 0x0a},
			expectErr: "object size 10 exceeds remaining buffer 2",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UnpackPersoBlob(tc.blob)
			if err == nil {
				t.Errorf("UnpackPersoBlob() succeeded, want error containing %q", tc.expectErr)
			} else if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("UnpackPersoBlob() returned error %q, want error containing %q", err, tc.expectErr)
			}
		})
	}
}
