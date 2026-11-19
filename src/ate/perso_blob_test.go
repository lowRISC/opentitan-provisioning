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
	testLongNameCert = EndorseCertResponse{
		KeyLabel: "long_dice_cert_name_v1__",
		Cert:     bytes.Repeat([]byte{0x55}, 128),
	}
	testSeed = Seed{
		Type: PersoObjectTypeGenericSeed,
		Raw:  bytes.Repeat([]byte{0x77}, 64),
	}
)

func TestBuildPersoBlobV0WireFormat(t *testing.T) {
	testPersoBlob := &PersoBlob{
		X509Certs: []EndorseCertResponse{{
			KeyLabel: "UDS",
			Cert:     []byte{0x01, 0x02, 0x03, 0x04},
		}},
	}
	blobBytes, err := BuildPersoBlob(testPersoBlob)
	if err != nil {
		t.Fatalf("BuildPersoBlob() failed: %v", err)
	}
	want := []byte{
		// V0 Object Header (Type=1, Size=11 -> 0x100B)
		0x10, 0x0B,
		// V0 Cert Header (NameSize=3, Size=9 -> 0x3009)
		0x30, 0x09,
		// Name (3 bytes)
		'U', 'D', 'S',
		// Cert Body (4 bytes)
		0x01, 0x02, 0x03, 0x04,
	}
	if diff := cmp.Diff(want, blobBytes); diff != "" {
		t.Errorf("BuildPersoBlob V0 wire format mismatch (-want +got):\n%s", diff)
	}
}

func TestBuildPersoBlobV1WireFormat(t *testing.T) {
	testPersoBlob := &PersoBlob{
		X509Certs: []EndorseCertResponse{{
			KeyLabel: "0123456789abcdef",
			Cert:     []byte{0x01, 0x02, 0x03, 0x04},
		}},
	}
	blobBytes, err := BuildPersoBlob(testPersoBlob)
	if err != nil {
		t.Fatalf("BuildPersoBlob() failed: %v", err)
	}
	want := []byte{
		// Version Prefix (4 bytes)
		0xF0, 0x04, 0x00, 0x01,
		// V1 Object Header (Type=1, Size=28 -> 0x0100001C)
		0x01, 0x00, 0x00, 0x1C,
		// V1 Cert Header (NameSize=16, Size=24 -> 0x10000018)
		0x10, 0x00, 0x00, 0x18,
		// Name (16 bytes)
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
		// Cert Body (4 bytes)
		0x01, 0x02, 0x03, 0x04,
	}
	if diff := cmp.Diff(want, blobBytes); diff != "" {
		t.Errorf("BuildPersoBlob V1 wire format mismatch (-want +got):\n%s", diff)
	}
}

func TestUnpackPersoBlobSuccess(t *testing.T) {
	testPersoBlob := &PersoBlob{
		DeviceID:     testDeviceID,
		Signature:    testSignature,
		X509TbsCerts: []EndorseCertRequest{testTbsCert},
		X509Certs:    []EndorseCertResponse{testCert, testLongNameCert},
		Seeds:        []Seed{testSeed},
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

	if got, want := len(unpacked.X509Certs), 2; got != want {
		t.Fatalf("got %d X509 certs, want %d", got, want)
	}
	if diff := cmp.Diff(testCert, unpacked.X509Certs[0]); diff != "" {
		t.Errorf("Unpacked X509 Cert mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(testLongNameCert, unpacked.X509Certs[1]); diff != "" {
		t.Errorf("Unpacked X509 Long Name Cert mismatch (-want +got):\n%s", diff)
	}
	if got, want := len(unpacked.Seeds), 1; got != want {
		t.Fatalf("got %d seeds, want %d", got, want)
	}
	if diff := cmp.Diff(testSeed, unpacked.Seeds[0]); diff != "" {
		t.Errorf("Unpacked Seed mismatch (-want +got):\n%s", diff)
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
			expectErr: "exceeds max",
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
		{
			name: "V0 object size smaller than header size (DeviceId)",
			// Type=5 (DeviceId), Size=1 (< 2)
			blob:      []byte{0x50, 0x01},
			expectErr: "object size 1 is smaller than header size 2",
		},
		{
			name: "V0 object size smaller than header size (X509Cert)",
			// Type=1 (X509Cert), Size=1 (< 2)
			blob:      []byte{0x10, 0x01},
			expectErr: "object size 1 is smaller than header size 2",
		},
		{
			name: "V0 object size smaller than header size (DevSeed)",
			// Type=2 (DevSeed), Size=1 (< 2)
			blob:      []byte{0x20, 0x01},
			expectErr: "object size 1 is smaller than header size 2",
		},
		{
			name: "V1 object size smaller than header size (innerSize=0, DeviceId)",
			// V1 prefix + Type=5 (DeviceId), innerSize=0 -> objSize=4 (< 8)
			blob:      []byte{0xF0, 0x04, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00},
			expectErr: "object size 4 is smaller than header size 8",
		},
		{
			name: "V1 object size smaller than header size (innerSize=1, DevSeed)",
			// V1 prefix + Type=2 (DevSeed), innerSize=1 -> objSize=5 (< 8)
			blob:      []byte{0xF0, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x01},
			expectErr: "object size 5 is smaller than header size 8",
		},
		{
			name: "V1 object size smaller than header size (innerSize=2, WasTbsHmac)",
			// V1 prefix + Type=4 (WasTbsHmac), innerSize=2 -> objSize=6 (< 8)
			blob:      []byte{0xF0, 0x04, 0x00, 0x01, 0x04, 0x00, 0x00, 0x02},
			expectErr: "object size 6 is smaller than header size 8",
		},
		{
			name: "V1 object size smaller than header size (innerSize=3, X509Cert)",
			// V1 prefix + Type=1 (X509Cert), innerSize=3 -> objSize=7 (< 8)
			blob:      []byte{0xF0, 0x04, 0x00, 0x01, 0x01, 0x00, 0x00, 0x03},
			expectErr: "object size 7 is smaller than header size 8",
		},
		{
			name: "V0 X509Cert truncated cert header (0 payload bytes)",
			// Type=1 (X509Cert), Size=2 -> 0 bytes left for 2-byte V0 cert header
			blob:      []byte{0x10, 0x02},
			expectErr: "buffer too small for certificate header",
		},
		{
			name: "V0 X509Tbs truncated cert header (1 payload byte)",
			// Type=0 (X509Tbs), Size=3 -> 1 byte left for 2-byte V0 cert header
			blob:      []byte{0x00, 0x03, 0xAA},
			expectErr: "buffer too small for certificate header",
		},
		{
			name: "V0 CwtCert truncated cert header (1 payload byte)",
			// Type=3 (CwtCert), Size=3 -> 1 byte left for 2-byte V0 cert header
			blob:      []byte{0x30, 0x03, 0xAA},
			expectErr: "buffer too small for certificate header",
		},
		{
			name: "V1 X509Cert truncated cert header (0 payload bytes)",
			// V1 prefix + Type=1 (X509Cert), innerSize=4 -> objSize=8, 0 bytes left for 4-byte V1 cert header
			blob:      []byte{0xF0, 0x04, 0x00, 0x01, 0x01, 0x00, 0x00, 0x04},
			expectErr: "buffer too small for certificate header",
		},
		{
			name: "V1 X509Tbs truncated cert header (3 payload bytes)",
			// V1 prefix + Type=0 (X509Tbs), innerSize=7 -> objSize=11, 3 bytes left for 4-byte V1 cert header
			blob:      []byte{0xF0, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0xAA, 0xBB, 0xCC},
			expectErr: "buffer too small for certificate header",
		},
		{
			name: "V0 DeviceId payload too short",
			// Type=5 (DeviceId), Size=18 (2-byte header + 16-byte payload, expected 34)
			blob:      append([]byte{0x50, 0x12}, make([]byte, 16)...),
			expectErr: "invalid device ID object size: 18, expected: 34",
		},
		{
			name: "V0 DeviceId payload too long",
			// Type=5 (DeviceId), Size=35 (2-byte header + 33-byte payload, expected 34)
			blob:      append([]byte{0x50, 0x23}, make([]byte, 33)...),
			expectErr: "invalid device ID object size: 35, expected: 34",
		},
		{
			name: "V1 DeviceId payload too short",
			// V1 prefix + Type=5 (DeviceId), innerSize=20 (4-byte header + 16-byte payload) -> objSize=24, expected 40
			blob:      append([]byte{0xF0, 0x04, 0x00, 0x01, 0x05, 0x00, 0x00, 0x14}, make([]byte, 16)...),
			expectErr: "invalid device ID object size: 24, expected: 40",
		},
		{
			name: "V1 DeviceId payload too long",
			// V1 prefix + Type=5 (DeviceId), innerSize=37 (4-byte header + 33-byte payload) -> objSize=41, expected 40
			blob:      append([]byte{0xF0, 0x04, 0x00, 0x01, 0x05, 0x00, 0x00, 0x25}, make([]byte, 33)...),
			expectErr: "invalid device ID object size: 41, expected: 40",
		},
		{
			name: "V0 WasTbsHmac payload too short",
			// Type=4 (WasTbsHmac), Size=18 (2-byte header + 16-byte payload, expected 34)
			blob:      append([]byte{0x40, 0x12}, make([]byte, 16)...),
			expectErr: "invalid WAS TBS HMAC object size: 18, expected: 34",
		},
		{
			name: "V0 WasTbsHmac payload too long",
			// Type=4 (WasTbsHmac), Size=35 (2-byte header + 33-byte payload, expected 34)
			blob:      append([]byte{0x40, 0x23}, make([]byte, 33)...),
			expectErr: "invalid WAS TBS HMAC object size: 35, expected: 34",
		},
		{
			name: "V1 WasTbsHmac payload too short",
			// V1 prefix + Type=4 (WasTbsHmac), innerSize=20 (4-byte header + 16-byte payload) -> objSize=24, expected 40
			blob:      append([]byte{0xF0, 0x04, 0x00, 0x01, 0x04, 0x00, 0x00, 0x14}, make([]byte, 16)...),
			expectErr: "invalid WAS TBS HMAC object size: 24, expected: 40",
		},
		{
			name: "V1 WasTbsHmac payload too long",
			// V1 prefix + Type=4 (WasTbsHmac), innerSize=37 (4-byte header + 33-byte payload) -> objSize=41, expected 40
			blob:      append([]byte{0xF0, 0x04, 0x00, 0x01, 0x04, 0x00, 0x00, 0x25}, make([]byte, 33)...),
			expectErr: "invalid WAS TBS HMAC object size: 41, expected: 40",
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

func TestUnpackPersoBlobV1DeviceIDAndSignature(t *testing.T) {
	var blob bytes.Buffer
	// V1 DeviceId: prefix (4B) + V1 header (Type=5, innerSize=36=0x24) + 32B payload
	blob.Write(persoTlvVersionPrefixV1[:])
	blob.Write([]byte{0x05, 0x00, 0x00, 0x24})
	blob.Write(testDeviceID.Raw[:])
	// V1 WasTbsHmac: prefix (4B) + V1 header (Type=4, innerSize=36=0x24) + 32B payload
	blob.Write(persoTlvVersionPrefixV1[:])
	blob.Write([]byte{0x04, 0x00, 0x00, 0x24})
	blob.Write(testSignature.Raw[:])

	unpacked, err := UnpackPersoBlob(blob.Bytes())
	if err != nil {
		t.Fatalf("UnpackPersoBlob() failed: %v", err)
	}
	if diff := cmp.Diff(testDeviceID, unpacked.DeviceID); diff != "" {
		t.Errorf("Unpacked V1 DeviceID mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(testSignature, unpacked.Signature); diff != "" {
		t.Errorf("Unpacked V1 Signature mismatch (-want +got):\n%s", diff)
	}
}

func TestExtractCertObjectErrors(t *testing.T) {
	testCases := []struct {
		name      string
		buf       []byte
		expectErr string
	}{
		{
			name:      "nil buffer",
			buf:       nil,
			expectErr: "buffer too small for object header",
		},
		{
			name:      "single byte buffer",
			buf:       []byte{0x10},
			expectErr: "buffer too small for object header",
		},
		{
			name:      "V0 objSize smaller than headerSize",
			buf:       []byte{0x10, 0x01},
			expectErr: "invalid object size: 1",
		},
		{
			name:      "V1 objSize smaller than headerSize",
			buf:       []byte{0xF0, 0x04, 0x00, 0x01, 0x01, 0x00, 0x00, 0x03},
			expectErr: "invalid object size: 7",
		},
		{
			name: "V0 truncated cert header with trailing bytes beyond objSize",
			// Type=1, Size=3 (1 payload byte), followed by extra bytes that must not be read
			buf:       []byte{0x10, 0x03, 0xAA, 0xBB, 0xCC, 0xDD},
			expectErr: "buffer too small for certificate header",
		},
		{
			name: "V1 truncated cert header with trailing bytes beyond objSize",
			// V1 prefix + Type=1, innerSize=6 -> objSize=10 (2 payload bytes), followed by extra bytes
			buf:       []byte{0xF0, 0x04, 0x00, 0x01, 0x01, 0x00, 0x00, 0x06, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE},
			expectErr: "buffer too small for certificate header",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := extractCertObject(tc.buf)
			if err == nil {
				t.Errorf("extractCertObject() succeeded, want error containing %q", tc.expectErr)
			} else if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("extractCertObject() returned error %q, want error containing %q", err, tc.expectErr)
			}
		})
	}
}
