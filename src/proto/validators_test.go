// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
package validators

import (
	"encoding/pem"
	"testing"

	dpb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
)

const okCertPEM = `
-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgIIE31FZVaPXTUwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMTI5MTMyNzQzWhcNMTQwNTI5MDAwMDAw
WjBpMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEYMBYGA1UEAwwPbWFp
bC5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfRrObuSW5T7q
5CnSEqefEmtH4CCv6+5EckuriNr1CjfVvqzwfAhopXkLrq45EQm8vkmf7W96XJhC
7ZM0dYi1/qOCAU8wggFLMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAa
BgNVHREEEzARgg9tYWlsLmdvb2dsZS5jb20wCwYDVR0PBAQDAgeAMGgGCCsGAQUF
BwEBBFwwWjArBggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nbGUuY29tL0dJQUcy
LmNydDArBggrBgEFBQcwAYYfaHR0cDovL2NsaWVudHMxLmdvb2dsZS5jb20vb2Nz
cDAdBgNVHQ4EFgQUiJxtimAuTfwb+aUtBn5UYKreKvMwDAYDVR0TAQH/BAIwADAf
BgNVHSMEGDAWgBRK3QYWG7z2aLV29YG2u2IaulqBLzAXBgNVHSAEEDAOMAwGCisG
AQQB1nkCBQEwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BraS5nb29nbGUuY29t
L0dJQUcyLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAH6RYHxHdcGpMpFE3oxDoFnP+
gtuBCHan2yE2GRbJ2Cw8Lw0MmuKqHlf9RSeYfd3BXeKkj1qO6TVKwCh+0HdZk283
TZZyzmEOyclm3UGFYe82P/iDFt+CeQ3NpmBg+GoaVCuWAARJN/KfglbLyyYygcQq
0SgeDh8dRKUiaW3HQSoYvTvdTuqzwK4CXsr3b5/dAOY8uMuG/IAR3FgwTbZ1dtoW
RvOTa8hYiU6A475WuZKyEHcwnGYe57u2I2KbMgcKjPniocj4QzgYsVAVKW3IwaOh
yE+vPxsiUkvQHdO2fojCkY8jg70jxM+gu59tPDNbw3Uh/2Ij310FgTHsnGQMyA==
-----END CERTIFICATE-----`

var okCertBytes = func() []byte {
	block, _ := pem.Decode([]byte(okCertPEM))
	if block == nil {
		panic("failed to decode certificate PEM")
	}
	return block.Bytes
}()

var (
	hwOriginOk = dpb.HardwareOrigin{
		DeviceType: &dpb.DeviceType{
			SiliconCreator:    dpb.SiliconCreator_SILICON_CREATOR_TEST,
			ProductIdentifier: 0,
		},
		DeviceIdentificationNumber: 0,
	}
	hwOriginBadCreator = dpb.HardwareOrigin{
		DeviceType: &dpb.DeviceType{
			SiliconCreator:    dpb.SiliconCreator_SILICON_CREATOR_UNSPECIFIED,
			ProductIdentifier: 0,
		},
		DeviceIdentificationNumber: 0,
	}
	// TODO: hwOriginBadDeviceId, which would have an inok DeviceIdentificationNumber field.

	deviceIdOk = dpb.DeviceId{
		HardwareOrigin: &hwOriginOk,
		SkuSpecific:    make([]byte, DeviceIdSkuSpecificLen),
	}
	deviceIdOkMissingSku = dpb.DeviceId{
		HardwareOrigin: &hwOriginOk,
		SkuSpecific:    nil, // Empty SkuSpecific is OK.
	}
	deviceIdBadOrigin = dpb.DeviceId{
		HardwareOrigin: &hwOriginBadCreator,
		SkuSpecific:    make([]byte, DeviceIdSkuSpecificLen),
	}
	deviceIdSkuTooLong = dpb.DeviceId{
		HardwareOrigin: &hwOriginOk,
		SkuSpecific:    make([]byte, DeviceIdSkuSpecificLen+1),
	}
	// TODO: deviceIdBadCrc, which would have an inok Crc32 field.

	certOk = dpb.DeviceIdPub{Blob: okCertBytes}
)

func TestValidateSiliconCreator(t *testing.T) {
	tests := []struct {
		name string
		sc   dpb.SiliconCreator
		ok   bool
	}{
		{
			name: "test",
			sc:   dpb.SiliconCreator_SILICON_CREATOR_TEST,
			ok:   true,
		},
		{
			name: "unspecified",
			sc:   dpb.SiliconCreator_SILICON_CREATOR_UNSPECIFIED,
		},
		{
			name: "out of bounds: -1",
			sc:   dpb.SiliconCreator(-1),
		},
		{
			name: "out of bounds: 2",
			sc:   dpb.SiliconCreator(2),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateSiliconCreator(tt.sc); (err == nil) != tt.ok {
				t.Errorf("expected ok=%t; got err=%q", tt.ok, err)
			}
		})
	}
}

func TestValidateDeviceType(t *testing.T) {
	tests := []struct {
		name string
		dt   dpb.DeviceType
		ok   bool
	}{
		{
			name: "ok",
			dt: dpb.DeviceType{
				SiliconCreator:    dpb.SiliconCreator_SILICON_CREATOR_TEST,
				ProductIdentifier: 0,
			},
			ok: true,
		},
		{
			name: "bad creator",
			dt: dpb.DeviceType{
				SiliconCreator:    dpb.SiliconCreator_SILICON_CREATOR_UNSPECIFIED,
				ProductIdentifier: 0,
			},
		},
		{
			name: "bad product id",
			dt: dpb.DeviceType{
				SiliconCreator:    dpb.SiliconCreator_SILICON_CREATOR_TEST,
				ProductIdentifier: 0x10000,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateDeviceType(&tt.dt); (err == nil) != tt.ok {
				t.Errorf("expected ok=%t; got err=%q", tt.ok, err)
			}
		})
	}
}

func TestValidateHardwareOrigin(t *testing.T) {
	tests := []struct {
		name string
		ho   *dpb.HardwareOrigin
		ok   bool
	}{
		{
			name: "ok",
			ho:   &hwOriginOk,
			ok:   true,
		},
		{
			name: "bad creator",
			ho:   &hwOriginBadCreator,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateHardwareOrigin(tt.ho); (err == nil) != tt.ok {
				t.Errorf("expected ok=%t; got err=%q", tt.ok, err)
			}
		})
	}
}

func TestValidateDeviceId(t *testing.T) {
	tests := []struct {
		name string
		di   *dpb.DeviceId
		ok   bool
	}{
		{
			name: "ok",
			di:   &deviceIdOk,
			ok:   true,
		},
		{
			name: "missing sku",
			di:   &deviceIdOkMissingSku,
			ok:   true, // SKU is optional.
		},
		{
			name: "bad origin",
			di:   &deviceIdBadOrigin,
		},
		{
			name: "sku too long",
			di:   &deviceIdSkuTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateDeviceId(tt.di); (err == nil) != tt.ok {
				t.Errorf("expected ok=%t; got err=%q", tt.ok, err)
			}
		})
	}
}

func TestValidateDeviceIdPub(t *testing.T) {
	tests := []struct {
		name string
		cert *dpb.DeviceIdPub
		ok   bool
	}{
		{
			name: "ok",
			cert: &certOk,
			ok:   true,
		},
		// FIXME: Fill this in (need inok examples).
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateDeviceIdPub(tt.cert); (err == nil) != tt.ok {
				t.Errorf("expected ok=%t; got err=%q", tt.ok, err)
			}
		})
	}
}

func TestValidateLifeCycle(t *testing.T) {
	tests := []struct {
		name string
		lc   dpb.DeviceLifeCycle
		ok   bool
	}{
		{
			name: "prod",
			lc:   dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
			ok:   true,
		},
		{
			name: "dev",
			lc:   dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_DEV,
			ok:   true,
		},
		{
			name: "unspecified",
			lc:   dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_UNSPECIFIED,
		},
		{
			name: "out of bounds: -1",
			lc:   dpb.DeviceLifeCycle(-1),
		},
		{
			name: "out of bounds: 13",
			lc:   dpb.DeviceLifeCycle(13),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateDeviceLifeCycle(tt.lc); (err == nil) != tt.ok {
				t.Errorf("expected ok=%t; got err=%q", tt.ok, err)
			}
		})
	}
}

func TestValidateDeviceData(t *testing.T) {
	tests := []struct {
		name string
		dd   *dpb.DeviceData
		ok   bool
	}{
		{
			name: "zero certs",
			dd: &dpb.DeviceData{
				DeviceIdPubs:    nil,
				Payload:         make([]byte, MinDeviceDataPayloadLen),
				DeviceLifeCycle: dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_DEV,
			},
			ok: true,
		},
		{
			name: "one cert",
			dd: &dpb.DeviceData{
				DeviceIdPubs:    []*dpb.DeviceIdPub{&certOk},
				Payload:         make([]byte, MinDeviceDataPayloadLen),
				DeviceLifeCycle: dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
			},
			ok: true,
		},
		{
			name: "two certs",
			dd: &dpb.DeviceData{
				DeviceIdPubs:    []*dpb.DeviceIdPub{&certOk, &certOk},
				Payload:         make([]byte, MinDeviceDataPayloadLen),
				DeviceLifeCycle: dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
			},
			ok: true,
		},
		{
			name: "payload too small",
			dd: &dpb.DeviceData{
				DeviceIdPubs:    nil,
				Payload:         make([]byte, MinDeviceDataPayloadLen-1),
				DeviceLifeCycle: dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
			},
		},
		{
			name: "bad device life cycle",
			dd: &dpb.DeviceData{
				DeviceIdPubs:    nil,
				Payload:         make([]byte, MinDeviceDataPayloadLen),
				DeviceLifeCycle: dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_UNSPECIFIED,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateDeviceData(tt.dd); (err == nil) != tt.ok {
				t.Errorf("expected ok=%t; got err=%q", tt.ok, err)
			}
		})
	}
}
