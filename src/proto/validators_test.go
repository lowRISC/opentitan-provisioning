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
	// TODO: add varying device identification numbers to test cases
	hwOriginOk = dpb.HardwareOrigin{
		SiliconCreatorId:           dpb.SiliconCreatorId_SILICON_CREATOR_ID_OPENSOURCE,
		ProductId:                  dpb.ProductId_PRODUCT_ID_EARLGREY_Z1,
		DeviceIdentificationNumber: 0,
	}
	hwOriginBadSiliconCreatorId = dpb.HardwareOrigin{
		SiliconCreatorId:           2,
		ProductId:                  dpb.ProductId_PRODUCT_ID_EARLGREY_A1,
		DeviceIdentificationNumber: 0,
	}
	hwOriginBadProductId = dpb.HardwareOrigin{
		SiliconCreatorId:           dpb.SiliconCreatorId_SILICON_CREATOR_ID_NUVOTON,
		ProductId:                  0x10000,
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
		HardwareOrigin: &hwOriginBadSiliconCreatorId,
		SkuSpecific:    make([]byte, DeviceIdSkuSpecificLen),
	}
	deviceIdSkuTooLong = dpb.DeviceId{
		HardwareOrigin: &hwOriginOk,
		SkuSpecific:    make([]byte, DeviceIdSkuSpecificLen+1),
	}
	// TODO: deviceIdBadCrc, which would have an inok Crc32 field.

	deviceDataOk = dpb.DeviceData{
		DeviceLifeCycle: dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
		Payload:         okCertBytes,
	}
)

func TestValidateSiliconCreatorId(t *testing.T) {
	tests := []struct {
		name string
		sc   dpb.SiliconCreatorId
		ok   bool
	}{
		{
			name: "unspecified",
			sc:   dpb.SiliconCreatorId_SILICON_CREATOR_ID_UNSPECIFIED,
		},
		{
			name: "opensource",
			sc:   dpb.SiliconCreatorId_SILICON_CREATOR_ID_OPENSOURCE,
			ok:   true,
		},
		{
			name: "nuvoton",
			sc:   dpb.SiliconCreatorId_SILICON_CREATOR_ID_NUVOTON,
			ok:   true,
		},
		{
			name: "invalid: -1",
			sc:   dpb.SiliconCreatorId(-1),
		},
		{
			name: "invalid: 2",
			sc:   dpb.SiliconCreatorId(2),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateSiliconCreatorId(tt.sc); (err == nil) != tt.ok {
				t.Errorf("expected ok=%t; got err=%q", tt.ok, err)
			}
		})
	}
}

func TestValidateProductId(t *testing.T) {
	tests := []struct {
		name string
		pi   dpb.ProductId
		ok   bool
	}{
		{
			name: "unspecified",
			pi:   dpb.ProductId_PRODUCT_ID_UNSPECIFIED,
		},
		{
			name: "earlgrey-z1",
			pi:   dpb.ProductId_PRODUCT_ID_EARLGREY_Z1,
			ok:   true,
		},
		{
			name: "earlgrey-a1",
			pi:   dpb.ProductId_PRODUCT_ID_EARLGREY_A1,
			ok:   true,
		},
		{
			name: "invalid: 0xffff",
			pi:   dpb.ProductId(0xffff),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateProductId(tt.pi); (err == nil) != tt.ok {
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
			name: "bad silicon creator ID",
			ho:   &hwOriginBadSiliconCreatorId,
		},
		{
			name: "bad product ID",
			ho:   &hwOriginBadProductId,
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

func TestValidateLifeCycle(t *testing.T) {
	tests := []struct {
		name string
		lc   dpb.DeviceLifeCycle
		ok   bool
	}{
		{
			name: "dev",
			lc:   dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_DEV,
			ok:   true,
		},
		{
			name: "prod",
			lc:   dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
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
			name: "empty payload",
			dd: &dpb.DeviceData{
				Payload:         make([]byte, 0),
				DeviceLifeCycle: dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_DEV,
			},
			ok: true,
		},
		{
			name: "valid payload with one cert",
			dd:   &deviceDataOk,
			ok:   true,
		},
		{
			name: "payload too large",
			dd: &dpb.DeviceData{
				Payload:         make([]byte, MaxDeviceDataPayloadLen+1),
				DeviceLifeCycle: dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
			},
		},
		{
			name: "bad device life cycle",
			dd: &dpb.DeviceData{
				Payload:         make([]byte, 0),
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
