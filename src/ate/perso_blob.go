// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package ate

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Constants from ate_api.h
const (
	kCertificateMaxSize         = 8192
	kCertificateKeyLabelMaxSize = 32
	kDevSeedBytesSize           = 128
	kWasHmacSignatureSize       = 32
	kPersoBlobMaxSize           = 65536
	kDeviceIDSize               = 32
)

// PersoBlobVersion represents the version of a personalization blob.
type PersoBlobVersion int

const (
	// PersoBlobVersionV0 is the original personalization blob format. It uses
	// a 16-bit object header (4-bit type, 12-bit size), which limits the
	// maximum size of any single object to 4KB.
	PersoBlobVersionV0 PersoBlobVersion = 0
	// PersoBlobVersionV1 personalization blobs start with a version TLV object
	// (which uses the V0 header format for backwards compatibility). The
	// immediately following object uses a larger 32-bit header (8-bit type,
	// 24-bit size), allowing for significantly larger objects (up to 16MB).
	PersoBlobVersionV1 PersoBlobVersion = 1
)

// PersoObjectType represents the type of an object in a personalization blob.
type PersoObjectType uint16

// Constants from perso_tlv_data.h (via ate_perso_blob.h)
const (
	PersoObjectTypeX509Tbs     PersoObjectType = 0
	PersoObjectTypeX509Cert    PersoObjectType = 1
	PersoObjectTypeDevSeed     PersoObjectType = 2
	PersoObjectTypeCwtCert     PersoObjectType = 3
	PersoObjectTypeWasTbsHmac  PersoObjectType = 4
	PersoObjectTypeDeviceId    PersoObjectType = 5
	PersoObjectTypeGenericSeed PersoObjectType = 6
	PersoObjectTypeBlobVersion PersoObjectType = 15
)

var persoTlvVersionPrefixV1 = [4]byte{0xF0, 0x04, 0x00, 0x01}

const (
	sizeOfVersionPrefix  = 4
	sizeOfObjectHeaderV0 = 2
	sizeOfObjectHeaderV1 = 4
	sizeOfCertHeaderV0   = 2
	sizeOfCertHeaderV1   = 4

	kCrthV0MaxCertNameLen = 15
	kObjhV0MaxObjSize     = 4095

	// V0 Header field definitions (from perso_tlv_data.h)
	objhSizeFieldShiftV0 = 0
	objhSizeFieldWidthV0 = 12
	objhSizeFieldMaskV0  = (1 << objhSizeFieldWidthV0) - 1
	objhTypeFieldShiftV0 = objhSizeFieldWidthV0
	objhTypeFieldWidthV0 = 16 - objhSizeFieldWidthV0
	objhTypeFieldMaskV0  = (1 << objhTypeFieldWidthV0) - 1

	crthSizeFieldShiftV0     = 0
	crthSizeFieldWidthV0     = 12
	crthSizeFieldMaskV0      = (1 << crthSizeFieldWidthV0) - 1
	crthNameSizeFieldShiftV0 = crthSizeFieldWidthV0
	crthNameSizeFieldWidthV0 = 4
	crthNameSizeFieldMaskV0  = (1 << crthNameSizeFieldWidthV0) - 1

	// TODO upstream V1 defintiions to perso_tlv_data.h in OpenTitan repo.
	// V1 Header field definitions
	objhSizeFieldShiftV1 = 0
	objhSizeFieldWidthV1 = 24
	objhSizeFieldMaskV1  = (1 << objhSizeFieldWidthV1) - 1
	objhTypeFieldShiftV1 = objhSizeFieldWidthV1
	objhTypeFieldWidthV1 = 32 - objhSizeFieldWidthV1
	objhTypeFieldMaskV1  = (1 << objhTypeFieldWidthV1) - 1

	crthSizeFieldShiftV1     = 0
	crthSizeFieldWidthV1     = 24
	crthSizeFieldMaskV1      = (1 << crthSizeFieldWidthV1) - 1
	crthNameSizeFieldShiftV1 = crthSizeFieldWidthV1
	crthNameSizeFieldWidthV1 = 32 - crthSizeFieldWidthV1
	crthNameSizeFieldMaskV1  = (1 << crthNameSizeFieldWidthV1) - 1

)

// DeviceIDBytes corresponds to device_id_bytes_t
type DeviceIDBytes struct {
	Raw [kDeviceIDSize]byte
}

// EndorseCertSignature corresponds to endorse_cert_signature_t
type EndorseCertSignature struct {
	Raw [kWasHmacSignatureSize]byte
}

// EndorseCertRequest corresponds to endorse_cert_request_t
type EndorseCertRequest struct {
	KeyLabel string
	Tbs      []byte
}

// EndorseCertResponse corresponds to endorse_cert_response_t
type EndorseCertResponse struct {
	KeyLabel string
	Cert     []byte
}

// Seed corresponds to seed_t
type Seed struct {
	Type PersoObjectType
	Raw  []byte
}

// PersoBlob is the Go representation of the unpacked personalization blob.
type PersoBlob struct {
	DeviceID     *DeviceIDBytes
	Signature    *EndorseCertSignature
	X509TbsCerts []EndorseCertRequest
	X509Certs    []EndorseCertResponse
	Seeds        []Seed
	CwtCerts     []EndorseCertResponse
}

// persoTLVCertObj corresponds to perso_tlv_cert_obj_t
type persoTLVCertObj struct {
	CertBody []byte
	Name     string
}

func getObjectVersion(body []byte) PersoBlobVersion {
	if len(body) >= sizeOfVersionPrefix+sizeOfObjectHeaderV1 &&
		body[0] == persoTlvVersionPrefixV1[0] &&
		body[1] == persoTlvVersionPrefixV1[1] &&
		body[2] == persoTlvVersionPrefixV1[2] &&
		body[3] == persoTlvVersionPrefixV1[3] {
		return PersoBlobVersionV1
	}
	return PersoBlobVersionV0
}

func selectObjectVersion(bodySize, nameSize int) PersoBlobVersion {
	if nameSize > kCrthV0MaxCertNameLen {
		return PersoBlobVersionV1
	}
	v0HeaderSize := sizeOfObjectHeaderV0
	if nameSize > 0 {
		v0HeaderSize += sizeOfCertHeaderV0 + nameSize
	}
	if v0HeaderSize+bodySize > kObjhV0MaxObjSize {
		return PersoBlobVersionV1
	}
	return PersoBlobVersionV0
}

func getObjectHeaderFields(body []byte) (size uint32, objType PersoObjectType, headerSize int) {
	blobVersion := getObjectVersion(body)
	if blobVersion == PersoBlobVersionV1 {
		header := binary.BigEndian.Uint32(body[sizeOfVersionPrefix:])
		innerSize := (header >> objhSizeFieldShiftV1) & objhSizeFieldMaskV1
		size = sizeOfVersionPrefix + innerSize
		objType = PersoObjectType((header >> objhTypeFieldShiftV1) & objhTypeFieldMaskV1)
		headerSize = sizeOfVersionPrefix + sizeOfObjectHeaderV1
	} else {
		header := binary.BigEndian.Uint16(body)
		size = uint32((header >> objhSizeFieldShiftV0) & objhSizeFieldMaskV0)
		objType = PersoObjectType((header >> objhTypeFieldShiftV0) & objhTypeFieldMaskV0)
		headerSize = sizeOfObjectHeaderV0
	}
	return
}

func getCertHeaderFields(body []byte, blobVersion int) (size uint32, nameSize uint32, headerSize int) {
	if blobVersion == 1 {
		header := binary.BigEndian.Uint32(body)
		size = (header >> crthSizeFieldShiftV1) & crthSizeFieldMaskV1
		nameSize = (header >> crthNameSizeFieldShiftV1) & crthNameSizeFieldMaskV1
		headerSize = sizeOfCertHeaderV1
	} else {
		header := binary.BigEndian.Uint16(body)
		size = uint32((header >> crthSizeFieldShiftV0) & crthSizeFieldMaskV0)
		nameSize = uint32((header >> crthNameSizeFieldShiftV0) & crthNameSizeFieldMaskV0)
		headerSize = sizeOfCertHeaderV0
	}
	return
}

func setObjectHeaderFields(buf []byte, size uint32, objType PersoObjectType, blobVersion int) int {
	if blobVersion == 1 {
		header := ((uint32(objType) & objhTypeFieldMaskV1) << objhTypeFieldShiftV1) | ((size & objhSizeFieldMaskV1) << objhSizeFieldShiftV1)
		binary.BigEndian.PutUint32(buf, header)
		return sizeOfObjectHeaderV1
	} else {
		header := ((uint16(objType) & objhTypeFieldMaskV0) << objhTypeFieldShiftV0) | ((uint16(size) & objhSizeFieldMaskV0) << objhSizeFieldShiftV0)
		binary.BigEndian.PutUint16(buf, header)
		return sizeOfObjectHeaderV0
	}
}

func setCertHeaderFields(buf []byte, certSize uint32, nameSize uint32, blobVersion int) int {
	if blobVersion == 1 {
		header := ((nameSize & crthNameSizeFieldMaskV1) << crthNameSizeFieldShiftV1) | ((certSize & crthSizeFieldMaskV1) << crthSizeFieldShiftV1)
		binary.BigEndian.PutUint32(buf, header)
		return sizeOfCertHeaderV1
	} else {
		header := (uint16(nameSize&crthNameSizeFieldMaskV0) << crthNameSizeFieldShiftV0) | (uint16(certSize&crthSizeFieldMaskV0) << crthSizeFieldShiftV0)
		binary.BigEndian.PutUint16(buf, header)
		return sizeOfCertHeaderV0
	}
}

func extractCertObject(buf []byte) (*persoTLVCertObj, error) {
	objSize, objType, headerSize := getObjectHeaderFields(buf)

	if objSize == 0 || int(objSize) > len(buf) {
		return nil, fmt.Errorf("invalid object size: %d, buffer size: %d", objSize, len(buf))
	}
	if objType != PersoObjectTypeX509Tbs && objType != PersoObjectTypeX509Cert && objType != PersoObjectTypeCwtCert {
		return nil, fmt.Errorf("invalid object type: %d, expected X509 TBS, cert, or CWT cert", objType)
	}

	blobVersion := getObjectVersion(buf)
	buf = buf[headerSize:]
	certEntrySize, nameLen, certHeaderSize := getCertHeaderFields(buf, int(blobVersion))

	buf = buf[certHeaderSize:]
	if len(buf) < int(nameLen) {
		return nil, fmt.Errorf("buffer too small for certificate name: %d, available: %d", nameLen, len(buf))
	}

	name := string(buf[:nameLen])
	buf = buf[nameLen:]

	certBodySize := int(certEntrySize) - int(nameLen) - certHeaderSize
	if certBodySize < 0 {
		return nil, fmt.Errorf("invalid certificate body size: %d", certBodySize)
	}
	if len(buf) < certBodySize {
		return nil, fmt.Errorf("buffer too small for certificate body: %d, available: %d", certBodySize, len(buf))
	}

	return &persoTLVCertObj{
		Name:     name,
		CertBody: buf[:certBodySize],
	}, nil
}

// UnpackPersoBlob unpacks a raw personalization blob into a structured format.
// This is the Go equivalent of the C function with the same name.
func UnpackPersoBlob(blobBytes []byte) (*PersoBlob, error) {
	if len(blobBytes) == 0 {
		return nil, errors.New("invalid personalization blob: empty")
	}
	if len(blobBytes) > kPersoBlobMaxSize {
		return nil, fmt.Errorf("blob size %d exceeds max %d", len(blobBytes), kPersoBlobMaxSize)
	}

	persoBlob := &PersoBlob{}
	offset := 0

	for offset < len(blobBytes) {
		remaining := len(blobBytes[offset:])
		if remaining == 0 {
			break
		}
		if remaining < sizeOfObjectHeaderV0 {
			return nil, errors.New("remaining buffer too small for object header")
		}

		objSize, objType, headerSize := getObjectHeaderFields(blobBytes[offset:])

		if objSize == 0 {
			// Check if the rest of the buffer is zeroes (padding)
			for i := offset; i < len(blobBytes); i++ {
				if blobBytes[i] != 0 {
					return nil, fmt.Errorf("invalid object type %d with size 0", objType)
				}
			}
			break
		}
		if offset+int(objSize) > len(blobBytes) {
			return nil, fmt.Errorf("object size %d exceeds remaining buffer %d", objSize, len(blobBytes[offset:]))
		}

		objBytes := blobBytes[offset : offset+int(objSize)]

		switch objType {
		case PersoObjectTypeBlobVersion:
			return nil, errors.New("Unexpected standalone version object")

		case PersoObjectTypeDeviceId:
			var deviceID DeviceIDBytes
			copy(deviceID.Raw[:], objBytes[headerSize:])
			persoBlob.DeviceID = &deviceID

		case PersoObjectTypeX509Tbs:
			certObj, err := extractCertObject(objBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to extract X509 TBS cert: %w", err)
			}
			persoBlob.X509TbsCerts = append(persoBlob.X509TbsCerts, EndorseCertRequest{
				KeyLabel: certObj.Name,
				Tbs:      certObj.CertBody,
			})

		case PersoObjectTypeX509Cert:
			certObj, err := extractCertObject(objBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to extract X509 cert: %w", err)
			}
			persoBlob.X509Certs = append(persoBlob.X509Certs, EndorseCertResponse{
				KeyLabel: certObj.Name,
				Cert:     certObj.CertBody,
			})
		case PersoObjectTypeCwtCert:
			certObj, err := extractCertObject(objBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to extract CWT cert: %w", err)
			}
			persoBlob.CwtCerts = append(persoBlob.CwtCerts, EndorseCertResponse{
				KeyLabel: certObj.Name,
				Cert:     certObj.CertBody,
			})

		case PersoObjectTypeWasTbsHmac:
			var signature EndorseCertSignature
			copy(signature.Raw[:], objBytes[headerSize:])
			persoBlob.Signature = &signature

		case PersoObjectTypeDevSeed, PersoObjectTypeGenericSeed:
			seedData := objBytes[headerSize:]
			persoBlob.Seeds = append(persoBlob.Seeds, Seed{
				Type: objType,
				Raw:  seedData,
			})
		}
		offset += int(objSize)
	}

	return persoBlob, nil
}

// BuildPersoBlob serializes a PersoBlob struct into a byte slice.
func BuildPersoBlob(persoBlob *PersoBlob) ([]byte, error) {
	var buf bytes.Buffer

	// 1. Device ID object
	if persoBlob.DeviceID != nil {
		blobVersion := selectObjectVersion(len(persoBlob.DeviceID.Raw), 0)
		if blobVersion == PersoBlobVersionV1 {
			buf.Write(persoTlvVersionPrefixV1[:])
		}
		headerSize := sizeOfObjectHeaderV1
		if blobVersion == PersoBlobVersionV0 {
			headerSize = sizeOfObjectHeaderV0
		}
		objSize := uint32(headerSize + len(persoBlob.DeviceID.Raw))
		hbuf := make([]byte, 4)
		actualHeaderSize := setObjectHeaderFields(hbuf, objSize, PersoObjectTypeDeviceId, int(blobVersion))
		buf.Write(hbuf[:actualHeaderSize])
		buf.Write(persoBlob.DeviceID.Raw[:])
	}

	// 2. Signature object
	if persoBlob.Signature != nil {
		blobVersion := selectObjectVersion(len(persoBlob.Signature.Raw), 0)
		if blobVersion == PersoBlobVersionV1 {
			buf.Write(persoTlvVersionPrefixV1[:])
		}
		headerSize := sizeOfObjectHeaderV1
		if blobVersion == PersoBlobVersionV0 {
			headerSize = sizeOfObjectHeaderV0
		}
		objSize := uint32(headerSize + len(persoBlob.Signature.Raw))
		hbuf := make([]byte, 4)
		actualHeaderSize := setObjectHeaderFields(hbuf, objSize, PersoObjectTypeWasTbsHmac, int(blobVersion))
		buf.Write(hbuf[:actualHeaderSize])
		buf.Write(persoBlob.Signature.Raw[:])
	}

	// 3. X509 TBS certificate objects
	for _, tbsCert := range persoBlob.X509TbsCerts {
		keyLabelBytes := []byte(tbsCert.KeyLabel)
		blobVersion := selectObjectVersion(len(tbsCert.Tbs), len(keyLabelBytes))
		if blobVersion == PersoBlobVersionV1 {
			buf.Write(persoTlvVersionPrefixV1[:])
		}
		certHeaderSizeVal := sizeOfCertHeaderV1
		if blobVersion == PersoBlobVersionV0 {
			certHeaderSizeVal = sizeOfCertHeaderV0
		}
		certEntrySize := uint32(certHeaderSizeVal + len(keyLabelBytes) + len(tbsCert.Tbs))
		headerSize := sizeOfObjectHeaderV1
		if blobVersion == PersoBlobVersionV0 {
			headerSize = sizeOfObjectHeaderV0
		}
		objSize := uint32(headerSize) + certEntrySize
		hbuf := make([]byte, 4)
		actualHeaderSize := setObjectHeaderFields(hbuf, objSize, PersoObjectTypeX509Tbs, int(blobVersion))
		buf.Write(hbuf[:actualHeaderSize])

		actualCertHeaderSize := setCertHeaderFields(hbuf, certEntrySize, uint32(len(keyLabelBytes)), int(blobVersion))
		buf.Write(hbuf[:actualCertHeaderSize])
		buf.Write(keyLabelBytes)
		buf.Write(tbsCert.Tbs)
	}

	// 4. X509 certificate objects
	for _, cert := range persoBlob.X509Certs {
		keyLabelBytes := []byte(cert.KeyLabel)
		blobVersion := selectObjectVersion(len(cert.Cert), len(keyLabelBytes))
		if blobVersion == PersoBlobVersionV1 {
			buf.Write(persoTlvVersionPrefixV1[:])
		}
		certHeaderSizeVal := sizeOfCertHeaderV1
		if blobVersion == PersoBlobVersionV0 {
			certHeaderSizeVal = sizeOfCertHeaderV0
		}
		certEntrySize := uint32(certHeaderSizeVal + len(keyLabelBytes) + len(cert.Cert))
		headerSize := sizeOfObjectHeaderV1
		if blobVersion == PersoBlobVersionV0 {
			headerSize = sizeOfObjectHeaderV0
		}
		objSize := uint32(headerSize) + certEntrySize
		hbuf := make([]byte, 4)
		actualHeaderSize := setObjectHeaderFields(hbuf, objSize, PersoObjectTypeX509Cert, int(blobVersion))
		buf.Write(hbuf[:actualHeaderSize])

		actualCertHeaderSize := setCertHeaderFields(hbuf, certEntrySize, uint32(len(keyLabelBytes)), int(blobVersion))
		buf.Write(hbuf[:actualCertHeaderSize])
		buf.Write(keyLabelBytes)
		buf.Write(cert.Cert)
	}

	// 5. CWT certificate objects
	for _, cert := range persoBlob.CwtCerts {
		keyLabelBytes := []byte(cert.KeyLabel)
		blobVersion := selectObjectVersion(len(cert.Cert), len(keyLabelBytes))
		if blobVersion == PersoBlobVersionV1 {
			buf.Write(persoTlvVersionPrefixV1[:])
		}
		certHeaderSizeVal := sizeOfCertHeaderV1
		if blobVersion == PersoBlobVersionV0 {
			certHeaderSizeVal = sizeOfCertHeaderV0
		}
		certEntrySize := uint32(certHeaderSizeVal + len(keyLabelBytes) + len(cert.Cert))
		headerSize := sizeOfObjectHeaderV1
		if blobVersion == PersoBlobVersionV0 {
			headerSize = sizeOfObjectHeaderV0
		}
		objSize := uint32(headerSize) + certEntrySize
		hbuf := make([]byte, 4)
		actualHeaderSize := setObjectHeaderFields(hbuf, objSize, PersoObjectTypeCwtCert, int(blobVersion))
		buf.Write(hbuf[:actualHeaderSize])

		actualCertHeaderSize := setCertHeaderFields(hbuf, certEntrySize, uint32(len(keyLabelBytes)), int(blobVersion))
		buf.Write(hbuf[:actualCertHeaderSize])
		buf.Write(keyLabelBytes)
		buf.Write(cert.Cert)
	}

	// 6. Seed objects
	for _, seed := range persoBlob.Seeds {
		blobVersion := selectObjectVersion(len(seed.Raw), 0)
		if blobVersion == PersoBlobVersionV1 {
			buf.Write(persoTlvVersionPrefixV1[:])
		}
		headerSize := sizeOfObjectHeaderV1
		if blobVersion == PersoBlobVersionV0 {
			headerSize = sizeOfObjectHeaderV0
		}
		objSize := uint32(headerSize + len(seed.Raw))
		hbuf := make([]byte, 4)
		actualHeaderSize := setObjectHeaderFields(hbuf, objSize, seed.Type, int(blobVersion))
		buf.Write(hbuf[:actualHeaderSize])
		buf.Write(seed.Raw)
	}

	return buf.Bytes(), nil
}
