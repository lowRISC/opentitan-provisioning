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
	kCertificateMaxSize         = 2048
	kCertificateKeyLabelMaxSize = 32
	kDevSeedBytesSize           = 128
	kWasHmacSignatureSize       = 32
	kPersoBlobMaxSize           = 8192
	kDeviceIDSize               = 32
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
)

const (
	sizeOfObjectHeader = 2
	sizeOfCertHeader   = 2
)

// Header field definitions from perso_tlv_data.h
const (
	objhSizeFieldShift = 0
	objhSizeFieldWidth = 12
	objhSizeFieldMask  = (1 << objhSizeFieldWidth) - 1
	objhTypeFieldShift = objhSizeFieldWidth
	objhTypeFieldWidth = 16 - objhSizeFieldWidth
	objhTypeFieldMask  = (1 << objhTypeFieldWidth) - 1

	crthSizeFieldShift     = 0
	crthSizeFieldWidth     = 12
	crthSizeFieldMask      = (1 << crthSizeFieldWidth) - 1
	crthNameSizeFieldShift = crthSizeFieldWidth
	crthNameSizeFieldWidth = 4
	crthNameSizeFieldMask  = (1 << crthNameSizeFieldWidth) - 1
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

// setObjectHeaderFields is a helper to create an object header.
func setObjectHeaderFields(size uint16, objType PersoObjectType) uint16 {
	return ((size & objhSizeFieldMask) << objhSizeFieldShift) | ((uint16(objType) & objhTypeFieldMask) << objhTypeFieldShift)
}

// setCertHeaderFields is a helper to create a certificate object header.
func setCertHeaderFields(certSize, nameSize uint16) uint16 {
	return ((certSize & crthSizeFieldMask) << crthSizeFieldShift) | ((nameSize & crthNameSizeFieldMask) << crthNameSizeFieldShift)
}

func getObjectHeaderFields(header uint16) (size uint16, objType PersoObjectType) {
	size = (header >> objhSizeFieldShift) & objhSizeFieldMask
	objType = PersoObjectType((header >> objhTypeFieldShift) & objhTypeFieldMask)
	return
}

func getCertHeaderFields(header uint16) (size, nameSize uint16) {
	size = (header >> crthSizeFieldShift) & crthSizeFieldMask
	nameSize = (header >> crthNameSizeFieldShift) & crthNameSizeFieldMask
	return
}

func extractCertObject(buf []byte) (*persoTLVCertObj, error) {
	if len(buf) < sizeOfObjectHeader {
		return nil, fmt.Errorf("buffer too small for object header: %d", len(buf))
	}
	objHeader := binary.BigEndian.Uint16(buf)
	objSize, objType := getObjectHeaderFields(objHeader)

	if objSize == 0 || int(objSize) > len(buf) {
		return nil, fmt.Errorf("invalid object size: %d, buffer size: %d", objSize, len(buf))
	}
	if objType != PersoObjectTypeX509Tbs && objType != PersoObjectTypeX509Cert && objType != PersoObjectTypeCwtCert {
		return nil, fmt.Errorf("invalid object type: %d, expected X509 TBS, cert, or CWT cert", objType)
	}

	buf = buf[sizeOfObjectHeader:]
	if len(buf) < sizeOfCertHeader {
		return nil, errors.New("buffer too small for certificate header")
	}

	certHeader := binary.BigEndian.Uint16(buf)
	_, nameLen := getCertHeaderFields(certHeader)

	buf = buf[sizeOfCertHeader:]
	if len(buf) < int(nameLen) {
		return nil, fmt.Errorf("buffer too small for certificate name: %d, available: %d", nameLen, len(buf))
	}

	name := string(buf[:nameLen])
	buf = buf[nameLen:]

	certBodySize := int(objSize) - int(nameLen) - sizeOfCertHeader - sizeOfObjectHeader
	if certBodySize < 0 {
		return nil, fmt.Errorf("invalid certificate body size: %d", certBodySize)
	}
	if certBodySize > len(buf) {
		return nil, fmt.Errorf("certificate body size (%d) exceeds available buffer size (%d)", certBodySize, len(buf))
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
		if len(blobBytes[offset:]) < sizeOfObjectHeader {
			// This can happen if the last object size was wrong
			return nil, errors.New("remaining buffer too small for object header")
		}

		header := binary.BigEndian.Uint16(blobBytes[offset:])
		objSize, objType := getObjectHeaderFields(header)

		if objSize == 0 {
			if offset == len(blobBytes)-sizeOfObjectHeader && header == 0 {
				break // Padding at the end
			}
			return nil, fmt.Errorf("invalid object type %d with size 0", objType)
		}
		if offset+int(objSize) > len(blobBytes) {
			return nil, fmt.Errorf("object size %d exceeds remaining buffer %d", objSize, len(blobBytes[offset:]))
		}

		objBytes := blobBytes[offset : offset+int(objSize)]

		switch objType {
		case PersoObjectTypeDeviceId:
			if len(objBytes) != kDeviceIDSize+sizeOfObjectHeader {
				return nil, fmt.Errorf("invalid device ID object size: %d", len(objBytes))
			}
			var deviceID DeviceIDBytes
			copy(deviceID.Raw[:], objBytes[sizeOfObjectHeader:])
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
			if len(objBytes) != kWasHmacSignatureSize+sizeOfObjectHeader {
				return nil, fmt.Errorf("invalid WAS TBS HMAC object size: %d", len(objBytes))
			}
			var signature EndorseCertSignature
			copy(signature.Raw[:], objBytes[sizeOfObjectHeader:])
			persoBlob.Signature = &signature

		case PersoObjectTypeDevSeed, PersoObjectTypeGenericSeed:
			if len(objBytes) > kDevSeedBytesSize+sizeOfObjectHeader {
				return nil, fmt.Errorf("invalid seed object size: %d", len(objBytes))
			}
			seedData := objBytes[sizeOfObjectHeader:]
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
		objSize := uint16(sizeOfObjectHeader + len(persoBlob.DeviceID.Raw))
		header := setObjectHeaderFields(objSize, PersoObjectTypeDeviceId)
		if err := binary.Write(&buf, binary.BigEndian, header); err != nil {
			return nil, err
		}
		if _, err := buf.Write(persoBlob.DeviceID.Raw[:]); err != nil {
			return nil, err
		}
	}

	// 2. Signature object
	if persoBlob.Signature != nil {
		objSize := uint16(sizeOfObjectHeader + len(persoBlob.Signature.Raw))
		header := setObjectHeaderFields(objSize, PersoObjectTypeWasTbsHmac)
		if err := binary.Write(&buf, binary.BigEndian, header); err != nil {
			return nil, err
		}
		if _, err := buf.Write(persoBlob.Signature.Raw[:]); err != nil {
			return nil, err
		}
	}

	// 3. TBS certificate objects
	for _, tbsCert := range persoBlob.X509TbsCerts {
		keyLabelBytes := []byte(tbsCert.KeyLabel)
		certEntrySize := uint16(sizeOfCertHeader + len(keyLabelBytes) + len(tbsCert.Tbs))
		objSize := uint16(sizeOfObjectHeader) + certEntrySize
		header := setObjectHeaderFields(objSize, PersoObjectTypeX509Tbs)
		if err := binary.Write(&buf, binary.BigEndian, header); err != nil {
			return nil, err
		}

		certHeader := setCertHeaderFields(certEntrySize, uint16(len(keyLabelBytes)))
		if err := binary.Write(&buf, binary.BigEndian, certHeader); err != nil {
			return nil, err
		}
		if _, err := buf.Write(keyLabelBytes); err != nil {
			return nil, err
		}
		if _, err := buf.Write(tbsCert.Tbs); err != nil {
			return nil, err
		}
	}

	// 4. X509 certificate objects
	for _, cert := range persoBlob.X509Certs {
		keyLabelBytes := []byte(cert.KeyLabel)
		certEntrySize := uint16(sizeOfCertHeader + len(keyLabelBytes) + len(cert.Cert))
		objSize := uint16(sizeOfObjectHeader) + certEntrySize
		header := setObjectHeaderFields(objSize, PersoObjectTypeX509Cert)
		if err := binary.Write(&buf, binary.BigEndian, header); err != nil {
			return nil, err
		}

		certHeader := setCertHeaderFields(certEntrySize, uint16(len(keyLabelBytes)))
		if err := binary.Write(&buf, binary.BigEndian, certHeader); err != nil {
			return nil, err
		}
		if _, err := buf.Write(keyLabelBytes); err != nil {
			return nil, err
		}
		if _, err := buf.Write(cert.Cert); err != nil {
			return nil, err
		}
	}

	// 5. CWT certificate objects
	for _, cwtCert := range persoBlob.CwtCerts {
		keyLabelBytes := []byte(cwtCert.KeyLabel)
		certEntrySize := uint16(sizeOfCertHeader + len(keyLabelBytes) + len(cwtCert.Cert))
		objSize := uint16(sizeOfObjectHeader) + certEntrySize
		header := setObjectHeaderFields(objSize, PersoObjectTypeCwtCert)
		if err := binary.Write(&buf, binary.BigEndian, header); err != nil {
			return nil, err
		}

		certHeader := setCertHeaderFields(certEntrySize, uint16(len(keyLabelBytes)))
		if err := binary.Write(&buf, binary.BigEndian, certHeader); err != nil {
			return nil, err
		}
		if _, err := buf.Write(keyLabelBytes); err != nil {
			return nil, err
		}
		if _, err := buf.Write(cwtCert.Cert); err != nil {
			return nil, err
		}
	}

	// 6. Seed objects
	for _, seed := range persoBlob.Seeds {
		objSize := uint16(sizeOfObjectHeader + len(seed.Raw))
		header := setObjectHeaderFields(objSize, seed.Type)
		if err := binary.Write(&buf, binary.BigEndian, header); err != nil {
			return nil, err
		}
		if _, err := buf.Write(seed.Raw); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}
