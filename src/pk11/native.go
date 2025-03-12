// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// package native is a cgo wrapper for reaching into the C API of a PKCS#11
// module when package pkcs11 does not provide a useable interface.
package native

import (
	"unsafe"

	"github.com/miekg/pkcs11"
)

/*
// We don't depend on a full pkcs11.h; instead, we redefine things as we need
// them, because the definitions are set in stone by the standard.

#include <stdlib.h> // For calloc() and free().

typedef unsigned char CK_BYTE;
typedef CK_BYTE* CK_BYTE_PTR;

typedef unsigned char CK_BBOOL;
typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;

struct CK_MECHANISM {
  CK_MECHANISM_TYPE mech;
  void* param;
  CK_ULONG len;
};

struct CK_ATTRIBUTE {
  CK_ATTRIBUTE_TYPE attr;
  void* param;
  CK_ULONG len;
};

typedef struct CK_MECHANISM* CK_MECHANISM_PTR;
typedef struct CK_ATTRIBUTE* CK_ATTRIBUTE_PTR;
typedef CK_OBJECT_HANDLE* CK_OBJECT_HANDLE_PTR;

#define kDeriveKeyOffset 63
typedef CK_RV (*CK_C_DeriveKey)(
  CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
  CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);

struct CK_HKDF_PARAMS {
  CK_BBOOL extract, expand;
  CK_MECHANISM_TYPE hash;
  CK_ULONG salt_type;
  void* salt;
  CK_ULONG salt_len;
  CK_OBJECT_HANDLE salt_key;
  void* info;
  CK_ULONG info_len;
};

// The following definitions are from the Luna HSM PKCS#11 module.
// See: https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/mechanisms/CKM_NIST_PRF_KDF.html
// for more information.


// PRF KDF schemes
#define CK_NIST_PRF_KDF_DES3_CMAC      0x00000001
#define CK_NIST_PRF_KDF_AES_CMAC       0x00000002
#define CK_PRF_KDF_ARIA_CMAC           0x00000003
#define CK_PRF_KDF_SEED_CMAC           0x00000004
#define CK_NIST_PRF_KDF_HMAC_SHA1      0x00000005
#define CK_NIST_PRF_KDF_HMAC_SHA224    0x00000006
#define CK_NIST_PRF_KDF_HMAC_SHA256    0x00000007
#define CK_NIST_PRF_KDF_HMAC_SHA384    0x00000008
#define CK_NIST_PRF_KDF_HMAC_SHA512    0x00000009
#define CK_PRF_KDF_HMAC_RIPEMD160      0x0000000A

// PRF KDF encoding schemes
// SCHEME_1:      Counter (4 bytes) || Context || 0x00             || Label            || Length
// SCHEME_2:      Counter (4 bytes) || Context || Label            ||                  ||
// SCHEME_3:      Counter (4 bytes) || Label   || 0x00             || Context          || Length
// SCHEME_4:      Counter (4 bytes) || Label   || Context          ||                  ||
// SCHEME_SCP03:  Label             || 0x00    || Length (2 bytes) || Counter (1 byte) || Context
// SCHEME_HID_KD: Counter (1 byte)  || Label   || 0x00             || Context          || Length (2 bytes)
#define LUNA_PRF_KDF_ENCODING_SCHEME_1      0x00000000
#define LUNA_PRF_KDF_ENCODING_SCHEME_2      0x00000001
#define LUNA_PRF_KDF_ENCODING_SCHEME_3      0x00000002
#define LUNA_PRF_KDF_ENCODING_SCHEME_4      0x00000003
#define LUNA_PRF_KDF_ENCODING_SCHEME_SCP03  0x00000004
#define LUNA_PRF_KDF_ENCODING_SCHEME_HID_KD 0x00000005

struct CK_KDF_PRF_PARAMS {
CK_ULONG prfType;
void*    pLabel;
CK_ULONG ulLabelLen;
void*    pContext;
CK_ULONG ulContextLen;
CK_ULONG ulCounter;
CK_ULONG ulEncodingScheme;
};

struct ctx {
  void* handle;
  void** vtable;
};

CK_RV RawDeriveKey(struct ctx** c, CK_SESSION_HANDLE session,
		CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE basekey,
		CK_ATTRIBUTE_PTR attrs, CK_ULONG attr_count, CK_OBJECT_HANDLE_PTR newkey)
{
  void* fn = (**c).vtable[kDeriveKeyOffset];
  return ((CK_C_DeriveKey)fn)(session, mech, basekey, attrs, attr_count, newkey);
}
*/
import "C"

// RawMech is a non-owning reference to a mechanism whose parameter may be
// allocated on the C heap.
type RawMech struct {
	typ   C.CK_MECHANISM_TYPE
	param unsafe.Pointer
	len   C.CK_ULONG
}

const (
	// CKMVendorDefined is a Go representation of CKM_VENDOR_DEFINED.
	CKMVendorDefined = 0x80000000
	// KDFPRFMechanismType is a Go representation of CK_NIST_PRF_KDF.
	// CKM_VENDOR_DEFINED + 0xA02
	KDFPRFMechanismType = CKMVendorDefined + 0xA02
)

// KDFPRFScheme is a Go representation of the available PRF KDF schemes.
type KDFPRFScheme uint

const (
	KDFPRFSchemeDES3CMAC      KDFPRFScheme = C.CK_NIST_PRF_KDF_DES3_CMAC
	KDFPRFSchemeAESCMAC                    = C.CK_NIST_PRF_KDF_AES_CMAC
	KDFPRFSchemeARIACMAC                   = C.CK_PRF_KDF_ARIA_CMAC
	KDFPRFSchemeSEEDCMAC                   = C.CK_PRF_KDF_SEED_CMAC
	KDFPRFSchemeHMACSHA1                   = C.CK_NIST_PRF_KDF_HMAC_SHA1
	KDFPRFSchemeHMACSHA224                 = C.CK_NIST_PRF_KDF_HMAC_SHA224
	KDFPRFSchemeHMACSHA256                 = C.CK_NIST_PRF_KDF_HMAC_SHA256
	KDFPRFSchemeHMACSHA384                 = C.CK_NIST_PRF_KDF_HMAC_SHA384
	KDFPRFSchemeHMACSHA512                 = C.CK_NIST_PRF_KDF_HMAC_SHA512
	KDFPRFSchemeHMACRIPEMD160              = C.CK_PRF_KDF_HMAC_RIPEMD160
)

// KDFPRFEncodingScheme is a Go representation of CK_PRF_KDF_ENCODING_SCHEME.
type KDFPRFEncodingScheme uint

const (
	KDFPRFEncodingScheme1     KDFPRFEncodingScheme = C.LUNA_PRF_KDF_ENCODING_SCHEME_1
	KDFPRFEncodingScheme2                          = C.LUNA_PRF_KDF_ENCODING_SCHEME_2
	KDFPRFEncodingScheme3                          = C.LUNA_PRF_KDF_ENCODING_SCHEME_3
	KDFPRFEncodingScheme4                          = C.LUNA_PRF_KDF_ENCODING_SCHEME_4
	KDFPRFEncodingSchemeSCP03                      = C.LUNA_PRF_KDF_ENCODING_SCHEME_SCP03
	KDFPRFEncodingSchemeHIDKD                      = C.LUNA_PRF_KDF_ENCODING_SCHEME_HID_KD
)

// KDFPRFParams is a Go representation of CK_KDF_PRF_PARAMS.
type KDFPRFParams struct {
	Scheme         KDFPRFScheme
	Label          []byte
	Context        []byte
	Counter        uint
	EncodingScheme KDFPRFEncodingScheme

	raw *C.struct_CK_KDF_PRF_PARAMS
}

// MakeRawMech allocates (and caches) a CK_KDF_PRF_PARAMS containing copies of
// data in the Go fields, and returns it wrapped in a RawMech.
//
// It must be freed with Free().
func (p *KDFPRFParams) MakeRawMech() RawMech {
	if p.raw != nil {
		goto done
	}

	p.raw = (*C.struct_CK_KDF_PRF_PARAMS)(C.calloc(C.sizeof_struct_CK_KDF_PRF_PARAMS, 1))
	if p.raw == nil {
		panic("calloc() returned nil")
	}

	*p.raw = C.struct_CK_KDF_PRF_PARAMS{
		prfType:          C.CK_ULONG(p.Scheme),
		ulLabelLen:       C.CK_ULONG(len(p.Label)),
		ulContextLen:     C.CK_ULONG(len(p.Context)),
		ulCounter:        C.CK_ULONG(p.Counter),
		ulEncodingScheme: C.CK_ULONG(p.EncodingScheme),
	}

	if len(p.Label) > 0 {
		p.raw.pLabel = C.CBytes(p.Label)
		p.raw.ulLabelLen = C.CK_ULONG(len(p.Label))
	}
	if len(p.Context) > 0 {
		p.raw.pContext = C.CBytes(p.Context)
		p.raw.ulContextLen = C.CK_ULONG(len(p.Context))
	}

done:
	return RawMech{
		typ:   C.CK_MECHANISM_TYPE(KDFPRFMechanismType),
		param: unsafe.Pointer(p.raw),
		len:   C.CK_ULONG(C.sizeof_struct_CK_KDF_PRF_PARAMS),
	}
}

// Frees memory allocated with MakeRawMech.
func (p *KDFPRFParams) Free() {
	if p.raw == nil {
		return
	}

	C.free(p.raw.pLabel)
	C.free(p.raw.pContext)
	C.free(unsafe.Pointer(p.raw))
	p.raw = nil
}

// HKDFParams is a Go representation of CK_HKDF_PARAMS.
type HKDFParams struct {
	Extract, Expand bool
	Hash            uint
	SaltType        uint
	Salt            []byte
	SaltKey         pkcs11.ObjectHandle
	Info            []byte

	raw *C.struct_CK_HKDF_PARAMS
}

// MakeRawMech allocates (and caches) a CK_HKDF_PARAM containing copies of
// data in the Go fields, and returns it wrapped in a RawMech.
//
// It must be freed with Free().
func (p *HKDFParams) MakeRawMech(mech uint) RawMech {
	if p.raw != nil {
		goto done
	}

	// This is calloc() to avoid Go getting confused from witnessing uninitialized
	// memory.
	p.raw = (*C.struct_CK_HKDF_PARAMS)(C.calloc(C.sizeof_struct_CK_HKDF_PARAMS, 1))
	if p.raw == nil {
		panic("calloc() returned nil")
	}

	*p.raw = C.struct_CK_HKDF_PARAMS{
		hash:      C.CK_MECHANISM_TYPE(p.Hash),
		salt_type: C.CK_ULONG(p.SaltType),
		salt_key:  C.CK_OBJECT_HANDLE(p.SaltKey),
	}

	if p.Extract {
		p.raw.extract = 1
	}
	if p.Expand {
		p.raw.expand = 1
	}

	if len(p.Salt) > 0 {
		p.raw.salt = C.CBytes(p.Salt)
		p.raw.salt_len = C.CK_ULONG(len(p.Salt))
	}
	if len(p.Info) > 0 {
		p.raw.info = C.CBytes(p.Info)
		p.raw.info_len = C.CK_ULONG(len(p.Info))
	}

done:
	return RawMech{
		typ:   C.CK_MECHANISM_TYPE(mech),
		param: unsafe.Pointer(p.raw),
		len:   C.CK_ULONG(C.sizeof_struct_CK_HKDF_PARAMS),
	}
}

// Frees memory allocated with MakeRawMech.
func (p *HKDFParams) Free() {
	if p.raw == nil {
		return
	}

	C.free(p.raw.salt)
	C.free(p.raw.info)
	C.free(unsafe.Pointer(p.raw))
	p.raw = nil
}

// copyAttrs creates a copy of attrs in the ABI expected by Cryptoki, living on
// the C heap.
//
// The returned memory will not be gc'd; use freeAttrs() to free it.
func copyAttrs(attrs []*pkcs11.Attribute) C.CK_ATTRIBUTE_PTR {
	ptr := C.calloc(C.size_t(len(attrs)), C.sizeof_struct_CK_ATTRIBUTE)
	if ptr == nil {
		panic("calloc() returned nil")
	}

	for i, attr := range attrs {
		offset := C.sizeof_struct_CK_ATTRIBUTE * C.size_t(i)
		cAttr := (*C.struct_CK_ATTRIBUTE)(unsafe.Pointer(uintptr(ptr) + uintptr(offset)))

		var value unsafe.Pointer
		if len(attr.Value) > 0 {
			value = C.CBytes(attr.Value)
		}
		*cAttr = C.struct_CK_ATTRIBUTE{
			attr:  C.CK_ATTRIBUTE_TYPE(attr.Type),
			param: value,
			len:   C.CK_ULONG(len(attr.Value)),
		}
	}
	return C.CK_ATTRIBUTE_PTR(ptr)
}

// freeAttrs frees memory allocated by copyAttrs.
func freeAttrs(attrs C.CK_ATTRIBUTE_PTR, count C.size_t) {
	ptr := unsafe.Pointer(attrs)
	for i := C.size_t(0); i < count; i++ {
		offset := C.sizeof_struct_CK_ATTRIBUTE * C.size_t(i)
		cAttr := (*C.struct_CK_ATTRIBUTE)(unsafe.Pointer(uintptr(ptr) + uintptr(offset)))
		C.free(cAttr.param)
	}
	C.free(unsafe.Pointer(attrs))
}

// RawDeriveKey performs a raw call to C_DeriveKey using a raw mechanism.
//
// This function is intended to support key derivation with mechanisms that
// package pkcs11 does not support.
func RawDeriveKey(ctx *pkcs11.Ctx, sess pkcs11.SessionHandle, basekey pkcs11.ObjectHandle, mech RawMech, attrs []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	cAttrs := copyAttrs(attrs)
	defer freeAttrs(cAttrs, C.size_t(len(attrs)))

	cMech := C.struct_CK_MECHANISM{
		mech:  mech.typ,
		param: mech.param,
		len:   mech.len,
	}

	var obj C.CK_OBJECT_HANDLE
	rv := C.RawDeriveKey(
		(**C.struct_ctx)(unsafe.Pointer(ctx)),
		C.CK_SESSION_HANDLE(sess),
		(*C.struct_CK_MECHANISM)(unsafe.Pointer(&cMech)),
		C.CK_OBJECT_HANDLE(basekey),
		cAttrs,
		C.CK_ULONG(len(attrs)),
		(*C.CK_OBJECT_HANDLE)(unsafe.Pointer(&obj)))

	if rv != 0 {
		return 0, pkcs11.Error(rv)
	}
	return pkcs11.ObjectHandle(obj), nil
}
