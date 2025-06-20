# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

"""hsmtool command templates."""

HSMTOOL_CONST = struct(
    ECC_CURVE = struct(
        PRIME256V1 = "1.2.840.10045.3.1.7",
        SECP384R1 = "1.3.132.0.34",
    ),
)

def _filename_key_pub(label):
    """Creates a filename key for public keys."""
    return "pub/" + label + ".pem"

def _filename_wrapped_key(label):
    """Creates a filename key for wrapped keys."""
    return "hsm/" + label + ".wrapped.bin"

def hsmtool_pk11_attrs(attrs = {}):
    """Creates a PKCS#11 attribute template.

    Args:
        attrs: A dictionary of attributes to include in the template.
    """
    return json.encode_indent(attrs)

def hsmtool_aes_keygen(label, template = {}):
    """Creates a key generation template for AES keys.

    Args:
        label: The label for the key.
        template: The template for the key.
    """
    return json.encode_indent({
        "command": "aes-generate",
        "label": label,
        "template": template,
    })

def hsmtool_aes_import(label, unwrap, unwrap_mechanism, template = {}):
    """Creates an import template for AES keys.

    Args:
        label: The label for the key.
        unwrap: Unwrapping key label.
        unwrap_mechanism: The mechanism used for unwrapping.
        template: The template for the key.
    """
    return json.encode_indent({
        "command": "aes-import",
        "label": label,
        "unwrap": unwrap,
        "unwrap_mechanism": unwrap_mechanism,
        "template": template,
        "filename": _filename_wrapped_key(label),
    })

def hsmtool_aes_export(label, wrap, wrap_mechanism):
    """Creates an export template for AES keys.

    Args:
        label: The label for the key.
        wrap: Wrapping key label.
        wrap_mechanism: The mechanism used for wrapping.
    """
    return json.encode_indent({
        "command": "aes-export",
        "label": label,
        "wrap": wrap,
        "wrap_mechanism": wrap_mechanism,
        "output": _filename_wrapped_key(label),
    })

def hsmtool_ecdsa_keygen(label, curve, wrapping, extractable, public_template = {}, private_template = {}):
    """Creates a key generation template for ECDSA keys.

    Args:
        label: The label for the key.
        curve: The curve for the key.
        wrapping: Whether the key is used for wrapping.
        extractable: Whether the key is extractable.
        public_template: The public template for the key.
        private_template: The private template for the key.
    """
    return json.encode_indent({
        "command": "ecdsa-generate",
        "label": label,
        "curve": curve,
        "wrapping": wrapping,
        "extractable": extractable,
        "public_template": public_template,
        "private_template": private_template,
    })

def hsmtool_ecdsa_export_pub(label):
    """Creates a public key export template for ECDSA keys.

    Args:
        label: The label for the key.
    """
    return json.encode_indent({
        "command": "ecdsa-export",
        "label": label,
        "private": False,
        "format": "Pem",
        "filename": _filename_key_pub(label),
    })

def hsmtool_ecdsa_export_priv(label, wrap, wrap_mechanism):
    """Creates a private key export template for ECDSA keys.

    Args:
        label: The label for the key.
        wrap: Wrapping key label.
        wrap_mechanism: The mechanism used for wrapping.
    """
    return json.encode_indent({
        "command": "ecdsa-export",
        "label": label,
        "private": True,
        "format": "Der",
        "wrap": wrap,
        "wrap_mechanism": wrap_mechanism,
        "filename": _filename_wrapped_key(label),
    })

def hsmtool_ecdsa_import_priv(label, unwrap, unwrap_mechanism, private_attrs = {}):
    """Creates an import template for ECDSA keys.

    Args:
        label: The label for the key.
        unwrap: Unwrap key label.
        unwrap_mechanism: The mechanism used for unwrapping.
        private_attrs: The private attributes for the key.
    """
    return json.encode_indent({
        "command": "ecdsa-import",
        "label": label,
        "public": False,
        "unwrap": unwrap,
        "unwrap_mechanism": unwrap_mechanism,
        "private_attrs": private_attrs,
        "filename": _filename_wrapped_key(label),
    })

def hsmtool_ecdsa_import_pub(label, public_attrs = {}):
    """Creates a public key import template for ECDSA keys.

    Args:
        label: The label for the key.
        public_attrs: The public attributes for the key.
    """
    return json.encode_indent({
        "command": "ecdsa-import",
        "label": label,
        "public": True,
        "filename": _filename_key_pub(label),
        "public_attrs": public_attrs,
    })

def hsmtool_generic_keygen(label, template = {}):
    """Creates a key generation template for generic keys.

    Args:
        label: The label for the key.
        template: The template for the key.
    """
    return json.encode_indent({
        "command": "kdf-generate",
        "label": label,
        "template": template,
    })

def hsmtool_generic_export(label, wrap, wrap_mechanism):
    """Creates an export template for generic keys.

    Args:
        label: The label for the key.
        wrap: Wrapping key label.
        wrap_mechanism: The mechanism used for wrapping.
    """
    return json.encode_indent({
        "command": "kdf-export",
        "label": label,
        "wrap": wrap,
        "wrap_mechanism": wrap_mechanism,
        "output": _filename_wrapped_key(label),
    })

def hsmtool_generic_import(label, unwrap, unwrap_mechanism, template = {}):
    """Creates an import template for generic keys.

    Args:
        label: The label for the key.
        unwrap: Unwrap key label.
        unwrap_mechanism: The mechanism used for unwrapping.
        template: The template for the key.
    """
    return json.encode_indent({
        "command": "kdf-import",
        "label": label,
        "unwrap": unwrap,
        "unwrap_mechanism": unwrap_mechanism,
        "template": template,
        "filename": _filename_wrapped_key(label),
    })

def hsmtool_rsa_keygen(label, key_length, public_exponent, wrapping, extractable, public_template = {}, private_template = {}):
    """Creates a key generation template for RSA keys.

    Args:
        label: The label for the key.
        key_length: The length of the key.
        public_exponent: The public exponent for the key.
        wrapping: Whether the key is used for wrapping.
        extractable: Whether the key is extractable.
        public_template: The public template for the key.
        private_template: The private template for the key.
    """
    return json.encode({
        "command": "rsa-generate",
        "label": label,
        "key_length": key_length,
        "public_exponent": public_exponent,
        "wrapping": wrapping,
        "extractable": extractable,
        "public_template": public_template,
        "private_template": private_template,
    })

def hsmtool_rsa_export_pub(label):
    """Creates a public key export template for RSA keys.

    Args:
        label: The label for the key.
    """
    return json.encode_indent({
        "command": "rsa-export",
        "label": label,
        "private": False,
        "format": "Pem",
        "filename": _filename_key_pub(label),
    })

def hsmtool_rsa_import_pub(label, public_attrs = {}):
    """Creates a public key import template for RSA keys.

    Args:
        label: The label for the key.
        public_attrs: The public attributes for the key.
    """
    return json.encode_indent({
        "command": "rsa-import",
        "label": label,
        "public": True,
        "filename": _filename_key_pub(label),
        "public_attrs": public_attrs,
    })

def hsmtool_object_destroy(label):
    """Creates a command to destroy an object in the HSM.

    Args:
        label: The label for the object.
    """
    return json.encode_indent({
        "command": "object-destroy",
        "label": label,
    })

def hsmtool_object_show(label):
    """Creates a command to show an object in the HSM.

    Args:
        label: The label for the object.
    """
    return json.encode_indent({
        "command": "object-show",
        "label": label,
        "redact": True,
    })
