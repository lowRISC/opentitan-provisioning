# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

"""Rules for HSM provisioning."""

load("@bazel_skylib//lib:shell.bzl", "shell")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")
load(
    "//rules:hsmtool.bzl",
    "hsmtool_aes_export",
    "hsmtool_aes_import",
    "hsmtool_aes_keygen",
    "hsmtool_ecdsa_export_priv",
    "hsmtool_ecdsa_export_pub",
    "hsmtool_ecdsa_import_priv",
    "hsmtool_ecdsa_import_pub",
    "hsmtool_ecdsa_keygen",
    "hsmtool_generic_export",
    "hsmtool_generic_import",
    "hsmtool_generic_keygen",
    "hsmtool_object_destroy",
    "hsmtool_pk11_attrs",
    "hsmtool_rsa_export_pub",
    "hsmtool_rsa_import_pub",
    "hsmtool_rsa_keygen",
)

KeyTemplateInfo = provider(
    """HSM key template information.

    This provider is used to generate HSM key templates for HSM operations.
    """,
    fields = {
        "type": "Key type identifier, valied values are 'aes', 'generic', 'ecdsa' and 'rsa'.",
        "label": "Key label.",
        "label_pub": "Public key label.",
        "label_priv": "Private key label.",
        "keygen_params": "hsmtool key generation parameters.",
        "export_public_only": "Set to true to export only the public key.",
        "wrapping_mechanism": "Mechanism used to wrap the key.",
        "wrapping_key": "Key used to wrap the key.",
        "import_template": "Template used to import the key.",
        "import_template_private": "Template used to import the private key.",
        "import_template_public": "Template used to import the public key.",
        "hsmtool_cmds": "Generated hsmtool commands.",
    },
)

def _key_label(kp):
    """Returns the key label from the keygen_params dictionary.

    Args:
        kp: keygen_params dictionary.
    """
    if "label" in kp:
        return kp["label"]
    fail("Unable to find key label in keygen_params.")

def _key_label_pub(kp):
    """Returns the public key label from the key information.

    Args:
        kp: keygen_params dictionary.
    """
    if "public_template" in kp:
        if "CKA_LABEL" in kp["public_template"]:
            return kp["public_template"]["CKA_LABEL"]
    return _key_label(kp)

def _key_label_priv(kp):
    """Returns the private key label from the key information.

    Args:
        kp: keygen_params dictionary.
    """
    if "private_template" in kp:
        if "CKA_LABEL" in kp["private_template"]:
            return kp["private_template"]["CKA_LABEL"]
    return _key_label(kp)

def _hsm_key_template_aes(ctx, keygen_params, import_template = {}):
    """Creates a key template for AES keys.

    Args:
        ctx: The rule context.
        keygen_params: The key generation parameters.
        import_template: The import template.
    """
    label = _key_label(keygen_params)

    if "template" not in keygen_params:
        fail("Key generation parameters must contain a template.")

    if not ctx.attr.wrapping_key:
        fail("Wrapping key must be specified.")

    hsmtool_cmds = {
        "keygen": hsmtool_aes_keygen(
            label = label,
            template = keygen_params["template"],
        ),
        "import": hsmtool_aes_import(
            label = label,
            unwrap = ctx.attr.wrapping_key[KeyTemplateInfo].label_priv,
            unwrap_mechanism = ctx.attr.wrapping_mechanism,
            template = import_template,
        ),
        "export": hsmtool_aes_export(
            label = label,
            wrap = ctx.attr.wrapping_key[KeyTemplateInfo].label_pub,
            wrap_mechanism = ctx.attr.wrapping_mechanism,
        ),
        "destroy": hsmtool_object_destroy(label),
    }

    return KeyTemplateInfo(
        type = "aes",
        label = label,

        # Generic keys do not have public/private labels; however, we
        # need to provide them for the KeyTemplateInfo provider so that
        # the key can be used in wrapping commands.
        label_pub = label,
        label_priv = label,
        keygen_params = keygen_params,
        export_public_only = ctx.attr.export_public_only,
        wrapping_mechanism = ctx.attr.wrapping_mechanism,
        wrapping_key = ctx.attr.wrapping_key,
        import_template = import_template,
        import_template_private = {},
        import_template_public = {},
        hsmtool_cmds = hsmtool_cmds,
    )

def _hsm_key_template_generic(ctx, keygen_params, import_template = {}):
    """Creates a key template for generic keys.

    Args:
        ctx: The rule context.
        keygen_params: The key generation parameters.
        import_template: The import template.
    """
    label = _key_label(keygen_params)

    if "template" not in keygen_params:
        fail("Key generation parameters must contain a template.")

    if not ctx.attr.wrapping_key:
        fail("Wrapping key must be specified.")

    hsmtool_cmds = {
        "keygen": hsmtool_generic_keygen(
            label = label,
            template = keygen_params["template"],
        ),
        "import": hsmtool_generic_import(
            label = label,
            unwrap = ctx.attr.wrapping_key[KeyTemplateInfo].label_priv,
            unwrap_mechanism = ctx.attr.wrapping_mechanism,
            template = import_template,
        ),
        "export": hsmtool_generic_export(
            label = label,
            wrap = ctx.attr.wrapping_key[KeyTemplateInfo].label_pub,
            wrap_mechanism = ctx.attr.wrapping_mechanism,
        ),
        "destroy": hsmtool_object_destroy(label),
    }

    return KeyTemplateInfo(
        type = "kdf",
        label = label,

        # Generic keys do not have public/private labels; however, we
        # need to provide them for the KeyTemplateInfo provider so that
        # the key can be used in wrapping commands.
        label_pub = label,
        label_priv = label,
        keygen_params = keygen_params,
        export_public_only = ctx.attr.export_public_only,
        wrapping_mechanism = ctx.attr.wrapping_mechanism,
        wrapping_key = ctx.attr.wrapping_key,
        import_template = import_template,
        import_template_private = {},
        import_template_public = {},
        hsmtool_cmds = hsmtool_cmds,
    )

def _hsm_key_template_ecdsa(ctx, keygen_params, import_template_private = {}, import_template_public = {}):
    """Creates a key template for ECDSA keys.

    Args:
        ctx: The rule context.
        keygen_params: The key generation parameters.
        import_template_private: The private import template.
        import_template_public: The public import template.
    """
    label = _key_label(keygen_params)
    label_pub = _key_label_pub(keygen_params)
    label_priv = _key_label_priv(keygen_params)

    for param in [
        "curve",
        "extractable",
        "private_template",
        "public_template",
        "wrapping",
    ]:
        if param not in keygen_params:
            fail("Key generation parameters must contain a %s." % param)

    hsmtool_cmds = {
        "keygen": hsmtool_ecdsa_keygen(
            label = label,
            curve = keygen_params["curve"],
            extractable = keygen_params["extractable"],
            private_template = keygen_params["private_template"],
            public_template = keygen_params["public_template"],
            wrapping = keygen_params["wrapping"],
        ),
        "import_pub": hsmtool_ecdsa_import_pub(
            label = label_pub,
            public_attrs = import_template_public,
        ),
        "export_pub": hsmtool_ecdsa_export_pub(label_pub),
        "destroy": hsmtool_object_destroy(label),
    }

    if not ctx.attr.export_public_only:
        hsmtool_cmds["import_priv"] = hsmtool_ecdsa_import_priv(
            label = label_priv,
            unwrap = ctx.attr.wrapping_key[KeyTemplateInfo].label_priv,
            unwrap_mechanism = ctx.attr.wrapping_mechanism,
            private_attrs = import_template_private,
        )
        hsmtool_cmds["export_priv"] = hsmtool_ecdsa_export_priv(
            label = label_priv,
            wrap = ctx.attr.wrapping_key[KeyTemplateInfo].label_pub,
            wrap_mechanism = ctx.attr.wrapping_mechanism,
        )

    return KeyTemplateInfo(
        type = "ecdsa",
        label = label,
        label_pub = label_pub,
        label_priv = label_priv,
        keygen_params = keygen_params,
        export_public_only = ctx.attr.export_public_only,
        wrapping_mechanism = ctx.attr.wrapping_mechanism,
        wrapping_key = ctx.attr.wrapping_key,
        import_template = {},
        import_template_private = import_template_private,
        import_template_public = import_template_public,
        hsmtool_cmds = hsmtool_cmds,
    )

def _hsm_key_template_rsa(ctx, keygen_params, import_template_private = {}, import_template_public = {}):
    """Creates a key template for RSA keys.

    Args:
        ctx: The rule context.
        keygen_params: The key generation parameters.
        import_template_private: The private import template.
        import_template_public: The public import template.
    """
    label = _key_label(keygen_params)
    label_pub = _key_label_pub(keygen_params)
    label_priv = _key_label_priv(keygen_params)

    for param in [
        "extractable",
        "key_length",
        "private_template",
        "public_exponent",
        "public_template",
        "wrapping",
    ]:
        if param not in keygen_params:
            fail("Key generation parameters must contain a %s." % param)

    hsmtool_cmds = {
        "keygen": hsmtool_rsa_keygen(
            label = label,
            key_length = keygen_params["key_length"],
            public_exponent = keygen_params["public_exponent"],
            extractable = keygen_params["extractable"],
            private_template = keygen_params["private_template"],
            public_template = keygen_params["public_template"],
            wrapping = keygen_params["wrapping"],
        ),
        "import_pub": hsmtool_rsa_import_pub(
            label = label_pub,
            public_attrs = import_template_public,
        ),
        "export_pub": hsmtool_rsa_export_pub(label_pub),
        "destroy": hsmtool_object_destroy(label),
    }

    if not ctx.attr.export_public_only:
        hsmtool_cmds["import_priv"] = hsmtool_ecdsa_import_priv(
            label = label_priv,
            unwrap = ctx.attr.wrapping_key[KeyTemplateInfo].label_priv,
            unwrap_mechanism = ctx.attr.wrapping_mechanism,
            private_attrs = import_template_private,
        )
        hsmtool_cmds["export_priv"] = hsmtool_ecdsa_export_priv(
            label = label_priv,
            wrap = ctx.attr.wrapping_key[KeyTemplateInfo].label_label_pub,
            wrap_mechanism = ctx.attr.wrapping_mechanism,
        )

    return KeyTemplateInfo(
        type = "rsa",
        label = label,
        label_pub = _key_label_pub(keygen_params),
        label_priv = _key_label_priv(keygen_params),
        keygen_params = keygen_params,
        export_public_only = ctx.attr.export_public_only,
        wrapping_mechanism = ctx.attr.wrapping_mechanism,
        wrapping_key = ctx.attr.wrapping_key,
        import_template = {},
        import_template_private = import_template_private,
        import_template_public = import_template_public,
        hsmtool_cmds = hsmtool_cmds,
    )

def _hsm_key_template(ctx):
    """Creates a key template for HSM provisioning.

    Args:
        ctx: The rule context.
    """
    if ctx.attr.wrapping_mechanism and not ctx.attr.wrapping_key:
        fail("Wrapping key must be specified if wrapping mechanism is specified.")

    keygen_params = json.decode(ctx.attr.keygen_params)

    if ctx.attr.import_template:
        import_template = json.decode(ctx.attr.import_template)
    else:
        import_template = {}

    if ctx.attr.import_template_private:
        import_template_private = json.decode(ctx.attr.import_template_private)
    else:
        import_template_private = {}

    if ctx.attr.import_template_public:
        import_template_public = json.decode(ctx.attr.import_template_public)
    else:
        import_template_public = {}

    if ctx.attr.type == "aes":
        return _hsm_key_template_aes(
            ctx,
            keygen_params,
            import_template,
        )
    elif ctx.attr.type == "generic":
        return _hsm_key_template_generic(
            ctx,
            keygen_params,
            import_template,
        )
    elif ctx.attr.type == "ecdsa":
        return _hsm_key_template_ecdsa(
            ctx,
            keygen_params,
            import_template_private,
            import_template_public,
        )
    elif ctx.attr.type == "rsa":
        return _hsm_key_template_rsa(
            ctx,
            keygen_params,
            import_template_private,
            import_template_public,
        )
    else:
        fail("Invalid key type: %s" % ctx.attr.type)

hsm_key_template = rule(
    implementation = _hsm_key_template,
    attrs = {
        "type": attr.string(
            mandatory = True,
            values = ["aes", "generic", "ecdsa", "rsa"],
        ),
        "export_public_only": attr.bool(
            default = False,
        ),
        "keygen_params": attr.string(
            mandatory = True,
        ),
        "wrapping_mechanism": attr.string(
            values = [
                "AesKeyWrap",
                "RsaPkcs",
                "RsaPkcsOaep",
                "VendorThalesAesKwp",
            ],
        ),
        "wrapping_key": attr.label(
            providers = [KeyTemplateInfo],
        ),
        "import_template": attr.string(),
        "import_template_private": attr.string(),
        "import_template_public": attr.string(),
    },
)

CertGenInfo = provider(
    """Provides information for certificate generation.

    This provider is used to generate certificates associated with HSM keys.
    """,
    fields = {
        "key": "Key to endorse in the certificate.",
        "config": "Certificate template.",
        "ca_key": "Key to sign the certificate.",
        "root_cert": "Set to true to generate a root (i.e. self-signed) certificate.",
    },
)

def _hsm_certgen(ctx):
    """Creates a certificate generation template for HSM provisioning.

    Args:
        ctx: The rule context.
    """
    if not ctx.attr.root_cert and not ctx.attr.ca_key:
        fail("CA key must be specified if non-root certificate is generated.")

    if ctx.attr.ca_key:
        ca_key = ctx.attr.ca_key[KeyTemplateInfo].label_priv
    else:
        ca_key = ctx.attr.key[KeyTemplateInfo].label_priv

    return CertGenInfo(
        key = ctx.attr.key[KeyTemplateInfo].label_priv,
        config = ctx.file.config.basename,
        ca_key = ca_key,
        root_cert = ctx.attr.root_cert,
    )

hsm_certgen = rule(
    implementation = _hsm_certgen,
    attrs = {
        "key": attr.label(
            mandatory = True,
            providers = [KeyTemplateInfo],
        ),
        "config": attr.label(
            mandatory = True,
            allow_single_file = True,
        ),
        "ca_key": attr.label(
            default = None,
            providers = [KeyTemplateInfo],
        ),
        "root_cert": attr.bool(
            default = False,
        ),
    },
)

def _destroy_command(key):
    """Creates a command to destroy a key in the HSM.

    Args:
        key: The key to destroy.
    """
    if "destroy" not in key.hsmtool_cmds:
        fail("Key %s does not have a destroy command." % key.label)
    return json.decode(key.hsmtool_cmds["destroy"])

def _process_command(key, command):
    """Creates a command to process a key in the HSM.

    Args:
        key: The key to process.
        command: The command to process the key.
    """
    if command not in key.hsmtool_cmds:
        fail("Key %s does not have a %s command." % (key.label, command))

    return json.decode(key.hsmtool_cmds[command])

def _hsmtool_genscripts(ctx):
    """Generates the hsmtool scripts.

    Args:
        ctx: The rule context.
    """
    up_hson_file = ctx.actions.declare_file(ctx.label.name + "_up.hjson")
    down_hjson_file = ctx.actions.declare_file(ctx.label.name + "_down.hjson")

    up_dict = []
    down_dict = []
    for key, command in ctx.attr.hsmtool_sequence.items():
        key = key[KeyTemplateInfo]

        # Filter invalid commands.
        if command == "destroy":
            fail("Destroy command should not be used in the sequence.")

        # Update down command sequence.
        if command in ["keygen", "import"]:
            down_dict.append(_destroy_command(key))

        # Update up command sequence.
        if command == "import" and key.type in ["ecdsa", "rsa"]:
            if "import_pub" in key.hsmtool_cmds:
                up_dict.append(_process_command(key, "import_pub"))
            if "import_priv" in key.hsmtool_cmds:
                up_dict.append(_process_command(key, "import_priv"))

        elif command == "export" and key.type in ["ecdsa", "rsa"]:
            if "export_pub" in key.hsmtool_cmds:
                up_dict.append(_process_command(key, "export_pub"))
            if "export_priv" in key.hsmtool_cmds:
                up_dict.append(_process_command(key, "export_priv"))

            # Process all other commands.
        else:
            up_dict.append(_process_command(key, command))

    ctx.actions.write(
        output = up_hson_file,
        content = json.encode_indent(up_dict),
    )
    ctx.actions.write(
        output = down_hjson_file,
        content = json.encode_indent(down_dict),
    )
    return up_hson_file, down_hjson_file

def _hsm_config_script_impl(ctx):
    out_file = ctx.actions.declare_file(ctx.label.name + ".bash")
    up_hson_file, down_hjson_file = _hsmtool_genscripts(ctx)

    substitutions = {
        "@@INIT_HJSON@@": shell.quote(up_hson_file.basename),
        "@@DESTROY_HJSON@@": shell.quote(down_hjson_file.basename),
        "@@HSMTOOL_BIN@@": shell.quote(ctx.executable._hsmtool.basename),
    }

    ctx.actions.expand_template(
        template = ctx.file._runner_general,
        output = out_file,
        substitutions = substitutions,
        is_executable = True,
    )

    outfiles = [
        ctx.executable._hsmtool,
        up_hson_file,
        down_hjson_file,
    ]

    return DefaultInfo(
        runfiles = ctx.runfiles(files = outfiles),
        executable = out_file,
    )

hsm_config_script = rule(
    implementation = _hsm_config_script_impl,
    attrs = {
        "hsmtool_sequence": attr.label_keyed_string_dict(
            mandatory = True,
        ),
        "_runner_general": attr.label(
            default = "//rules/scripts:hsmtool_runner.template.sh",
            allow_single_file = True,
        ),
        "_hsmtool": attr.label(
            default = "@lowrisc_opentitan//sw/host/hsmtool",
            allow_single_file = True,
            cfg = "exec",
            executable = True,
        ),
    },
    executable = True,
)

def hsm_config_tar(name, hsmtool_sequence, **kwargs):
    """Creates a tarball with the HSM configuration.

    Args:
        name: The name of the tarball.
        hsmtool_sequence: The sequence of commands to run.
        **kwargs: Additional attributes to pass to the rule.
    """
    hsm_config_script(
        name = name,
        hsmtool_sequence = hsmtool_sequence,
        **kwargs
    )
    pkg_tar(
        name = name + "_pkg",
        srcs = [
            ":" + name,
        ],
        extension = "tar.gz",
        include_runfiles = True,
    )

def _certgen_params(ctx):
    """Returns the certificate generation parameters.

    This function processes the certificate generation parameters
    and returns the templates, keys, and endorsing keys.

    Root certificates are added before non-root certificates, this
    is to ensure that the root certificate is always generated first.

    Args:
        ctx: The rule context.
    """
    templates, keys, endorsing_keys = [], [], []

    # First pass: Add root certs.
    for cg in ctx.attr.certs:
        cg = cg[CertGenInfo]
        if not cg.root_cert:
            continue
        templates.append(shell.quote(cg.config))
        keys.append(shell.quote(cg.key))
        endorsing_keys.append(shell.quote(cg.ca_key))

    # Second pass: Add non-root certs.
    for cg in ctx.attr.certs:
        cg = cg[CertGenInfo]
        if cg.root_cert:
            continue
        templates.append(shell.quote(cg.config))
        keys.append(shell.quote(cg.key))
        endorsing_keys.append(shell.quote(cg.ca_key))

    return templates, keys, endorsing_keys

def _hsm_certgen_script_impl(ctx):
    """Generates the certificate generation script.

    Args:
        ctx: The rule context.
    """
    out_file = ctx.actions.declare_file(ctx.label.name + ".bash")
    templates, keys, endorsing_keys = _certgen_params(ctx)

    substitutions = {
        "@@CERTGEN_TEMPLATES@@": " ".join(templates),
        "@@CERTGEN_KEYS@@": " ".join(keys),
        "@@CERTGEN_ENDORSING_KEYS@@": " ".join(endorsing_keys),
    }

    ctx.actions.expand_template(
        template = ctx.file._runner_ca_sign,
        output = out_file,
        substitutions = substitutions,
        is_executable = True,
    )

    return DefaultInfo(
        executable = out_file,
    )

hsm_certgen_script = rule(
    implementation = _hsm_certgen_script_impl,
    attrs = {
        "certs": attr.label_list(
            mandatory = True,
            providers = [CertGenInfo],
        ),
        "_runner_ca_sign": attr.label(
            default = "//rules/scripts:hsm_ca_sign.sh",
            allow_single_file = True,
        ),
    },
    executable = True,
)

def hsm_certgen_tar(name, certs, **kwargs):
    """Creates a tarball with the certificate generation script.

    Args:
        name: The name of the tarball.
        certs: The certificate generation parameters.
        **kwargs: Additional attributes to pass to the rule.
    """
    hsm_certgen_script(
        name = name,
        certs = certs,
        **kwargs
    )
    pkg_tar(
        name = name + "_pkg",
        srcs = [
            ":" + name,
        ],
        extension = "tar.gz",
        include_runfiles = True,
    )

def hsm_spm_wrapping_key(name):
    """Creates a wrapping key for SPM.

    Args:
        name: The name of the wrapping key.
    """
    hsm_key_template(
        name = name,
        export_public_only = True,
        import_template_public = hsmtool_pk11_attrs({
            "CKA_ENCRYPT": True,
            "CKA_VERIFY": True,
            "CKA_WRAP": True,
            "CKA_TOKEN": True,
        }),
        keygen_params = hsmtool_rsa_keygen(
            extractable = False,
            key_length = 3072,
            label = name,
            private_template = {
                "CKA_CLASS": "CKO_PRIVATE_KEY",
                "CKA_LABEL": name + ".priv",
                "CKA_DECRYPT": True,
                "CKA_SIGN": True,
                "CKA_TOKEN": True,
                "CKA_SENSITIVE": True,
            },
            public_exponent = 65537,
            public_template = {
                "CKA_CLASS": "CKO_PUBLIC_KEY",
                "CKA_LABEL": name + ".pub",
                "CKA_ENCRYPT": True,
                "CKA_VERIFY": True,
                "CKA_TOKEN": True,
            },
            wrapping = True,
        ),
        type = "rsa",
    )

def hsm_spm_identity_key(name, curve):
    """Creates an identity key for SPM.

    Args:
        name: The name of the identity key.
        curve: The curve to use for the key.
    """
    hsm_key_template(
        name = name,
        export_public_only = True,
        import_template_public = hsmtool_pk11_attrs({
            "CKA_VERIFY": True,
            "CKA_TOKEN": True,
        }),
        keygen_params = hsmtool_ecdsa_keygen(
            curve = curve,
            extractable = False,
            label = name,
            private_template = {
                "CKA_LABEL": name + ".priv",
                "CKA_SIGN": True,
                "CKA_TOKEN": True,
                "CKA_EXTRACTABLE": False,
            },
            public_template = {
                "CKA_LABEL": name + ".pub",
                "CKA_VERIFY": True,
                "CKA_TOKEN": True,
            },
            wrapping = False,
        ),
        type = "ecdsa",
    )

def hsm_sku_wrapping_key(name, wrapping_key, wrapping_mechanism):
    """Creates a wrapping key for SKU.

    Args:
        name: The name of the wrapping key.
        wrapping_key: The key used to wrap the key.
        wrapping_mechanism: The mechanism used to wrap the key.
    """

    # TODO(moidx): Remove WRAP and ENCRYPT from import template
    # once `hsmtool` is updated to support querying based on
    # unwrap attributes.
    hsm_key_template(
        name = name,
        import_template = hsmtool_pk11_attrs({
            "CKA_DECRYPT": True,
            "CKA_ENCRYPT": True,
            "CKA_SENSITIVE": True,
            "CKA_TOKEN": True,
            "CKA_UNWRAP": True,
            "CKA_WRAP": True,
            "CKA_EXTRACTABLE": False,
        }),
        keygen_params = hsmtool_aes_keygen(
            label = name,
            template = {
                "CKA_ENCRYPT": True,
                "CKA_DECRYPT": True,
                "CKA_WRAP": True,
                "CKA_UNWRAP": True,
                "CKA_SENSITIVE": True,
                "CKA_EXTRACTABLE": True,
                "CKA_TOKEN": True,
            },
        ),
        type = "aes",
        wrapping_key = wrapping_key,
        wrapping_mechanism = wrapping_mechanism,
    )

def hsm_sku_rma_key(name):
    """Creates an RMA token wrapping key for SKU.

    Args:
        name: The name of the wrapping key.
    """
    hsm_key_template(
        name = name,
        export_public_only = True,
        import_template_public = hsmtool_pk11_attrs({
            "CKA_ENCRYPT": True,
            "CKA_TOKEN": True,
            "CKA_WRAP": True,
        }),
        keygen_params = hsmtool_rsa_keygen(
            extractable = False,
            key_length = 3072,
            label = name,
            private_template = {
                "CKA_CLASS": "CKO_PRIVATE_KEY",
                "CKA_LABEL": name + ".priv",
                "CKA_DECRYPT": True,
                "CKA_SIGN": False,
                "CKA_TOKEN": True,
                "CKA_EXTRACTABLE": False,
            },
            public_exponent = 65537,
            public_template = {
                "CKA_CLASS": "CKO_PUBLIC_KEY",
                "CKA_LABEL": name + ".pub",
                "CKA_ENCRYPT": True,
                "CKA_VERIFY": False,
                "CKA_TOKEN": True,
            },
            wrapping = True,
        ),
        type = "rsa",
    )

def hsm_certificate_authority_root(name, curve):
    """Creates a root certificate authority key.

    Args:
        name: The name of the certificate authority key.
        curve: The curve to use for the key.
    """
    hsm_key_template(
        name = name,
        export_public_only = True,
        keygen_params = hsmtool_ecdsa_keygen(
            curve = curve,
            extractable = False,
            label = name,
            private_template = {
                "CKA_LABEL": name + ".priv",
                "CKA_SIGN": True,
                "CKA_TOKEN": True,
                "CKA_EXTRACTABLE": False,
                "CKA_SENSITIVE": True,
            },
            public_template = {
                "CKA_LABEL": name + ".pub",
                "CKA_VERIFY": True,
                "CKA_TOKEN": True,
            },
            wrapping = False,
        ),
        type = "ecdsa",
    )

def hsm_certificate_authority_intermediate(name, curve):
    hsm_key_template(
        name = name,
        export_public_only = True,
        import_template_public = hsmtool_pk11_attrs({
            "CKA_VERIFY": True,
            "CKA_TOKEN": True,
        }),
        keygen_params = hsmtool_ecdsa_keygen(
            curve = curve,
            extractable = False,
            label = name,
            private_template = {
                "CKA_LABEL": name + ".priv",
                "CKA_SIGN": True,
                "CKA_TOKEN": True,
                "CKA_EXTRACTABLE": False,
                "CKA_SENSITIVE": True,
            },
            public_template = {
                "CKA_LABEL": name + ".pub",
                "CKA_VERIFY": True,
                "CKA_TOKEN": True,
            },
            wrapping = False,
        ),
        type = "ecdsa",
    )

def hsm_generic_secret(name, wrapping_key, wrapping_mechanism):
    """Creates a generic secret key.

    Args:
        name: The name of the generic secret key.
        wrapping_key: The key used to wrap the key.
        wrapping_mechanism: The mechanism used to wrap the key.
    """
    hsm_key_template(
        name = name,
        import_template = hsmtool_pk11_attrs({
            "CKA_DERIVE": True,
            "CKA_SENSITIVE": True,
            "CKA_SIGN": True,
            "CKA_TOKEN": True,
            "CKA_EXTRACTABLE": False,
        }),
        keygen_params = hsmtool_generic_keygen(
            label = name,
            template = {
                "CKA_DERIVE": True,
                "CKA_SENSITIVE": True,
                "CKA_EXTRACTABLE": True,
                "CKA_TOKEN": True,
            },
        ),
        type = "generic",
        wrapping_key = wrapping_key,
        wrapping_mechanism = wrapping_mechanism,
    )
