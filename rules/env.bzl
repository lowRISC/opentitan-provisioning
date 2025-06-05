# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

"""Rules for environment substitution."""

def _envsubst_impl(ctx):
    """Implementation of the envsubst rule."""
    template = ctx.file.template
    env_config = ctx.file.env_config

    # Get the output filename from the template basename
    out_name = template.basename.replace(".tmpl", "")

    # Create the output file
    out = ctx.actions.declare_file(out_name)

    # Create the command
    ctx.actions.run_shell(
        outputs = [out],
        inputs = [template, env_config],
        command = """
            set -a
            source {env_config}
            set +a
            envsubst < {template} > {out}
        """.format(
            env_config = env_config.path,
            template = template.path,
            out = out.path,
        ),
    )

    return [DefaultInfo(files = depset([out]))]

envsubst = rule(
    implementation = _envsubst_impl,
    attrs = {
        "template": attr.label(
            mandatory = True,
            allow_single_file = [".tmpl"],
            doc = "Template file to process",
        ),
        "env_config": attr.label(
            mandatory = True,
            allow_single_file = True,
            doc = "Environment configuration file",
        ),
    },
    doc = "Rule to generate files using envsubst with environment variables",
)

def envsubst_template(name, template):
    """Generate a list of configuration files with environment substitution.

    This macro uses default values for dev and prod environments.

    Args:
        name: Must be 'sku'
        template: The template file to use for the configuration.
    """
    envsubst(
        name = name,
        template = template,
        env_config = select({
            "//:dev_env": "//config/env/dev:spm.env",
            "//:prod_env": "//config/env/prod:spm.env",
            "//conditions:default": "//config/env/dev:spm.env",
        }),
    )
