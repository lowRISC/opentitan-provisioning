#!/usr/bin/env bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

case "$MODE" in
    diff)
        echo "$FILES" | xargs ${lint_tool} -s -d
        exit $?
        ;;
    fix)
        echo "$FILES" | xargs ${lint_tool} -s -w
        ;;
    *)
        echo "Unknown mode: $MODE"
        exit 2
esac
