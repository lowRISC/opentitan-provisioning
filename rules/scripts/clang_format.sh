#!/usr/bin/env bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

case "$MODE" in
    diff)
        RESULT=0
        for f in $FILES; do
            diff -Naur "$f" <(${lint_tool} ${f})
            RESULT=$(($RESULT | $?))
        done
        exit $RESULT
        ;;
    fix)
        echo "$FILES" | xargs ${lint_tool} -i
        ;;
    *)
        echo "Unknown mode: $MODE"
        exit 2
esac
