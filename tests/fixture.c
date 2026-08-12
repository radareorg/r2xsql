/* Copyright (c) 2024-2026 Elias Bachaalany
 * SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
 *
 * This file is licensed under the Human-Origin Source License v1.0.
 * See LICENSE.
 *
 * Deterministic, license-clean fixture for the r2xsql test-suite: a few
 * named functions (one calling another, so xrefs/callers/callees are
 * non-empty) plus a unique string marker, so the tests in this directory
 * have stable, predictable data to assert against. Portable C (no libc
 * beyond stdio/string), built at test time by test_support.py.
 */

#include <stdio.h>
#include <string.h>

const char *r2xsql_marker = "r2xsql_test_marker_string";

int r2xsql_add(int a, int b) {
    return a + b;
}

int r2xsql_mul(int a, int b) {
    return a * b;
}

int r2xsql_compute(int x) {
    int acc = 0;
    int i;
    for (i = 0; i < x; i++) {
        acc = r2xsql_add(acc, r2xsql_mul(i, 2));
    }
    return acc;
}

int main(int argc, char **argv) {
    printf("%s: %d\n", r2xsql_marker, r2xsql_compute(argc));
    if (argc > 1 && !strcmp(argv[1], "x")) {
        return r2xsql_add(1, 2);
    }
    return 0;
}
