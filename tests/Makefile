# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
R2?=r2
R2R?=r2r
R2XSQL_PLUGIN?=../build-make/core_r2xsql.$(shell $(R2) -H R2_LIBEXT)
R2R_ARGS?=-L
TESTS?=db
CC?=cc

all: test

build/fixture.bin: fixture.c Makefile
	@mkdir -p build
	$(CC) -O0 -g $< -o $@

# Explicit loading works with r2r's -NN and ignores installed user plugins.
# Regenerate when switching build directories, even if the plugin is older.
load:
	@test -f "$(R2XSQL_PLUGIN)" || { echo "Plugin not found: $(R2XSQL_PLUGIN)"; exit 1; }
	@mkdir -p build
	@printf 'L %s\n' "$(abspath $(R2XSQL_PLUGIN))" > build/load.r2

test: build/fixture.bin load
	R2R_RADARE2="$(R2)" R2XSQL_PLUGIN="$(abspath $(R2XSQL_PLUGIN))" $(R2R) -u $(R2R_ARGS) -C . $(TESTS)

clean:
	rm -rf build

.PHONY: all test load clean
