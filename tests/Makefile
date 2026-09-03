# r2xsql's shipped test suite, run by radare2's own r2r.
#
#   make            build the fixture and run every test
#   make clean      remove the built fixture
#
# The plugin has to be loadable. Either install core_r2xsql into radare2's
# plugin directory, or point at a build tree:
#
#   make R2XSQL_PLUGIN_DIR=/path/to/build/bin
#
# The tests live under db/extras/ deliberately: r2r runs radare2 with -NN and
# R2_NOPLUGINS unless a test's path contains an "extras" component, and
# without plugins there is no `sql` command to test. That is also why they are
# named explicitly on the r2r command line -- r2r skips extras directories
# during plain recursion.

CC   ?= cc
R2R  ?= r2r
FIXTURE = build/fixture.bin

ifdef R2XSQL_PLUGIN_DIR
R2R_ENV = R2_LIBR_PLUGINS=$(R2XSQL_PLUGIN_DIR)
endif

all: test

$(FIXTURE): fixture.c
	@mkdir -p build
	$(CC) -O0 -g -o $@ fixture.c

test: $(FIXTURE)
	$(R2R_ENV) $(R2R) -u -L -C . db/extras/cmd

clean:
	rm -rf build

.PHONY: all test clean
