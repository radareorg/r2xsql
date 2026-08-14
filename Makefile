# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
# Copyright (c) 2024-2026 Elias Bachaalany
#
# r2xsql — in-r2 plugin (core_r2xsql) build, radare2-native style.
#
# This is the radare2-conventional build for the *plugin only* (the in-process
# `sql` command radare2 loads). It mirrors the layout radare2 plugins use:
# plugin paths come from `r2 -H`, radare2 itself from `pkg-config r_core`.
# CMake remains the primary/full build (CLI flavors, tests, MCP, Windows) — see
# README.md; this Makefile exists so the plugin can be built and installed the
# radare2 way, with no CMake required.
#
#   make               build build-make/core_r2xsql.$(R2_LIBEXT)
#   make user-install  install into the per-user plugin dir (no root)
#   make install       install system-wide (R2_LIBR_PLUGINS)
#   make test          build, then load the plugin in r2 and run one SQL query
#   make clean
#
# Requires: a C++20 compiler, radare2 with pkg-config (`pkg-config r_core`),
# and libxsql (auto-used from ../libxsql, else cloned into build-make/libxsql).

# The radare2 driver. Most installs expose both `r2` and `radare2`; override
# with `make R2=radare2` if only the long name is on PATH.
R2?=r2
R2_LIBEXT=$(shell $(R2) -H R2_LIBEXT)
R2_USER_PLUGINS=$(shell $(R2) -H R2_USER_PLUGINS)
R2_LIBR_PLUGINS=$(shell $(R2) -H R2_LIBR_PLUGINS)

CXX?=g++
CC?=gcc
CWD=$(shell pwd)
BUILD=build-make

# --- libxsql: sibling checkout by default, else fetched into build-make/ ------
LIBXSQL_DIR?=../libxsql
LIBXSQL_URL?=https://github.com/0xeb/libxsql.git
ifeq ($(wildcard $(LIBXSQL_DIR)/CMakeLists.txt),)
  LIBXSQL_DIR:=$(BUILD)/libxsql
endif

# --- radare2 (in-process libr backend) ----------------------------------------
R2_CFLAGS=$(shell pkg-config --cflags r_core)
R2_LDFLAGS=$(shell pkg-config --libs r_core)

# --- include paths ------------------------------------------------------------
XSQL_INC=-I$(LIBXSQL_DIR)/include \
         -I$(LIBXSQL_DIR)/external/sqlite \
         -I$(LIBXSQL_DIR)/external/nlohmann/include \
         -I$(LIBXSQL_DIR)/external/httplib
R2XSQL_INC=-I$(CWD)/src/lib/include -I$(CWD)/src/lib/src -I$(CWD)/src

# --- defines ------------------------------------------------------------------
# R2XSQL_HAVE_LIBR=1  -> compile the in-process libr backend (real, not stub).
# XSQL_HAS_THINCLIENT -> libxsql's httplib path (header-only), matches CMake FORCE.
# XSQL_VERSION_STRING -> libxsql's --version string. Derived from libxsql's own
# CMakeLists at build time so it always follows whatever libxsql main is at —
# no pinned value here (r2xsql tracks libxsql main). Override with
# `make XSQL_VERSION=x` only if you must.
# (pattern has no '(' on purpose: an unbalanced paren inside $(shell ...) makes
# GNU make read it as an unterminated call.)
XSQL_VERSION = $(shell grep -m1 'libxsql VERSION' "$(LIBXSQL_DIR)/CMakeLists.txt" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
DEFS=-DR2XSQL_HAVE_LIBR=1 -DXSQL_HAS_THINCLIENT -DXSQL_VERSION_STRING=\"$(XSQL_VERSION)\"
SQLITE_DEFS=-DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_RTREE -DSQLITE_ENABLE_JSON1 \
            -DSQLITE_ENABLE_COLUMN_METADATA

CXXFLAGS+=-std=c++20 -fPIC -O2 -Wall $(R2_CFLAGS) $(XSQL_INC) $(R2XSQL_INC) $(DEFS)
CFLAGS+=-fPIC -O2 $(SQLITE_DEFS) -I$(LIBXSQL_DIR)/external/sqlite
LDFLAGS+=$(R2_LDFLAGS) -lpthread -lm -ldl

PLUGIN=$(BUILD)/core_r2xsql.$(R2_LIBEXT)
PLUGDIR?=$(R2_LIBR_PLUGINS)

# --- sources ------------------------------------------------------------------
# All of src/lib/src/*.cpp is the full (libr) plugin set: the 43 core adapters
# plus backend_libr.cpp + direct_libr.cpp (guarded by R2XSQL_HAVE_LIBR).
R2XSQL_SRCS=$(wildcard src/lib/src/*.cpp)
R2XSQL_OBJS=$(patsubst src/lib/src/%.cpp,$(BUILD)/obj/r2xsql/%.o,$(R2XSQL_SRCS))
XSQL_SRCS=$(wildcard $(LIBXSQL_DIR)/src/*.cpp)
XSQL_OBJS=$(patsubst $(LIBXSQL_DIR)/src/%.cpp,$(BUILD)/obj/xsql/%.o,$(XSQL_SRCS))
SQLITE_OBJ=$(BUILD)/obj/sqlite/sqlite3.o
PLUGIN_OBJ=$(BUILD)/obj/plugin/core_r2xsql.o

OBJS=$(SQLITE_OBJ) $(XSQL_OBJS) $(R2XSQL_OBJS) $(PLUGIN_OBJ)

all: $(PLUGIN)

-include $(BUILD)/libxsql.mk

# libxsql fetch (only if the sibling is absent and we redirected into build-make)
$(LIBXSQL_DIR)/CMakeLists.txt:
	@echo "libxsql not found at ../libxsql -- cloning $(LIBXSQL_URL)"
	git clone --depth 1 $(LIBXSQL_URL) $(LIBXSQL_DIR)

$(BUILD)/libxsql.mk: $(LIBXSQL_DIR)/CMakeLists.txt
	@mkdir -p $(dir $@)
	@touch $@

$(BUILD)/obj/sqlite/sqlite3.o: $(LIBXSQL_DIR)/external/sqlite/sqlite3.c | $(LIBXSQL_DIR)/CMakeLists.txt
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/obj/xsql/%.o: $(LIBXSQL_DIR)/src/%.cpp | $(LIBXSQL_DIR)/CMakeLists.txt
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/obj/r2xsql/%.o: src/lib/src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/obj/plugin/core_r2xsql.o: src/plugin/core_r2xsql.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(PLUGIN): $(OBJS)
	$(CXX) -shared -o $@ $(OBJS) $(LDFLAGS)
ifneq (,$(wildcard /usr/bin/codesign))
	-codesign -f -s - $(PLUGIN)
endif

install: $(PLUGIN)
	mkdir -p "$(DESTDIR)$(PLUGDIR)"
	rm -f "$(DESTDIR)$(PLUGDIR)/core_r2xsql.$(R2_LIBEXT)"
	cp -f $(PLUGIN) "$(DESTDIR)$(PLUGDIR)/core_r2xsql.$(R2_LIBEXT)"
ifneq (,$(wildcard /usr/bin/codesign))
	-codesign -f -s - "$(DESTDIR)$(PLUGDIR)/core_r2xsql.$(R2_LIBEXT)"
endif

uninstall:
	rm -f "$(DESTDIR)$(PLUGDIR)/core_r2xsql.$(R2_LIBEXT)"

user-install:
	$(MAKE) install PLUGDIR="$(R2_USER_PLUGINS)"

user-uninstall:
	$(MAKE) uninstall PLUGDIR="$(R2_USER_PLUGINS)"

# Smoke test: load the freshly built plugin and run one query.
test: $(PLUGIN)
	@echo "=== loading core_r2xsql and running a SQL query ==="
	$(R2) -i "$(CWD)/$(PLUGIN)" -qc 'aa; sql SELECT count(*) AS n FROM funcs' -- /bin/ls

clean:
	rm -rf $(BUILD)/obj $(PLUGIN)

mrproper: clean
	rm -rf $(BUILD)

.PHONY: all install uninstall user-install user-uninstall test clean mrproper
