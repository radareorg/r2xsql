# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
# Copyright (c) 2024-2026 Elias Bachaalany
#
# r2xsql — in-r2 plugin (core_r2xsql) build, radare2-native style.
#
# This is the radare2-conventional build for the *plugin only* (the in-process
# `sql` command radare2 loads). It mirrors the layout radare2 plugins use:
# plugin paths come from `r2 -H`, radare2 itself from `pkg-config r_core`.
# CMake remains the library and cross-platform build (including Windows) — see
# README.md; this Makefile exists so the plugin can be built and installed the
# radare2 way, with no CMake required.
#
#   make               build build-make/core_r2xsql.$(R2_LIBEXT)
#   make user-install  install into the per-user plugin dir (no root)
#   make install       install system-wide (R2_LIBR_PLUGINS)
#   make test          build, then run the r2r regression suite
#   make clean
#
# Requires: a C++20 compiler, radare2 with pkg-config (`pkg-config r_core`),
# and libxsql (auto-used from ../libxsql, else cloned into build-make/libxsql).

# The radare2 driver. Most installs expose both `r2` and `radare2`; override
# with `make R2=radare2` if only the long name is on PATH.
R2?=r2
R2R?=r2r
R2_LIBEXT=$(shell $(R2) -NN -H R2_LIBEXT)
R2_USER_PLUGINS=$(shell $(R2) -NN -H R2_USER_PLUGINS)
R2_LIBR_PLUGINS=$(shell $(R2) -NN -H R2_LIBR_PLUGINS)

CXX?=g++
CC?=gcc
CWD=$(shell pwd)
BUILD=build-make

# --- libxsql: sibling checkout by default, else fetched into build-make/ ------
LIBXSQL_DIR?=../libxsql
LIBXSQL_URL?=https://github.com/0xeb/libxsql.git
LIBXSQL_REF?=v1.0.21
ifeq ($(wildcard $(LIBXSQL_DIR)/CMakeLists.txt),)
  LIBXSQL_DIR:=$(BUILD)/libxsql
endif

# --- radare2 (in-process libr backend) ----------------------------------------
R2_CFLAGS=$(shell pkg-config --cflags r_core)
R2_LDFLAGS=$(shell pkg-config --libs r_core)

# --- include paths ------------------------------------------------------------
XSQL_INC=-I$(LIBXSQL_DIR)/include \
         -I$(LIBXSQL_DIR)/external/sqlite \
         -I$(LIBXSQL_DIR)/external/nlohmann/include
R2XSQL_INC=-I$(CWD)/src/lib/include -I$(CWD)/src/lib/src -I$(CWD)/src

# --- defines ------------------------------------------------------------------
# R2XSQL_HAVE_LIBR=1  -> compile the in-process libr backend (real, not stub).
# XSQL_VERSION_STRING -> libxsql's --version string. Derived from libxsql's own
# CMakeLists at build time, so it follows the libxsql checkout in use (the
# pinned LIBXSQL_REF when fetched). Override with
# `make XSQL_VERSION=x` only if you must.
# (pattern has no '(' on purpose: an unbalanced paren inside $(shell ...) makes
# GNU make read it as an unterminated call.)
XSQL_VERSION = $(shell grep -m1 'libxsql VERSION' "$(LIBXSQL_DIR)/CMakeLists.txt" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
DEFS=-DR2XSQL_HAVE_LIBR=1 -DXSQL_VERSION_STRING=\"$(XSQL_VERSION)\"
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

# Removing files must not fetch or rebuild dependencies via included makefiles.
ifneq ($(filter-out clean mrproper uninstall user-uninstall,$(or $(MAKECMDGOALS),all)),)
-include $(BUILD)/libxsql.mk
-include $(OBJS:.o=.d)
endif

.DELETE_ON_ERROR:

# libxsql fetch (only if the sibling is absent and we redirected into build-make)
$(LIBXSQL_DIR)/CMakeLists.txt:
	@echo "libxsql not found at ../libxsql -- cloning $(LIBXSQL_URL)"
	git clone --depth 1 --branch $(LIBXSQL_REF) $(LIBXSQL_URL) $(LIBXSQL_DIR)

$(BUILD)/libxsql.mk: $(LIBXSQL_DIR)/CMakeLists.txt
	@mkdir -p $(dir $@)
	@touch $@

# Rebuild legacy objects without .d files when this Makefile is updated.
$(BUILD)/obj/sqlite/sqlite3.o: $(LIBXSQL_DIR)/external/sqlite/sqlite3.c Makefile | $(LIBXSQL_DIR)/CMakeLists.txt
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD)/obj/xsql/%.o: $(LIBXSQL_DIR)/src/%.cpp Makefile | $(LIBXSQL_DIR)/CMakeLists.txt
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(BUILD)/obj/r2xsql/%.o: src/lib/src/%.cpp Makefile
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(BUILD)/obj/plugin/core_r2xsql.o: src/plugin/core_r2xsql.cpp Makefile
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

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

# Check output as well as process status: r2 can exit 0 after an SQL exception.
test: $(PLUGIN)
	$(MAKE) -C tests R2="$(R2)" R2R="$(R2R)" R2XSQL_PLUGIN="$(abspath $(PLUGIN))"

clean:
	rm -rf $(BUILD)/obj $(PLUGIN)

mrproper: clean
	rm -rf $(BUILD)

.PHONY: all install uninstall user-install user-uninstall test clean mrproper
