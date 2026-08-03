# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0

CMAKE ?= cmake
BUILD_DIR ?= build
BUILD_TYPE ?= Release

R2 ?= radare2
R2_PREFIX ?= $(shell "$(R2)" -H R2_PREFIX 2>/dev/null)
R2_LIBR_PLUGINS ?= $(shell "$(R2)" -H R2_LIBR_PLUGINS 2>/dev/null)
R2_USER_PLUGINS ?= $(shell "$(R2)" -H R2_USER_PLUGINS 2>/dev/null)

PLUGIN_EXT ?= so
PLUGIN := core_r2sql.$(PLUGIN_EXT)
PLUGIN_PATH ?= $(BUILD_DIR)/bin/$(PLUGIN)
SYSTEM_PLUGDIR := $(DESTDIR)$(R2_LIBR_PLUGINS)

R2SQL_WITH_MCP ?= ON
CMAKE_FLAGS := \
	-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
	-DR2SQL_BUILD_CLI=ON \
	-DR2SQL_BUILD_PLUGIN=ON \
	-DR2SQL_BUILD_EXAMPLES=OFF \
	-DR2SQL_BUILD_FULL=ON \
	-DR2SQL_WITH_MCP=$(R2SQL_WITH_MCP) \
	-DFASTMCPP_BUILD_TESTS=OFF \
	-DRadare2_ROOT="$(R2_PREFIX)"

.PHONY: all build configure plugin install install-symlink symstall user-install uninstall user-uninstall deinstall clean distclean mrproper test help

all: plugin

build: configure
	$(CMAKE) --build "$(BUILD_DIR)" --config $(BUILD_TYPE)

configure:
	$(CMAKE) -S . -B "$(BUILD_DIR)" $(CMAKE_FLAGS) $(CMAKE_EXTRA_FLAGS)

plugin: build
	@test -f "$(PLUGIN_PATH)" || { echo "error: $(PLUGIN_PATH) was not built" >&2; exit 1; }

symstall: plugin
	install -d "$(SYSTEM_PLUGDIR)"
	ln -sf "$(abspath $(PLUGIN_PATH))" "$(SYSTEM_PLUGDIR)/$(PLUGIN)"

install-symlink: symstall

install: PLUGDIR := $(SYSTEM_PLUGDIR)
user-install: PLUGDIR := $(R2_USER_PLUGINS)
install user-install: plugin
	install -d "$(PLUGDIR)"
	install -m 755 "$(PLUGIN_PATH)" "$(PLUGDIR)/$(PLUGIN)"

uninstall: PLUGDIR := $(SYSTEM_PLUGDIR)
user-uninstall: PLUGDIR := $(R2_USER_PLUGINS)
uninstall user-uninstall:
	@test -n "$(PLUGDIR)" && rm -f "$(PLUGDIR)/$(PLUGIN)"

deinstall: uninstall

clean:
	rm -rf "$(BUILD_DIR)"

distclean:
	rm -rf "$(BUILD_DIR)"

mrproper: distclean

test: build
	$(CMAKE) --build "$(BUILD_DIR)" --target test --config $(BUILD_TYPE);
