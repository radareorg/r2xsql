# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
# Copyright (c) 2024-2026 Elias Bachaalany
#
# r2xsql -- in-r2 plugin (core_r2xsql) build, meson flavour.
#
# Follows the conventional radare2 plugin layout: a shared_module named
# core_r2xsql, installed into radare2's own plugin dir (queried from
# `radare2 -HR2_LIBR_PLUGINS`), built
# against `pkg-config r_core`. Both build systems now produce the SAME single
# artifact -- there are no CLI flavors and no MCP any more. CMake remains the
# primary build (it also drives the test suites and is what Windows uses);
# this path exists because r2's ecosystem, and r2pm, build with meson.
#
# libxsql (r2xsql's SQL core) is consumed as a meson subproject: the wrap in
# subprojects/ fetches it and a packagefiles/ overlay supplies the meson.build,
# so no CMake is required for this path. Build with:
#
#   meson setup build-meson
#   meson compile -C build-meson
#   meson install -C build-meson        # into R2_LIBR_PLUGINS
#   meson install -C build-meson --destdir=... or -Dr2_user_plugins=true

project('r2xsql', ['c', 'cpp'],
  license: 'LicenseRef-Human-Origin-Source-1.0',
  meson_version: '>=0.55.0',
  version: '0.0.1',
  default_options: ['cpp_std=c++20', 'c_std=c11', 'warning_level=1'])

# --- radare2 plugin dir, straight from r2 itself ------------------------------
r2 = find_program('radare2', 'r2', required: true)
if get_option('r2_user_plugins')
  res = run_command(r2, '-HR2_USER_PLUGINS', capture: true, check: false)
else
  res = run_command(r2, '-HR2_LIBR_PLUGINS', capture: true, check: false)
endif
if res.returncode() == 0 and res.stdout().strip() != ''
  r2_plugdir = res.stdout().strip()
else
  r2_plugdir = get_option('prefix') / 'lib' / 'radare2' / 'plugins'
endif
message('core_r2xsql will install to: ' + r2_plugdir)

# --- dependencies -------------------------------------------------------------
r_core  = dependency('r_core')
threads = dependency('threads')
xsql_dep = subproject('libxsql').get_variable('xsql_dep')

# --- r2xsql core (all of src/lib/src is the full/libr plugin set) -------------
# The 42 core table adapters plus backend_libr.cpp + direct_libr.cpp, which are
# gated by R2XSQL_HAVE_LIBR (=1 here: this build is the in-process libr flavor).
r2xsql_srcs = files(
  'src/lib/src/backend_common.cpp',
  'src/lib/src/backend_libr.cpp',
  'src/lib/src/backend_mock.cpp',
  'src/lib/src/backend_r2pipe.cpp',
  'src/lib/src/direct_libr.cpp',
  'src/lib/src/json_utils.cpp',
  'src/lib/src/session.cpp',
  'src/lib/src/tables_assemble.cpp',
  'src/lib/src/tables_binary.cpp',
  'src/lib/src/tables_bininfo.cpp',
  'src/lib/src/tables_blocks.cpp',
  'src/lib/src/tables_bookmarks.cpp',
  'src/lib/src/tables_byte_search.cpp',
  'src/lib/src/tables_bytes.cpp',
  'src/lib/src/tables_calling_conventions.cpp',
  'src/lib/src/tables_cfg_edges.cpp',
  'src/lib/src/tables_classes.cpp',
  'src/lib/src/tables_comments.cpp',
  'src/lib/src/tables_data_items.cpp',
  'src/lib/src/tables_decompiler.cpp',
  'src/lib/src/tables_demangle.cpp',
  'src/lib/src/tables_esil.cpp',
  'src/lib/src/tables_exports.cpp',
  'src/lib/src/tables_flags.cpp',
  'src/lib/src/tables_funcs.cpp',
  'src/lib/src/tables_function_frames.cpp',
  'src/lib/src/tables_graph_tables.cpp',
  'src/lib/src/tables_grep.cpp',
  'src/lib/src/tables_imports.cpp',
  'src/lib/src/tables_instructions.cpp',
  'src/lib/src/tables_io_maps.cpp',
  'src/lib/src/tables_libs.cpp',
  'src/lib/src/tables_locals.cpp',
  'src/lib/src/tables_operands.cpp',
  'src/lib/src/tables_patches.cpp',
  'src/lib/src/tables_projects.cpp',
  'src/lib/src/tables_read_cstr.cpp',
  'src/lib/src/tables_registers.cpp',
  'src/lib/src/tables_relocs.cpp',
  'src/lib/src/tables_rop.cpp',
  'src/lib/src/tables_runtime_settings.cpp',
  'src/lib/src/tables_sections.cpp',
  'src/lib/src/tables_segments.cpp',
  'src/lib/src/tables_strings.cpp',
  'src/lib/src/tables_switch_tables.cpp',
  'src/lib/src/tables_syscalls.cpp',
  'src/lib/src/tables_types.cpp',
  'src/lib/src/tables_types_members.cpp',
  'src/lib/src/tables_xrefs.cpp',
  'src/lib/src/version.cpp',
  'src/lib/src/views_shared.cpp',
)
plugin_src = files('src/plugin/core_r2xsql.cpp')

r2xsql_inc = include_directories('src/lib/include', 'src/lib/src', 'src')

shared_module('core_r2xsql',
  [r2xsql_srcs, plugin_src],
  name_prefix: '',
  cpp_args: ['-DR2XSQL_HAVE_LIBR=1'],
  include_directories: r2xsql_inc,
  dependencies: [xsql_dep, r_core, threads],
  install: true,
  install_dir: r2_plugdir)
