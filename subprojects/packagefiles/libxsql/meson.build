# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
# meson overlay for libxsql (which is CMake-native upstream). Applied via the
# libxsql.wrap patch_directory so the r2xsql meson build can consume libxsql
# without CMake. Mirrors libxsql/CMakeLists.txt: the xsql static lib over the
# vendored sqlite3 amalgamation + header-only nlohmann.
project('libxsql', ['c', 'cpp'],
  meson_version: '>=0.57.0',
  default_options: ['cpp_std=c++17'])

# Derive libxsql's version from its own CMakeLists so the --version banner
# always follows whatever libxsql main is at — no pinned value here.
fs = import('fs')
libxsql_ver = 'unknown'
foreach line : fs.read('CMakeLists.txt').split('\n')
  if line.contains('libxsql VERSION')
    libxsql_ver = line.split('VERSION ')[1].split(' ')[0]
  endif
endforeach
message('libxsql version (derived from CMakeLists): ' + libxsql_ver)

# Vendored SQLite amalgamation, same compile-defs as libxsql's CMake.
sqlite3_lib = static_library('sqlite3',
  'external/sqlite/sqlite3.c',
  c_args: [
    '-DSQLITE_ENABLE_FTS5',
    '-DSQLITE_ENABLE_RTREE',
    '-DSQLITE_ENABLE_JSON1',
    '-DSQLITE_ENABLE_COLUMN_METADATA',
  ],
  include_directories: include_directories('external/sqlite'),
  pic: true)

xsql_inc = include_directories(
  'include',
  'external/sqlite',
  'external/nlohmann/include')

xsql_defs = ['-DXSQL_VERSION_STRING="' + libxsql_ver + '"']

xsql_lib = static_library('xsql',
  'src/aggregates.cpp',
  'src/database.cpp',
  'src/functions.cpp',
  'src/script.cpp',
  'src/statement.cpp',
  cpp_args: xsql_defs,
  include_directories: xsql_inc,
  link_with: sqlite3_lib,
  pic: true)

# Consumers get the include dirs transitively.
xsql_dep = declare_dependency(
  link_with: [xsql_lib, sqlite3_lib],
  include_directories: xsql_inc)
