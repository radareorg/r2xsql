# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
# Copyright (c) 2024-2026 Elias Bachaalany
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
# r2xsql — SQL interface for radare2.
#
# This CMakeLists is fully self-contained: it builds cleanly as a subdirectory
# of a larger project, AND as a standalone repo (sibling-detect libxsql, else
# FetchContent). It never reaches outside its own tree except via the
# standard sibling-detect-or-fetch dance.

cmake_minimum_required(VERSION 3.20)
project(r2xsql VERSION 0.0.1 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build every static library — including the fetched libxsql — as
# position-independent code. The core_r2xsql plugin is a shared module, and on
# Linux GNU ld refuses to link non-PIC static objects into a .so
# ("relocation R_X86_64_TPOFF32 against `__tls_guard' ... recompile with -fPIC").
# Must be set BEFORE the deps are fetched/added so the
# FetchContent targets inherit it. No-op on macOS/Windows (PIC by default).
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Detect standalone vs subproject build (mirrors libxsql's pattern).
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(R2XSQL_STANDALONE ON)
  set(R2XSQL_STANDALONE_LABEL "standalone")
else()
  set(R2XSQL_STANDALONE OFF)
  set(R2XSQL_STANDALONE_LABEL "subproject")
endif()

# Output dirs only when standalone (the parent project owns them otherwise).
if(R2XSQL_STANDALONE)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
endif()

# CMake module path (FindRadare2.cmake lives here).
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# ============================================================================
# Options
# ============================================================================

option(R2XSQL_BUILD_PLUGIN    "Build the in-r2 plugin (core_r2xsql)"      ON)
option(R2XSQL_BUILD_EXAMPLES  "Build r2xsql examples"                   ${R2XSQL_STANDALONE})
option(R2XSQL_ALLOW_STATIC_CRT_LIBR
       "Permit a static MSVC runtime (/MT) with the full/libr flavor — only safe when radare2 is also static-runtime" OFF)

# ============================================================================
# libxsql dependency
#   Order: existing target > sibling subdir > FetchContent
# ============================================================================

include(FetchContent)

if(TARGET xsql::xsql)
  message(STATUS "r2xsql: using xsql::xsql from parent project")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../libxsql/CMakeLists.txt")
  message(STATUS "r2xsql: adding sibling libxsql at ../libxsql")
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
else()
  message(STATUS "r2xsql: fetching libxsql from GitHub")
  FetchContent_Declare(libxsql
    GIT_REPOSITORY https://github.com/0xeb/libxsql.git
    GIT_TAG        main
    GIT_SHALLOW    TRUE)
  FetchContent_MakeAvailable(libxsql)
endif()

# ============================================================================
# radare2 dependency (MANDATORY)
#   r2xsql ships one artifact: the in-r2 plugin core_r2xsql, which links libr
#   and loads into a radare2 process. There is no pipe-only build to fall back
#   to any more, so a missing radare2 is a hard configure error rather than a
#   downgrade.
# ============================================================================

find_package(Radare2 QUIET)

if(NOT Radare2_FOUND)
  message(FATAL_ERROR
    "r2xsql: radare2 NOT found, and the plugin cannot be built without it. "
    "Pass -DRadare2_ROOT=<prefix> pointing at a radare2 install (see "
    "cmake/FindRadare2.cmake for what it looks for).")
endif()

message(STATUS "r2xsql: radare2 ${Radare2_VERSION} at ${Radare2_ROOT}")
# CRT hazard: the libr backend frees radare2-allocated buffers
# (r_core_cmd_str) with the caller's CRT. If an outer project forces a static
# MSVC runtime (/MT) but radare2 was built against the dynamic runtime (/MD,
# the meson default), that free crosses CRT heaps and corrupts memory at
# runtime. The build LINKS cleanly, so this fails silently — make it a hard
# configure error unless the user affirms radare2 is also static-runtime.
if(MSVC)
  set(_r2_static_crt OFF)
  if(DEFINED CMAKE_MSVC_RUNTIME_LIBRARY
     AND NOT CMAKE_MSVC_RUNTIME_LIBRARY MATCHES "DLL")
    set(_r2_static_crt ON)
  endif()
  # Also catch /MT injected via raw flags rather than the runtime-library
  # var — across the global and every per-config flag variable.
  foreach(_v CMAKE_C_FLAGS CMAKE_CXX_FLAGS
             CMAKE_C_FLAGS_DEBUG          CMAKE_CXX_FLAGS_DEBUG
             CMAKE_C_FLAGS_RELEASE        CMAKE_CXX_FLAGS_RELEASE
             CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_CXX_FLAGS_RELWITHDEBINFO
             CMAKE_C_FLAGS_MINSIZEREL     CMAKE_CXX_FLAGS_MINSIZEREL)
    if(DEFINED ${_v} AND "${${_v}}" MATCHES "(^| )[-/]MT")
      set(_r2_static_crt ON)
    endif()
  endforeach()
  if(_r2_static_crt AND NOT R2XSQL_ALLOW_STATIC_CRT_LIBR)
    message(FATAL_ERROR
      "r2xsql: a static MSVC runtime (/MT) is in effect with the plugin, "
      "which frees radare2-allocated buffers with the caller's CRT. "
      "Mixing a /MT plugin with a /MD radare2 corrupts the heap at runtime. "
      "Fix one of: build radare2 static-runtime, or — if radare2 is "
      "genuinely static-runtime too — "
      "pass -DR2XSQL_ALLOW_STATIC_CRT_LIBR=ON.")
  endif()
endif()

# ============================================================================
# Windows VERSIONINFO resource (version.hpp is the source of truth)
# ============================================================================
# Parse R2XSQL_VERSION_* from the C++ header so the embedded binary version
# resource can never drift from version(). Enable the RC language and expose the
# xsql_add_versioninfo() helper that CLI/plugin targets call to attach a
# generated .rc. No-op on non-Windows.

set(_r2xsql_version_hpp "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include/r2xsql/version.hpp")
file(READ "${_r2xsql_version_hpp}" _r2xsql_version_contents)
string(REGEX MATCH "R2XSQL_VERSION_MAJOR[ \t]+([0-9]+)" _ "${_r2xsql_version_contents}")
set(TOOL_VERSION_MAJOR "${CMAKE_MATCH_1}")
string(REGEX MATCH "R2XSQL_VERSION_MINOR[ \t]+([0-9]+)" _ "${_r2xsql_version_contents}")
set(TOOL_VERSION_MINOR "${CMAKE_MATCH_1}")
string(REGEX MATCH "R2XSQL_VERSION_PATCH[ \t]+([0-9]+)" _ "${_r2xsql_version_contents}")
set(TOOL_VERSION_PATCH "${CMAKE_MATCH_1}")
if(TOOL_VERSION_MAJOR STREQUAL "" OR TOOL_VERSION_MINOR STREQUAL "" OR TOOL_VERSION_PATCH STREQUAL "")
  message(FATAL_ERROR "r2xsql: failed to parse version from ${_r2xsql_version_hpp}")
endif()
message(STATUS "r2xsql: version ${TOOL_VERSION_MAJOR}.${TOOL_VERSION_MINOR}.${TOOL_VERSION_PATCH}")
if(WIN32)
  enable_language(RC)
endif()
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/versioninfo.cmake)

# ============================================================================
# Subdirs
# ============================================================================

add_subdirectory(src)

if(R2XSQL_BUILD_EXAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples")
  add_subdirectory(examples)
endif()

message(STATUS "")
message(STATUS "r2xsql ${PROJECT_VERSION} (${R2XSQL_STANDALONE_LABEL})")
if(R2XSQL_STANDALONE)
  message(STATUS "  Mode             : standalone")
else()
  message(STATUS "  Mode             : subproject")
endif()
message(STATUS "  radare2          : ${Radare2_VERSION} at ${Radare2_ROOT}")
message(STATUS "  Artifact         : core_r2xsql (in-r2 plugin)")
message(STATUS "")
