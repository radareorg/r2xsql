# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
# Copyright (c) 2024-2026 Elias Bachaalany
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
# r2xsql command-line tool — two flavors from one main.cpp:
#   * r2xsql       (pipe-only) — ALWAYS built; links the backend-neutral core
#                               only, no radare2. Spawns radare2 over a pipe.
#   * r2xsql-full  (libr)      — built when R2XSQL_FULL_ENABLED; links the
#                               in-process libr backend (r2xsql_libr).
# main.cpp guards every libr reference behind `#if R2XSQL_HAVE_LIBR`, so the
# pipe binary compiled with R2XSQL_HAVE_LIBR=0 needs neither backend_libr nor
# radare2.

if(NOT TARGET replxx::replxx)
  # Static linkage keeps both CLI flavors self-contained.
  set(BUILD_SHARED_LIBS OFF)
  FetchContent_Declare(replxx
    GIT_REPOSITORY https://github.com/AmokHuginnsson/replxx.git
    GIT_TAG 2b248467112cbbc16f63fde38230fd7c7ffc55f1) # release-0.0.4
  FetchContent_MakeAvailable(replxx)
endif()

# Shared wiring for a CLI target.
function(r2xsql_configure_cli tgt)
  target_link_libraries(${tgt} PRIVATE r2xsql::r2xsql replxx::replxx)
  target_include_directories(${tgt} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
  if(WIN32)
    target_compile_definitions(${tgt} PRIVATE
      WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  endif()
endfunction()

# Pipe-only CLI — always built.
add_executable(r2xsql_cli_pipe main.cpp)
set_target_properties(r2xsql_cli_pipe PROPERTIES OUTPUT_NAME r2xsql)
target_compile_definitions(r2xsql_cli_pipe PRIVATE R2XSQL_HAVE_LIBR=0)
r2xsql_configure_cli(r2xsql_cli_pipe)
xsql_add_versioninfo(r2xsql_cli_pipe
  FILETYPE          VFT_APP
  DESCRIPTION       "r2xsql - SQL interface for radare2 (pipe-only)"
  ORIGINAL_FILENAME "r2xsql.exe")

# Full (in-process libr) CLI — when the full flavor is enabled.
if(R2XSQL_FULL_ENABLED)
  add_executable(r2xsql_cli_full main.cpp)
  set_target_properties(r2xsql_cli_full PROPERTIES OUTPUT_NAME r2xsql-full)
  target_compile_definitions(r2xsql_cli_full PRIVATE R2XSQL_HAVE_LIBR=1)
  # Link Radare2::libr directly (not only transitively via the r2xsql_libr OBJECT
  # library): an executable consuming an OBJECT library does not reliably inherit
  # that library's INTERFACE link deps, so backend_libr.cpp's r_core_*/r_file_*
  # symbols would be left undefined. The core_r2xsql plugin links it the same way.
  target_link_libraries(r2xsql_cli_full PRIVATE r2xsql_libr Radare2::libr)
  r2xsql_configure_cli(r2xsql_cli_full)
  xsql_add_versioninfo(r2xsql_cli_full
    FILETYPE          VFT_APP
    DESCRIPTION       "r2xsql - SQL interface for radare2 (embedded radare2 / libr)"
    ORIGINAL_FILENAME "r2xsql-full.exe")
endif()
