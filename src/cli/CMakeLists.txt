# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
# Copyright (c) 2024-2026 Elias Bachaalany
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
# r2sql command-line tool — two flavors from one main.cpp:
#   * r2sql       (pipe-only) — ALWAYS built; links the backend-neutral core
#                               only, no radare2. Spawns radare2 over a pipe.
#   * r2sql-full  (libr)      — built when R2SQL_FULL_ENABLED; links the
#                               in-process libr backend (r2sql_libr).
# main.cpp guards every libr reference behind `#if R2SQL_HAVE_LIBR`, so the
# pipe binary compiled with R2SQL_HAVE_LIBR=0 needs neither backend_libr nor
# radare2.

# Shared wiring for a CLI target.
function(r2sql_configure_cli tgt)
  target_link_libraries(${tgt} PRIVATE r2sql::r2sql)
  target_include_directories(${tgt} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
  if(R2SQL_WITH_MCP)
    target_sources(${tgt} PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/../common/mcp_server.cpp)
    target_link_libraries(${tgt} PRIVATE fastmcpp_core)
    target_compile_definitions(${tgt} PRIVATE R2SQL_HAS_MCP=1)
  endif()
  if(WIN32)
    target_compile_definitions(${tgt} PRIVATE
      WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  endif()
endfunction()

# Pipe-only CLI — always built.
add_executable(r2sql_cli_pipe main.cpp)
set_target_properties(r2sql_cli_pipe PROPERTIES OUTPUT_NAME r2sql)
target_compile_definitions(r2sql_cli_pipe PRIVATE R2SQL_HAVE_LIBR=0)
r2sql_configure_cli(r2sql_cli_pipe)
xsql_add_versioninfo(r2sql_cli_pipe
  FILETYPE          VFT_APP
  DESCRIPTION       "r2sql - SQL interface for radare2 (pipe-only)"
  ORIGINAL_FILENAME "r2sql.exe")

# Full (in-process libr) CLI — when the full flavor is enabled.
if(R2SQL_FULL_ENABLED)
  add_executable(r2sql_cli_full main.cpp)
  set_target_properties(r2sql_cli_full PROPERTIES OUTPUT_NAME r2sql-full)
  target_compile_definitions(r2sql_cli_full PRIVATE R2SQL_HAVE_LIBR=1)
  # Link Radare2::libr directly (not only transitively via the r2sql_libr OBJECT
  # library): an executable consuming an OBJECT library does not reliably inherit
  # that library's INTERFACE link deps, so backend_libr.cpp's r_core_*/r_file_*
  # symbols would be left undefined. The core_r2sql plugin links it the same way.
  target_link_libraries(r2sql_cli_full PRIVATE r2sql_libr Radare2::libr)
  r2sql_configure_cli(r2sql_cli_full)
  xsql_add_versioninfo(r2sql_cli_full
    FILETYPE          VFT_APP
    DESCRIPTION       "r2sql - SQL interface for radare2 (embedded radare2 / libr)"
    ORIGINAL_FILENAME "r2sql-full.exe")
endif()
