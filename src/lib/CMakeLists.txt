# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
# Copyright (c) 2024-2026 Elias Bachaalany
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
# libr2sql — static core library exposing radare2 state as SQLite virtual
# tables. Backend-neutral: it carries the mock + r2pipe backends only and links
# NO radare2, so a true pipe-only r2sql can link it without importing any
# r_*.dll. The libr (in-process radare2) backend lives in the optional
# r2sql_libr OBJECT library below, shared by r2sql-full and the in-r2 plugin.

add_library(r2sql STATIC
  src/version.cpp
  src/session.cpp
  src/backend_common.cpp
  src/backend_mock.cpp
  src/backend_r2pipe.cpp
  src/json_utils.cpp
  src/tables_binary.cpp
  src/tables_funcs.cpp
  src/tables_locals.cpp
  src/tables_blocks.cpp
  src/tables_bytes.cpp
  src/tables_cfg_edges.cpp
  src/tables_switch_tables.cpp
  src/tables_function_frames.cpp
  src/tables_data_items.cpp
  src/tables_byte_search.cpp
  src/tables_graph_tables.cpp
  src/tables_instructions.cpp
  src/tables_operands.cpp
  src/tables_esil.cpp
  src/tables_xrefs.cpp
  src/tables_strings.cpp
  src/tables_imports.cpp
  src/tables_exports.cpp
  src/tables_sections.cpp
  src/tables_segments.cpp
  src/tables_io_maps.cpp
  src/tables_flags.cpp
  src/tables_comments.cpp
  src/tables_bookmarks.cpp
  src/tables_grep.cpp
  src/tables_decompiler.cpp
  src/tables_types.cpp
  src/tables_types_members.cpp
  src/tables_projects.cpp
  src/tables_runtime_settings.cpp
  src/tables_true_believers.cpp
  src/true_believers.cpp   # vendored true_believers decoder
)
add_library(r2sql::r2sql ALIAS r2sql)

# In a pipe-only build the libr backend lives nowhere else, so compile its
# R2SQL_HAVE_LIBR=0 stub (open_libr() -> nullptr, libr_data_dir_status())
# straight into the core library. This honors backend.hpp's contract that
# open_libr() is ALWAYS linkable (returning nullptr without libr support).
# When the full flavor is enabled the real definition comes from the
# r2sql_libr OBJECT library below, so adding it here would duplicate the
# symbol — hence the guard.
if(NOT R2SQL_FULL_ENABLED)
  target_sources(r2sql PRIVATE src/backend_libr.cpp)
endif()

target_include_directories(r2sql
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(r2sql PUBLIC xsql::xsql)
target_compile_features(r2sql PUBLIC cxx_std_20)

if(WIN32)
  target_compile_definitions(r2sql PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS)
  target_link_libraries(r2sql PUBLIC ws2_32)
endif()

set_target_properties(r2sql PROPERTIES POSITION_INDEPENDENT_CODE ON)

# ---------------------------------------------------------------------------
# Optional libr (in-process radare2) backend.
#
# Built only when the full flavor is enabled (R2SQL_FULL_ENABLED, set by the
# top-level CMake when R2SQL_BUILD_FULL=ON and radare2 is found). Compiled as an
# OBJECT library with R2SQL_HAVE_LIBR=1 and linked into BOTH r2sql-full and the
# core_r2sql plugin. The core library above never links radare2, so the
# pipe-only r2sql stays free of r_*.dll imports.
# ---------------------------------------------------------------------------
if(R2SQL_FULL_ENABLED)
  add_library(r2sql_libr OBJECT src/backend_libr.cpp)
  target_compile_definitions(r2sql_libr PRIVATE R2SQL_HAVE_LIBR=1)
  target_link_libraries(r2sql_libr PUBLIC r2sql Radare2::libr)
  target_compile_features(r2sql_libr PUBLIC cxx_std_20)
  set_target_properties(r2sql_libr PROPERTIES POSITION_INDEPENDENT_CODE ON)

  if(WIN32)
    target_compile_definitions(r2sql_libr PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      _CRT_SECURE_NO_WARNINGS)

    # On Windows the r2 import libs reference DLLs; copy them next to the full
    # consumers (r2sql-full + core_r2sql) so each loads radare2 without PATH
    # juggling. The pipe-only r2sql needs none of these.
    if(Radare2_ROOT)
      file(GLOB _r2_dlls "${Radare2_ROOT}/bin/*.dll")
      if(_r2_dlls)
        add_custom_target(r2sql_copy_r2_dlls ALL
          COMMAND ${CMAKE_COMMAND} -E make_directory
            "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/$<CONFIG>"
          VERBATIM)
        foreach(_dll IN LISTS _r2_dlls)
          add_custom_command(TARGET r2sql_copy_r2_dlls POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
              "${_dll}" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/$<CONFIG>/"
            VERBATIM)
        endforeach()
      endif()
    endif()
  endif()
endif()
