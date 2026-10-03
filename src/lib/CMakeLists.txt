# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
# Copyright (c) 2024-2026 Elias Bachaalany
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
# libr2xsql — static core library exposing radare2 state as SQLite virtual
# tables. The libr backend lives in the r2xsql_libr OBJECT library below;
# the mock backend supports consumers with canned command responses.

add_library(r2xsql STATIC
  src/version.cpp
  src/session.cpp
  src/backend_common.cpp
  src/backend_mock.cpp
  src/json_utils.cpp
  src/tables_binary.cpp
  src/tables_bininfo.cpp
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
  src/tables_patches.cpp
  src/tables_grep.cpp
  src/tables_decompiler.cpp
  src/tables_types.cpp
  src/tables_types_members.cpp
  src/tables_projects.cpp
  src/tables_rop.cpp
  src/tables_syscalls.cpp
  src/tables_calling_conventions.cpp
  src/tables_classes.cpp
  src/tables_registers.cpp
  src/tables_relocs.cpp
  src/tables_libs.cpp
  src/tables_demangle.cpp
  src/tables_assemble.cpp
  src/tables_read_cstr.cpp
  src/tables_runtime_settings.cpp
  src/views_shared.cpp     # callers / callees / string_refs (family-shared)
)
add_library(r2xsql::r2xsql ALIAS r2xsql)

target_include_directories(r2xsql
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# r_util for r_name_check, which the table sources call through <r_util.h>.
target_link_libraries(r2xsql PUBLIC xsql::xsql Radare2::r_util)
target_compile_features(r2xsql PUBLIC cxx_std_20)

if(WIN32)
  target_compile_definitions(r2xsql PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS)
endif()

set_target_properties(r2xsql PROPERTIES POSITION_INDEPENDENT_CODE ON)

# In-process backend, linked into the plugin and embedding examples.
# direct_libr.cpp is the C-API side of the src/direct.hpp seam: the row
# producers a ported table uses instead of running a command and parsing its
# JSON. It belongs here rather than in a tables_*.cpp because those are
# compiled into the core library above, which only uses r_util.
add_library(r2xsql_libr OBJECT
  src/backend_libr.cpp
  src/direct_libr.cpp
)
if(Radare2_ROOT)
  # Fallback for r_sys_prefix()'s data-dir cliff: on Windows it resolves relative to the RUNNING
  # executable's own location, not radare2's install, so an embedding app
  # silently gets an empty calling-convention/syscall/types SDB unless it
  # happens to be deployed inside radare2's own bin/. The prefix this
  # target was actually configured against is known at build time; bake it
  # in as a same-machine fallback backend_libr.cpp uses ONLY when live
  # auto-detection fails (see libr_data_dir_status() callers).
  file(TO_CMAKE_PATH "${Radare2_ROOT}" _r2xsql_radare2_root_native)
  target_compile_definitions(r2xsql_libr PRIVATE
    "R2XSQL_RADARE2_PREFIX=\"${_r2xsql_radare2_root_native}\"")
endif()
target_link_libraries(r2xsql_libr PUBLIC r2xsql Radare2::libr)
target_compile_features(r2xsql_libr PUBLIC cxx_std_20)
# The seam header is internal (src/), not part of the shipped include/ API.
target_include_directories(r2xsql_libr PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
set_target_properties(r2xsql_libr PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(WIN32)
  target_compile_definitions(r2xsql_libr PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS)

  # On Windows the r2 import libs reference DLLs; copy them next to the full
  # consumers (examples and core_r2xsql) so each loads radare2 without PATH
  # juggling.
  if(Radare2_ROOT)
    file(GLOB _r2_dlls "${Radare2_ROOT}/bin/*.dll")
    if(_r2_dlls)
      add_custom_target(r2xsql_copy_r2_dlls ALL
        COMMAND ${CMAKE_COMMAND} -E make_directory
          "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/$<CONFIG>"
        VERBATIM)
      foreach(_dll IN LISTS _r2_dlls)
        add_custom_command(TARGET r2xsql_copy_r2_dlls POST_BUILD
          COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_dll}" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/$<CONFIG>/"
          VERBATIM)
      endforeach()
    endif()
  endif()
endif()
