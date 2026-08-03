# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
# Copyright (c) 2024-2026 Elias Bachaalany
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
# r2xsql examples — minimal consumers of the libr2xsql C++ API.

add_executable(list_funcs list_funcs.cpp)
target_link_libraries(list_funcs PRIVATE r2xsql::r2xsql)
target_compile_features(list_funcs PRIVATE cxx_std_20)

# The example calls open_libr() unconditionally and falls back to r2pipe when it
# returns nullptr, so open_libr() must be LINKABLE in both flavors:
#   * pipe-only — the R2XSQL_HAVE_LIBR=0 stub compiled into the core r2xsql library
#                 resolves it (returns nullptr -> example uses r2pipe).
#   * full      — the real definition lives in the r2xsql_libr OBJECT library, not
#                 the core static lib (which stays radare2-free). Link it (plus
#                 Radare2::libr directly, as the full CLI does — an executable
#                 consuming an OBJECT library does not inherit its INTERFACE link
#                 deps) so the in-process backend and its r_* symbols resolve.
if(R2XSQL_FULL_ENABLED)
  target_link_libraries(list_funcs PRIVATE r2xsql_libr Radare2::libr)
endif()

# Auto-copy r2 DLLs (Windows) next to the example exe so it can launch
# when linked against libr.
if(WIN32 AND R2XSQL_FULL_ENABLED)
  add_custom_command(TARGET list_funcs POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${Radare2_ROOT}/bin" "$<TARGET_FILE_DIR:list_funcs>"
    COMMENT "Copying radare2 DLLs next to list_funcs"
  )
endif()
