# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
# Copyright (c) 2024-2026 Elias Bachaalany
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
# r2xsql examples — minimal consumers of the libr2xsql C++ API.

add_executable(list_funcs list_funcs.cpp)
target_link_libraries(list_funcs PRIVATE r2xsql::r2xsql)
target_compile_features(list_funcs PRIVATE cxx_std_20)

# The example calls open_libr() and falls back to r2pipe when it returns
# nullptr, so it needs BOTH backends linkable. open_libr()'s real definition
# lives in the r2xsql_libr OBJECT library rather than the core static lib (which
# stays radare2-free), so link it explicitly -- plus Radare2::libr, because an
# executable consuming an OBJECT library does not inherit its INTERFACE link
# deps. The r2pipe backend comes from the core library.
target_link_libraries(list_funcs PRIVATE r2xsql_libr Radare2::libr)

# Auto-copy r2 DLLs (Windows) next to the example exe so it can launch.
if(WIN32)
  add_custom_command(TARGET list_funcs POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${Radare2_ROOT}/bin" "$<TARGET_FILE_DIR:list_funcs>"
    COMMENT "Copying radare2 DLLs next to list_funcs"
  )
endif()
