# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
# Copyright (c) 2024-2026 Elias Bachaalany
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
# r2xsql in-r2 plugin (core_r2xsql)
#
# Builds a shared library that radare2 loads as an RCorePlugin. Once
# loaded, exposes the `sql` command for querying the host RCore via
# r2xsql's table catalog.

add_library(core_r2xsql MODULE core_r2xsql.cpp)

# Output as core_r2xsql so radare2's loader picks it up under the plugins
# directory. The `core_` prefix is mandatory (r2's plugin loader scans
# for it to identify R_LIB_TYPE_CORE plugins); the `_r2xsql` suffix
# disambiguates against r2's own bundled `core_*` plugins.
set_target_properties(core_r2xsql PROPERTIES
  OUTPUT_NAME "core_r2xsql"
  PREFIX ""
)

target_include_directories(core_r2xsql PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../lib/include
  ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# core (backend-neutral) + the libr backend object lib (brings backend_libr +
# Radare2::libr). Built only under R2XSQL_FULL_ENABLED.
target_link_libraries(core_r2xsql PRIVATE r2xsql::r2xsql r2xsql_libr Radare2::libr)
target_compile_features(core_r2xsql PRIVATE cxx_std_20)

if(R2XSQL_WITH_MCP)
  target_sources(core_r2xsql PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/mcp_server.cpp)
  target_link_libraries(core_r2xsql PRIVATE fastmcpp_core)
  target_compile_definitions(core_r2xsql PRIVATE R2XSQL_HAS_MCP=1)
endif()

if(WIN32)
  target_compile_definitions(core_r2xsql PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
  )
endif()

# Make the plugin discoverable: drop next to consumer exes during
# development. Production installs would use radare2's plugin path.
set_target_properties(core_r2xsql PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
)

xsql_add_versioninfo(core_r2xsql
  FILETYPE          VFT_DLL
  DESCRIPTION       "r2xsql in-r2 plugin (sql command)"
  ORIGINAL_FILENAME "core_r2xsql.dll")
