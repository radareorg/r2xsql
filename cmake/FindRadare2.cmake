# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
# Copyright (c) 2024-2026 Elias Bachaalany
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
# FindRadare2.cmake — locate a radare2 install (built or pkg-config-discoverable).
#
# Resolution order:
#   1. -DRadare2_ROOT=... or ENV{Radare2_ROOT}
#   2. ${CMAKE_SOURCE_DIR}/../radare2/prefix (parent-project bundled build)
#   3. ${CMAKE_SOURCE_DIR}/radare2/prefix    (standalone-with-checkout)
#   4. pkg-config (if available on PATH)
#
# Provides:
#   Radare2_FOUND       — TRUE if found
#   Radare2_ROOT        — install prefix (with bin/, lib/, include/libr/)
#   Radare2_VERSION     — version string from r_core.pc
#   Radare2_INCLUDE_DIRS, Radare2_LIBRARY_DIRS, Radare2_LIBRARIES
#   Imported targets:
#     Radare2::r_core, Radare2::r_anal, Radare2::r_bin, Radare2::r_util,
#     Radare2::r_io, Radare2::r_cons, Radare2::r_main, Radare2::r_socket, ...
#     Radare2::libr  (INTERFACE bundle of the lot)
#
# Plus:
#   Radare2_EXECUTABLE  — path to radare2(.exe) (for the r2pipe backend)

set(_r2_search_roots "")

if(DEFINED Radare2_ROOT AND Radare2_ROOT)
  list(APPEND _r2_search_roots "${Radare2_ROOT}")
endif()
if(DEFINED ENV{Radare2_ROOT})
  list(APPEND _r2_search_roots "$ENV{Radare2_ROOT}")
endif()

foreach(_candidate
        "${CMAKE_CURRENT_SOURCE_DIR}/../radare2/prefix"
        "${CMAKE_CURRENT_SOURCE_DIR}/radare2/prefix"
        "${CMAKE_SOURCE_DIR}/radare2/prefix"
        "${CMAKE_SOURCE_DIR}/../radare2/prefix")
  if(EXISTS "${_candidate}")
    get_filename_component(_abs "${_candidate}" ABSOLUTE)
    list(APPEND _r2_search_roots "${_abs}")
  endif()
endforeach()
if(_r2_search_roots)
  list(REMOVE_DUPLICATES _r2_search_roots)
endif()

set(Radare2_FOUND FALSE)
set(_r2_resolved_root "")

foreach(_root IN LISTS _r2_search_roots)
  if(EXISTS "${_root}/include/libr/r_core.h"
     AND (EXISTS "${_root}/lib" OR EXISTS "${_root}/lib64"))
    set(_r2_resolved_root "${_root}")
    set(Radare2_FOUND TRUE)
    break()
  endif()
endforeach()

if(_r2_resolved_root)
  set(Radare2_ROOT "${_r2_resolved_root}" CACHE PATH "radare2 install prefix" FORCE)
endif()

if(NOT Radare2_FOUND)
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(_R2 QUIET r_core)
    if(_R2_FOUND)
      set(Radare2_FOUND TRUE)
      set(Radare2_VERSION "${_R2_VERSION}")
      set(Radare2_INCLUDE_DIRS "${_R2_INCLUDE_DIRS}")
      set(Radare2_LIBRARY_DIRS "${_R2_LIBRARY_DIRS}")
      set(Radare2_LIBRARIES    "${_R2_LIBRARIES}")
    endif()
  endif()
endif()

if(Radare2_FOUND AND Radare2_ROOT)
  # Normalize separators: on Windows, Git-Bash passes -DRadare2_ROOT as
  # "D:\a\...\r2prefix" (backslashes), and file(GLOB) treats backslashes as escapes
  # rather than separators, so the libdir glob below matches nothing and we end up
  # linking zero radare2 libs. TO_CMAKE_PATH forces forward slashes everywhere.
  file(TO_CMAKE_PATH "${Radare2_ROOT}" Radare2_ROOT)

  set(Radare2_INCLUDE_DIRS "${Radare2_ROOT}/include/libr"
                           "${Radare2_ROOT}/include/libr/sdb")

  # radare2's libdir under the prefix varies by platform/build: plain lib, lib64,
  # or lib/<multiarch-triplet> — meson's default on Debian/Ubuntu installs to
  # lib/x86_64-linux-gnu. Locate it from where libr_core actually landed; if we
  # assumed lib/ we would find NO libraries there, leave Radare2_LIBRARIES empty,
  # and link r2xsql-full / the plugin with zero radare2 libs — which compiles and
  # links "cleanly" right up to a wall of undefined r_core_* references.
  set(_r2_libdir "${Radare2_ROOT}/lib")
  file(GLOB _r2_core_glob
       "${Radare2_ROOT}/lib/libr_core.*"   "${Radare2_ROOT}/lib/r_core.*"
       "${Radare2_ROOT}/lib64/libr_core.*" "${Radare2_ROOT}/lib64/r_core.*"
       "${Radare2_ROOT}/lib/*/libr_core.*" "${Radare2_ROOT}/lib/*/r_core.*")
  # r_core.* also matches pkgconfig's r_core.pc, which is NOT a library and lives
  # in lib/pkgconfig/ — and since file(GLOB) sorts its results, that .pc sorts
  # ahead of lib/r_core.lib and would mis-resolve the libdir to lib/pkgconfig
  # (zero libraries). Drop any pkgconfig / .pc match.
  list(FILTER _r2_core_glob EXCLUDE REGEX "(/pkgconfig/|\\.pc$)")
  if(_r2_core_glob)
    list(GET _r2_core_glob 0 _r2_core0)
    get_filename_component(_r2_libdir "${_r2_core0}" DIRECTORY)
  endif()
  set(Radare2_LIBRARY_DIRS "${_r2_libdir}")

  set(_pc "${_r2_libdir}/pkgconfig/r_core.pc")
  if(EXISTS "${_pc}")
    file(STRINGS "${_pc}" _pclines REGEX "^Version:")
    if(_pclines)
      string(REGEX REPLACE "^Version:[ \t]+(.+)$" "\\1" Radare2_VERSION "${_pclines}")
    endif()
  endif()

  set(_r2_libs r_core r_anal r_bin r_util r_io r_cons r_main r_socket
               r_reg r_arch r_search r_syscall r_config r_lang r_egg r_debug
               r_bp r_crypto r_flag r_fs r_magic r_parse)
  set(Radare2_LIBRARIES "")
  foreach(_lib IN LISTS _r2_libs)
    set(_full "")
    foreach(_ext ".lib" ".dll.a" ".so" ".dylib" ".a")
      if(EXISTS "${_r2_libdir}/${_lib}${_ext}")
        set(_full "${_r2_libdir}/${_lib}${_ext}")
        break()
      elseif(EXISTS "${_r2_libdir}/lib${_lib}${_ext}")
        set(_full "${_r2_libdir}/lib${_lib}${_ext}")
        break()
      endif()
    endforeach()
    if(_full)
      if(NOT TARGET Radare2::${_lib})
        add_library(Radare2::${_lib} UNKNOWN IMPORTED)
        set_target_properties(Radare2::${_lib} PROPERTIES
          IMPORTED_LOCATION "${_full}"
          INTERFACE_INCLUDE_DIRECTORIES "${Radare2_INCLUDE_DIRS}")
      endif()
      list(APPEND Radare2_LIBRARIES Radare2::${_lib})
    endif()
  endforeach()

  # A resolved root but an empty library set means consumers (r2xsql-full, the
  # plugin) would link with NO radare2 libs and die on a wall of undefined
  # r_core_* symbols. Surface it at configure time instead.
  list(LENGTH Radare2_LIBRARIES _r2_nlibs)
  message(STATUS "FindRadare2: libdir='${_r2_libdir}', resolved ${_r2_nlibs} libraries")
  if(_r2_nlibs EQUAL 0)
    message(WARNING "FindRadare2: found radare2 at '${Radare2_ROOT}' but located ZERO "
                    "import libraries under '${_r2_libdir}'. Full/plugin links will fail "
                    "with undefined r_core_* symbols.")
  endif()

  if(NOT TARGET Radare2::libr)
    add_library(Radare2::libr INTERFACE IMPORTED)
    set_target_properties(Radare2::libr PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${Radare2_INCLUDE_DIRS}"
      INTERFACE_LINK_LIBRARIES      "${Radare2_LIBRARIES}")
  endif()

  find_program(Radare2_EXECUTABLE
    NAMES radare2 r2
    PATHS "${Radare2_ROOT}/bin"
    NO_DEFAULT_PATH)
  if(NOT Radare2_EXECUTABLE)
    find_program(Radare2_EXECUTABLE NAMES radare2 r2)
  endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Radare2
  REQUIRED_VARS Radare2_ROOT Radare2_INCLUDE_DIRS
  VERSION_VAR   Radare2_VERSION)

mark_as_advanced(Radare2_INCLUDE_DIRS Radare2_LIBRARIES Radare2_EXECUTABLE)
