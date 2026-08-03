// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// LibrBackend — in-process wrapper around r_core, compiled when
// R2XSQL_HAVE_LIBR is set. In a pipe-only build (no radare2 at configure time)
// R2XSQL_HAVE_LIBR is unset and open_libr() returns nullptr.

#include <r2xsql/backend.hpp>

#if R2XSQL_HAVE_LIBR
#  include <r_core.h>
#  include <r_userconf.h>
#  include <r_util.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>

namespace r2xsql {

#if R2XSQL_HAVE_LIBR

// Mirror r2's own data-dir resolution (cbin.c builds <r_sys_prefix>/<R2_SDB_FCNSIGN>
// for the type DB) so we can detect, before the bin loads, whether this binary
// is deployed where radare2 expects its data files.
LibrDataDirStatus libr_data_dir_status() {
  LibrDataDirStatus st;
  char* pfx = r_sys_prefix(nullptr);
  if (pfx) {
    char* dir = r_file_new(pfx, R2_SDB_FCNSIGN, nullptr);  // <prefix>/share/fcnsign
    if (dir) {
      st.probe_path = dir;
      st.found = r_file_is_directory(dir);
      free(dir);
    }
    free(pfx);
  }
  return st;
}

namespace {

class LibrBackend : public Backend {
 public:
  // Construct from an already-existing core (used by the in-r2 plugin).
  explicit LibrBackend(RCore* core, bool owns) : core_(core), owns_(owns) {}

  ~LibrBackend() override {
    if (owns_ && core_) {
      // If a project name was provided in write mode, persist analysis so
      // a subsequent run with the same project skips `aaa`.
      if (write_ && !project_.empty()) {
        r_core_project_save(core_, project_.c_str());
      }
      r_core_free(core_);
      core_ = nullptr;
    }
  }

  static std::unique_ptr<LibrBackend> open(const LibrOpenOptions& opts, BackendError* err) {
    RCore* core = r_core_new();
    if (!core) {
      if (err) err->message = "r_core_new failed";
      return nullptr;
    }
    r_core_loadlibs(core, R_CORE_LOADLIBS_ALL, nullptr);

    bool loaded_project = false;
    if (!opts.project.empty()) {
      // Try to reopen an existing project. If it exists, file open + aaa
      // are handled by the project script.
      loaded_project = r_core_project_open(core, opts.project.c_str());
    }

    if (!loaded_project && !opts.path.empty()) {
      RIODesc* fd = r_core_file_open(core, opts.path.c_str(), opts.write ? R_PERM_RW : R_PERM_R, 0);
      if (!fd) {
        if (err) err->message = std::string("could not open file: ") + opts.path;
        r_core_free(core);
        return nullptr;
      }
      // Before bin load (which triggers the type DB + ordinal-import lookups),
      // warn once if r2's data dir isn't reachable from this executable's
      // location — otherwise the user just sees r2's cryptic "Cannot find" spew
      // with a silently-degraded `types` table.
      LibrDataDirStatus dd = libr_data_dir_status();
      if (!dd.found) {
        std::fprintf(stderr,
            "r2xsql-full: radare2 data dir not found (looked in %s).\n"
            "       The 'types' table and ordinal-imported symbols will be "
            "incomplete.\n"
            "       Run r2xsql-full from the radare2 install bin/ directory (next "
            "to radare2.exe), or use the pipe-only r2xsql.\n",
            dd.probe_path.empty() ? "<unknown>" : dd.probe_path.c_str());
      }
      r_core_bin_load(core, opts.path.c_str(), UT64_MAX);

      // Reopen so the IO image is fully mapped before analysis. A bare
      // file-open + bin-load leaves the virtual image incompletely mapped for
      // reference scanning, so an in-process `aaa` finds fewer code/string
      // xrefs than the canonical `radare2 <file>` launcher does. Reopening
      // (`oo` / `oo+` in write mode) finalizes the mapping exactly as the
      // launcher does, so the libr (full) flavor's analysis matches the
      // pipe-only (spawned-radare2) reference 1:1.
      (void)r_core_cmd0(core, opts.write ? "oo+" : "oo");
    }

    auto b = std::unique_ptr<LibrBackend>(new LibrBackend(core, /*owns=*/true));
    b->project_ = opts.project;
    b->write_   = opts.write;

    // Skip analysis if a project supplied it. Otherwise honor opts.analyze.
    if (!loaded_project && opts.analyze) (void)b->cmd("aaa");
    return b;
  }

  std::string cmd(std::string_view command) override {
    if (!core_) return {};
    std::lock_guard lock(m_);
    std::string c(command);
    char* res = r_core_cmd_str(core_, c.c_str());
    if (!res) return {};
    std::string out(res);
    free(res);
    return out;
  }

  bool alive() const override { return core_ != nullptr; }
  std::string_view name() const override { return "libr"; }

 private:
  std::mutex m_;
  RCore* core_ = nullptr;
  bool owns_   = false;
  bool write_  = false;
  std::string project_;
};

}  // namespace

std::unique_ptr<Backend> open_libr(const LibrOpenOptions& opts, BackendError* err) {
  return LibrBackend::open(opts, err);
}

// Used by the in-r2 plugin to wrap the host's RCore* without taking ownership.
// Declared in <r2xsql/backend.hpp>; plain C++ linkage (see the note there on why
// no extern "C").
std::unique_ptr<Backend> make_libr_backend_from_core(void* core_ptr) {
  return std::unique_ptr<Backend>(new LibrBackend(static_cast<RCore*>(core_ptr), /*owns=*/false));
}

#else  // R2XSQL_HAVE_LIBR == 0

std::unique_ptr<Backend> open_libr(const LibrOpenOptions&, BackendError* err) {
  if (err) err->message = "r2xsql was built without libr support (R2XSQL_HAVE_LIBR=0)";
  return nullptr;
}

// Pipe-only: the data dir is resolved by the spawned radare2.exe, not by this
// process, so there is nothing to probe — report it as available (N/A).
LibrDataDirStatus libr_data_dir_status() { return LibrDataDirStatus{}; }

// Pipe-only stub so a consumer that references the symbol still links; there is
// no in-process core to wrap without libr.
std::unique_ptr<Backend> make_libr_backend_from_core(void*) { return nullptr; }

#endif

}  // namespace r2xsql
