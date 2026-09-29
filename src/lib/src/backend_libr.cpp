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
#  include "direct.hpp"

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
// for the type DB, and separately for the calling-convention/syscall SDBs) so
// we can detect, before the bin loads, whether this binary is deployed where
// radare2 expects its data files.
LibrDataDirStatus libr_data_dir_status_at(const char* prefix) {
  LibrDataDirStatus st;
  // An explicit prefix is probed as given. Do NOT route it through
  // r_sys_prefix(): up to radare2 6.1 that returned its argument, but from
  // 6.2 it returns the executable-derived prefix (and exports R2_PREFIX=arg
  // as a side effect), so the probe silently checked the wrong directory.
  char* pfx = prefix ? strdup(prefix) : r_sys_prefix(nullptr);
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

LibrDataDirStatus libr_data_dir_status() { return libr_data_dir_status_at(nullptr); }

namespace {

// syscalls is a THIRD, more severe shape of the data-dir cliff than either
// calling-conventions or types, and neither the `dir.prefix` config fix nor
// an asm.arch/asm.bits cache-bust poke can reach it: `r_syscall_setup`'s SDB
// loader (`openDatabase`, libr/syscall/syscall.c) never consults `dir.prefix`
// -- or any core config at all. It resolves its data directory purely via
// `r_sys_prefix(NULL)`, which on Windows always derives from THIS
// EXECUTABLE'S OWN module path (`r_sys_get_src_dir_w32()`); the `R2_PREFIX`
// env var fallback inside `r_sys_prefix()` is only consulted if that call
// itself returns null, which it never does for a validly running process --
// so there is no config value or environment variable this loader ever
// honors. (It also cannot fall back to radare2's compiled-in gperf syscall
// tables and skip the file lookup entirely: that path is gated on
// `HAVE_GPERF`, off by default in radare2's own meson build --
// `-Dsdb_cgen=false` -- and this project's build follows that default.)
//
// So after the target's real (arch, bits, os) triple is known (i.e. after
// file-open/bin-load, when `core->anal->syscall` has already been
// (re-)stamped via the normal asm.arch/asm.os/asm.bits config-callback chain
// -- just with a wrongly-resolved, empty `db`), reopen the syscall SDB
// ourselves directly from the fallback prefix and swap it in. This
// replicates `r_syscall_setup`'s own (non-exported) os-alias and
// arm/16-bit normalization -- darwin/osx/macos -> darwin, android -> linux,
// arm + 16-bit + linux -> 32-bit -- so the filename built here is EXACTLY
// the one `r_syscall_setup` would have opened had its internal
// `r_sys_prefix(NULL)` call resolved to the right prefix. Verified directly
// (not assumed): from the wrong deployment location `asj` returns 0 entries
// even with the existing `dir.prefix` fix in effect; from radare2's own
// `bin/`, the same query returns the real table (e.g. 1224 Windows NT
// syscalls for a Windows PE target).
std::string normalized_syscall_os(const std::string& os) {
  if (os == "darwin" || os == "osx" || os == "macos") return "darwin";
  if (os == "android") return "linux";
  return os;
}

// Only reached under R2XSQL_RADARE2_PREFIX (the same-machine data-dir fallback);
// a prefix-agnostic build (e.g. the Makefile/meson plugin) never calls it.
[[maybe_unused]] void reload_syscall_db_from_prefix(RCore* core, const char* prefix) {
  if (!core || !core->anal || !core->anal->syscall) return;
  RSyscall* sc = core->anal->syscall;
  if (!sc->arch || !sc->os) return;  // r_syscall_setup never ran

  const std::string os   = normalized_syscall_os(sc->os);
  const std::string arch = sc->arch;
  int bits = sc->bits;
  if (arch.rfind("arm", 0) == 0 && bits == 16 && os == "linux") bits = 32;

  // Same two-step path build as openDatabase() (libr/syscall/syscall.c):
  // "<prefix>/<R2_SDB>/syscall/<os>-<arch>-<bits>.sdb", using the same
  // public R2_SDB/R_JOIN_* macros the type-db fallback above already relies
  // on (R2_SDB_FCNSIGN is built from the same R2_SDB).
  const std::string dbname =
      std::string("syscall") + R_SYS_DIR + os + "-" + arch + "-" + std::to_string(bits);
  char* file = r_str_newf(R_JOIN_3_PATHS("%s", R2_SDB, "%s.sdb"), prefix, dbname.c_str());
  if (!file) return;
  if (r_file_exists(file)) {
    if (!sc->db) sc->db = sdb_new0();
    sdb_reset(sc->db);
    if (sdb_open(sc->db, file) < 0) {
      sdb_free(sc->db);
      sc->db = sdb_new0();
    }
  }
  free(file);
}

class LibrBackend : public Backend {
 public:
  // Construct from an already-existing core (used by the in-r2 plugin).
  explicit LibrBackend(RCore* core, bool owns)
      : core_(core), owns_(owns), direct_(direct::make_libr_api(core, m_)) {}

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

    // Detect and, if possible, fix the data-dir cliff BEFORE opening
    // anything: cbin.c's calling-convention/syscall/type SDB loader
    // (r_core_anal_cc_init / r_core_anal_type_init) is cache-guarded on
    // (arch, bits) and fires as soon as arch/bits are known — which can
    // happen as early as file-open's own format detection, not just at the
    // explicit bin_load call below. Setting `dir.prefix` any later risks
    // the SDB already being cached (wrong) by the time this code would
    // have set it, with the cache guard then skipping every later reload
    // even after `dir.prefix` is corrected. r_sys_prefix() on Windows
    // resolves relative to THIS EXECUTABLE'S OWN location, not radare2's
    // install, so an embedding app needs this if it isn't deployed inside
    // radare2's own bin/. If auto-detection
    // fails and this build knows the radare2 prefix it was actually
    // configured against (R2XSQL_RADARE2_PREFIX, same machine — see
    // CMakeLists.txt), point `dir.prefix` there so `funcs.calltype`/
    // `funcs.stackframe`/`types`/syscalls resolve correctly instead of
    // silently reporting a plausible-but-wrong value (confirmed for
    // calltype: a degraded SDB still contains a synthetic "reg" convention,
    // so a caller sees *a* value, just the wrong one, with nothing in the
    // log to say so).
    LibrDataDirStatus dd = libr_data_dir_status();
    // set below; drives the syscall-db reload after file load. maybe_unused:
    // only read/written under R2XSQL_RADARE2_PREFIX (undefined in a
    // prefix-agnostic Makefile/meson build).
    [[maybe_unused]] bool using_fallback_prefix = false;
    if (!dd.found) {
#ifdef R2XSQL_RADARE2_PREFIX
      LibrDataDirStatus fallback = libr_data_dir_status_at(R2XSQL_RADARE2_PREFIX);
      if (fallback.found) {
        using_fallback_prefix = true;
        r_config_set(core->config, "dir.prefix", R2XSQL_RADARE2_PREFIX);
        // r_core_new()'s own config setup already fired the calling-
        // convention SDB loader once, at construction, using dir.prefix's
        // WRONG default — "asm.arch" defaults to R_SYS_ARCH (this host's
        // own arch), which is exactly what a native-arch target's later
        // auto-detection will also report, so the loader's (arch, bits)
        // cache guard (cbin.c's r_core_anal_cc_init) would otherwise skip
        // every later reload as "unchanged" even after dir.prefix is fixed
        // above. Poke "asm.arch" to a different REAL architecture (asm.arch
        // validates against the known arch list and silently rejects an
        // unrecognized value, so a nonsense sentinel does nothing) to force
        // one (wasted but harmless) reload that both uses the now-correct
        // dir.prefix and invalidates the cache, so the actual file's arch
        // detection below triggers a genuine, correct reload. "arm" is
        // never R_SYS_ARCH (this host's own arch) on any host this project
        // builds for.
        r_config_set(core->config, "asm.arch", "arm");
        // types has its OWN cache guard, a different shape than calling
        // conventions': r_anal_types_reload (libr/anal/type.c:127) skips
        // reloading whenever `types_loaded_bits == bits` (arch is not part
        // of its guard at all). r_core_new()'s own init (core.c:2715)
        // already called r_core_anal_type_init ONCE, using dir.prefix's
        // wrong default, stamping types_loaded_bits with the host's native
        // bits -- so calling it again with the SAME bits (unchanged since)
        // hits the guard and is silently skipped, dir.prefix fix or not.
        // Poke "asm.bits" too, to a value nothing real will match, so this
        // call's own types_loaded_bits stamp goes stale as soon as the
        // real file's bits get auto-detected later (which changes
        // core->config bits and re-triggers this same loader via its own
        // config callback) -- that LATER call is what actually reloads
        // types correctly, using the dir.prefix already fixed here.
        r_config_set_i(core->config, "asm.bits", 16);
        r_core_anal_type_init(core);
        std::fprintf(stderr,
            "r2xsql: this executable is not deployed inside radare2's "
            "install bin/ (looked in %s); falling back to the prefix this "
            "build was configured against (%s) for calling-convention, "
            "syscall, and type data.\n",
            dd.probe_path.empty() ? "<unknown>" : dd.probe_path.c_str(),
            R2XSQL_RADARE2_PREFIX);
      } else
#endif
      {
        std::fprintf(stderr,
            "r2xsql: radare2 data dir not found (looked in %s).\n"
            "       The 'types' table, ordinal-imported symbols, "
            "'funcs.calltype', and 'funcs.stackframe' will be incomplete "
            "or report a generic fallback value rather than the correct "
            "one.\n"
            "       Run the host application from the radare2 install bin/ directory "
            "(next to radare2.exe), or use the r2pipe backend.\n",
            dd.probe_path.empty() ? "<unknown>" : dd.probe_path.c_str());
      }
    }

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

    // By this point the target's real (arch, bits, os) has been auto-detected
    // and core->anal->syscall re-stamped via the normal config-callback chain
    // -- but, unlike calling-conventions/types, its `db` is still wrong if the
    // fallback prefix is in play (see reload_syscall_db_from_prefix above for
    // why `dir.prefix` never reaches it). Fix it explicitly, after the load
    // sequence, whether or not a project/file was actually opened above (a
    // project load re-stamps syscall from its own saved arch/bits/os too).
#ifdef R2XSQL_RADARE2_PREFIX
    if (using_fallback_prefix) {
      reload_syscall_db_from_prefix(core, R2XSQL_RADARE2_PREFIX);
    }
#endif

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

  // Structural no-eval dispatch: `r_core_call_str_at` (core.c) seeks to `addr`
  // then hands `command` straight to `r_cmd_call`, which indexes directly into
  // the top-level command handler keyed on the command's own first character
  // and passes the remainder as that handler's raw argument — the command
  // string is never re-scanned for `;`/`@`/`|`/backtick chaining the way
  // `r_core_cmd0` (what `cmd()` above ultimately runs) does. A `;`/`@`/`|`/
  // backtick inside an argument therefore cannot start a second command; it is
  // opaque data to whichever single handler this dispatch reaches.
  bool cmd_noeval(int64_t addr, std::string_view command, std::string* out) override {
    if (!core_) return false;
    std::lock_guard lock(m_);
    std::string c(command);
    char* res = r_core_call_str_at(core_, static_cast<ut64>(addr), c.c_str());
    if (!res) {
      // r_core_call_str_at returns NULL only when the command's own first
      // character has no registered handler at all -- a dispatch-routing
      // failure, not a normal validation rejection (those come back as
      // in-band diagnostic text, exactly like cmd()'s failures). Surface it
      // through the same "unknown command" marker table_utils::
      // command_error_text already recognizes, so every caller's existing
      // error check catches this without a second code path.
      if (out) *out = "r2xsql: unknown command for no-eval dispatch";
      return true;
    }
    if (out) *out = res;
    free(res);
    return true;
  }

  bool alive() const override { return core_ != nullptr; }
  std::string_view name() const override { return "libr"; }

  // The only backend that has one: an in-process core is exactly what the
  // C-API producers need. It shares this backend's mutex, so a direct read and
  // a command can never interleave on the same core.
  direct::Api* direct() override { return direct_.get(); }

 private:
  std::mutex m_;
  RCore* core_ = nullptr;
  bool owns_   = false;
  bool write_  = false;
  std::string project_;
  std::unique_ptr<direct::Api> direct_;
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
