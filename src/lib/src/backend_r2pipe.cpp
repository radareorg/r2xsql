// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// R2PipeBackend — spawns radare2(.exe) -q0 and communicates over stdio.
//
// The r2 -q0 protocol: write a command terminated by \n. Read response
// until a NUL (\0) byte is encountered (NUL terminates each reply).

#include <r2sql/backend.hpp>

#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <signal.h>
#  include <spawn.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <unistd.h>
extern char** environ;
#endif

namespace r2sql {

namespace {

#ifdef _WIN32
struct WinPipe {
  HANDLE read = nullptr;
  HANDLE write = nullptr;
  ~WinPipe() {
    if (read)  CloseHandle(read);
    if (write) CloseHandle(write);
  }
};

class R2PipeWinBackend : public Backend {
 public:
  ~R2PipeWinBackend() override { shutdown(); }

  bool start(const R2PipeOpenOptions& opts, BackendError* err) {
    std::string exe = opts.r2_executable.empty() ? "radare2.exe" : opts.r2_executable;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE child_in_r = nullptr, child_in_w = nullptr;
    HANDLE child_out_r = nullptr, child_out_w = nullptr;
    if (!CreatePipe(&child_in_r, &child_in_w, &sa, 0) ||
        !CreatePipe(&child_out_r, &child_out_w, &sa, 0)) {
      if (err) err->message = "CreatePipe failed";
      return false;
    }
    SetHandleInformation(child_in_w,  HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(child_out_r, HANDLE_FLAG_INHERIT, 0);

    std::string cmdline;
    cmdline.reserve(256);
    cmdline += "\"";
    cmdline += exe;
    cmdline += "\"";
    cmdline += " -q0";
    if (opts.write) cmdline += " -w";
    if (!opts.analyze) cmdline += " -e bin.cache=true";
    for (auto& a : opts.extra_args) {
      cmdline += " ";
      cmdline += a;
    }
    if (!opts.path.empty()) {
      cmdline += " \"";
      cmdline += opts.path;
      cmdline += "\"";
    } else {
      cmdline += " -";
    }

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput  = child_in_r;
    si.hStdOutput = child_out_w;
    si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);

    std::vector<char> cmdbuf(cmdline.begin(), cmdline.end());
    cmdbuf.push_back(0);

    BOOL ok = CreateProcessA(nullptr, cmdbuf.data(), nullptr, nullptr,
                              TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(child_in_r);
    CloseHandle(child_out_w);
    if (!ok) {
      DWORD e = GetLastError();
      CloseHandle(child_in_w);
      CloseHandle(child_out_r);
      if (err) {
        err->message = "CreateProcess failed for ";
        err->message += exe;
        err->message += " (code ";
        err->message += std::to_string(e);
        err->message += ")";
      }
      return false;
    }
    proc_  = pi.hProcess;
    CloseHandle(pi.hThread);
    stdin_  = child_in_w;
    stdout_ = child_out_r;

    // q0 prints a single NUL byte once it's ready. Consume it.
    char b;
    DWORD got = 0;
    if (!ReadFile(stdout_, &b, 1, &got, nullptr) || got != 1 || b != '\0') {
      if (err) err->message = "r2 -q0 handshake failed";
      shutdown();
      return false;
    }

    if (opts.analyze && opts.project.empty()) {
      // Best-effort analysis; ignore output. Some binaries have no need.
      (void)cmd("aaa");
    }
    write_ = opts.write;
    project_ = opts.project;
    // If a project was requested, check whether it already exists. If yes,
    // load it (this restores analysis so we skip `aaa`). If no, run a fresh
    // analysis and let `Ps NAME` on close persist the project. Trying to
    // load a non-existent project leaves r2 in a half-initialised state, so
    // we use `Pl` (list projects) to detect existence first.
    if (!project_.empty()) {
      bool exists = project_exists_(project_);
      if (exists) {
        (void)cmd("P " + project_);
      } else if (opts.analyze) {
        (void)cmd("aaa");
      }
    }
    return true;
  }

  bool project_exists_(const std::string& name) {
    auto list = cmd("Pl");
    size_t pos = 0;
    while (pos < list.size()) {
      size_t nl = list.find('\n', pos);
      std::string_view line(list.data() + pos,
                            (nl == std::string::npos ? list.size() : nl) - pos);
      pos = (nl == std::string::npos) ? list.size() : nl + 1;
      while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
        line.remove_suffix(1);
      while (!line.empty() && line.front() == ' ') line.remove_prefix(1);
      if (line == name) return true;
    }
    return false;
  }

  void shutdown() {
    if (stdin_) {
      // If we opened in -w with a project name, persist analysis on close.
      if (write_ && !project_.empty()) {
        std::string save = "Ps " + project_ + "\n";
        DWORD w = 0;
        WriteFile(stdin_, save.c_str(), (DWORD)save.size(), &w, nullptr);
        // Drain the response (NUL-terminated) before quitting.
        char drain;
        DWORD got = 0;
        for (int n = 0; n < 1 << 20; ++n) {
          if (!ReadFile(stdout_, &drain, 1, &got, nullptr) || got != 1) break;
          if (drain == '\0') break;
        }
      }
      const char quit[] = "q\n";
      DWORD w = 0;
      WriteFile(stdin_, quit, sizeof(quit) - 1, &w, nullptr);
      CloseHandle(stdin_);
      stdin_ = nullptr;
    }
    if (stdout_) {
      CloseHandle(stdout_);
      stdout_ = nullptr;
    }
    if (proc_) {
      WaitForSingleObject(proc_, 2000);
      TerminateProcess(proc_, 0);
      CloseHandle(proc_);
      proc_ = nullptr;
    }
  }

  std::string cmd(std::string_view command) override {
    if (!stdin_ || !stdout_) return {};
    std::lock_guard lock(m_);

    std::string line(command);
    line += '\n';
    DWORD written = 0;
    if (!WriteFile(stdin_, line.data(), static_cast<DWORD>(line.size()),
                    &written, nullptr) ||
        written != line.size()) {
      return {};
    }

    std::string out;
    out.reserve(64);
    char buf[4096];
    DWORD got = 0;
    for (;;) {
      if (!ReadFile(stdout_, buf, sizeof(buf), &got, nullptr) || got == 0) break;
      // r2 -q0 terminates each reply with a NUL byte.
      DWORD nul = static_cast<DWORD>(-1);
      for (DWORD i = 0; i < got; ++i) {
        if (buf[i] == '\0') { nul = i; break; }
      }
      if (nul != static_cast<DWORD>(-1)) {
        out.append(buf, nul);
        break;
      }
      out.append(buf, got);
    }
    return out;
  }

  bool alive() const override { return proc_ != nullptr; }
  std::string_view name() const override { return "r2pipe"; }

 private:
  std::mutex m_;
  HANDLE proc_   = nullptr;
  HANDLE stdin_  = nullptr;
  HANDLE stdout_ = nullptr;
  bool   write_  = false;
  std::string project_;
};

#else  // POSIX

class R2PipePosixBackend : public Backend {
 public:
  ~R2PipePosixBackend() override { shutdown(); }

  bool start(const R2PipeOpenOptions& opts, BackendError* err) {
    int in_p[2]  = {-1, -1};
    int out_p[2] = {-1, -1};
    if (pipe(in_p) != 0 || pipe(out_p) != 0) {
      if (err) err->message = "pipe() failed";
      return false;
    }

    std::string exe = opts.r2_executable.empty() ? "radare2" : opts.r2_executable;

    posix_spawn_file_actions_t acts;
    posix_spawn_file_actions_init(&acts);
    posix_spawn_file_actions_adddup2(&acts, in_p[0], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&acts, out_p[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&acts, in_p[0]);
    posix_spawn_file_actions_addclose(&acts, in_p[1]);
    posix_spawn_file_actions_addclose(&acts, out_p[0]);
    posix_spawn_file_actions_addclose(&acts, out_p[1]);

    std::vector<std::string> args = {exe, "-q0"};
    if (opts.write) args.emplace_back("-w");
    for (auto& a : opts.extra_args) args.push_back(a);
    if (!opts.path.empty()) args.push_back(opts.path);
    else args.emplace_back("-");

    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);

    pid_t pid = 0;
    int rc = posix_spawnp(&pid, exe.c_str(), &acts, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&acts);
    close(in_p[0]);
    close(out_p[1]);
    if (rc != 0) {
      close(in_p[1]);
      close(out_p[0]);
      if (err) err->message = std::string("posix_spawnp failed: ") + std::strerror(rc);
      return false;
    }
    pid_ = pid;
    stdin_  = in_p[1];
    stdout_ = out_p[0];

    char b;
    if (::read(stdout_, &b, 1) != 1 || b != '\0') {
      if (err) err->message = "r2 -q0 handshake failed";
      shutdown();
      return false;
    }
    if (opts.analyze && opts.project.empty()) (void)cmd("aaa");
    write_ = opts.write;
    project_ = opts.project;
    if (!project_.empty()) {
      bool exists = project_exists_(project_);
      if (exists) (void)cmd("P " + project_);
      else if (opts.analyze) (void)cmd("aaa");
    }
    return true;
  }

  bool project_exists_(const std::string& name) {
    auto list = cmd("Pl");
    size_t pos = 0;
    while (pos < list.size()) {
      size_t nl = list.find('\n', pos);
      std::string_view line(list.data() + pos,
                            (nl == std::string::npos ? list.size() : nl) - pos);
      pos = (nl == std::string::npos) ? list.size() : nl + 1;
      while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
        line.remove_suffix(1);
      while (!line.empty() && line.front() == ' ') line.remove_prefix(1);
      if (line == name) return true;
    }
    return false;
  }

  void shutdown() {
    if (stdin_ >= 0) {
      if (write_ && !project_.empty()) {
        std::string save = "Ps " + project_ + "\n";
        (void)::write(stdin_, save.c_str(), save.size());
        char drain;
        for (int n = 0; n < 1 << 20; ++n) {
          if (::read(stdout_, &drain, 1) != 1) break;
          if (drain == '\0') break;
        }
      }
      const char quit[] = "q\n";
      (void)::write(stdin_, quit, sizeof(quit) - 1);
      close(stdin_);
      stdin_ = -1;
    }
    if (stdout_ >= 0) {
      close(stdout_);
      stdout_ = -1;
    }
    if (pid_ > 0) {
      int status = 0;
      for (int i = 0; i < 20; ++i) {
        if (waitpid(pid_, &status, WNOHANG) != 0) { pid_ = -1; return; }
        usleep(50 * 1000);
      }
      kill(pid_, SIGKILL);
      waitpid(pid_, &status, 0);
      pid_ = -1;
    }
  }

  std::string cmd(std::string_view command) override {
    if (stdin_ < 0 || stdout_ < 0) return {};
    std::lock_guard lock(m_);
    std::string line(command);
    line += '\n';
    ssize_t w = ::write(stdin_, line.data(), line.size());
    if (w != static_cast<ssize_t>(line.size())) return {};

    std::string out;
    char buf[4096];
    for (;;) {
      ssize_t n = ::read(stdout_, buf, sizeof(buf));
      if (n <= 0) break;
      ssize_t nul = -1;
      for (ssize_t i = 0; i < n; ++i) if (buf[i] == '\0') { nul = i; break; }
      if (nul >= 0) { out.append(buf, nul); break; }
      out.append(buf, n);
    }
    return out;
  }

  bool alive() const override { return pid_ > 0; }
  std::string_view name() const override { return "r2pipe"; }

 private:
  std::mutex m_;
  pid_t pid_   = -1;
  int   stdin_ = -1;
  int   stdout_ = -1;
  bool  write_ = false;
  std::string project_;
};
#endif

}  // namespace

std::unique_ptr<Backend> open_r2pipe(const R2PipeOpenOptions& opts, BackendError* err) {
#ifdef _WIN32
  auto b = std::make_unique<R2PipeWinBackend>();
#else
  auto b = std::make_unique<R2PipePosixBackend>();
#endif
  if (!b->start(opts, err)) return nullptr;
  return b;
}

}  // namespace r2sql
