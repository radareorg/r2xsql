// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// list_funcs.cpp — minimal libr2sql consumer.
//
// Opens a binary (libr backend if available, else r2pipe), lists the
// first N functions via SQL. Demonstrates the API a third-party tool
// would use to embed r2sql.

#include <r2sql/r2sql.hpp>

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>

static void usage(const char* argv0) {
  std::fprintf(stderr,
               "usage: %s <binary-or-project> [limit]\n"
               "  Lists the first <limit> functions (default 20).\n",
               argv0);
}

int main(int argc, char** argv) {
  if (argc < 2) {
    usage(argv[0]);
    return 2;
  }

  const std::string path = argv[1];
  const int limit = (argc >= 3) ? std::atoi(argv[2]) : 20;

  std::unique_ptr<r2sql::Backend> backend;

  // Prefer libr; fall back to r2pipe if libr isn't linked or fails.
  r2sql::LibrOpenOptions libr_opts;
  libr_opts.path = path;
  backend = r2sql::open_libr(libr_opts);

  if (!backend) {
    std::fprintf(stderr, "libr backend unavailable, falling back to r2pipe...\n");
    r2sql::R2PipeOpenOptions pipe_opts;
    pipe_opts.path = path;
    backend = r2sql::open_r2pipe(pipe_opts);
  }

  if (!backend) {
    std::fprintf(stderr, "error: could not open '%s' with any backend\n",
                 path.c_str());
    return 1;
  }

  r2sql::Session sess(std::move(backend));

  const std::string sql =
      "SELECT addr, name, size FROM funcs ORDER BY size DESC LIMIT " +
      std::to_string(limit);

  auto result = sess.query(sql);
  if (!result.ok()) {
    std::fprintf(stderr, "error: query failed\n");
    return 1;
  }

  std::printf("%-18s  %-40s  %s\n", "addr", "name", "size");
  std::printf("%-18s  %-40s  %s\n", "------------------",
              "----------------------------------------", "----");
  for (auto& row : result.rows) {
    std::printf("%-18s  %-40s  %s\n",
                row[0].c_str(), row[1].c_str(), row[2].c_str());
  }
  std::printf("\n%zu rows\n", result.rows.size());

  return 0;
}
