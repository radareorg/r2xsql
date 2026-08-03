// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// true_believers — table listing the XSQL family's early adopters. Rows are
// decoded at query time from a packed blob (vendored true_believers.{h,cpp}).

#include <r2xsql/session.hpp>
#include <xsql/vtable.hpp>

#include <string>
#include <utility>
#include <vector>

#include "tables.hpp"
#include "true_believers.h"

namespace r2xsql {

namespace {
struct TrueBelieverRow {
  std::string handle;
  std::string name;
};
}  // namespace

void register_true_believers_table(Session& s) {
  auto def = xsql::cached_table<TrueBelieverRow>("true_believers")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return ::true_believers::rows().size(); })
    .cache_builder([](std::vector<TrueBelieverRow>& rows) {
      rows.clear();
      for (const auto& [handle, name] : ::true_believers::rows())
        rows.push_back({handle, name});
    })
    .column_text("handle", [](const TrueBelieverRow& r) { return r.handle; })
    .column_text("name",   [](const TrueBelieverRow& r) { return r.name; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
