// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// grep — composite view over funcs/flags/imports/exports/sections/comments.
// Each row tags its source via `kind`; native records (or r2pipe command
// results) are read per query, so the view is always live. The `pattern` pseudo-column
// pushes a case-insensitive SQL `LIKE`-style filter down: `WHERE pattern = 'x%'`
// matches `name`/`full_name` without materialising the full cache. An
// unfiltered scan returns every entity flat.

#include <cctype>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_sources.hpp"

namespace r2xsql {

namespace {
struct GrepRow {
  std::string kind;
  std::string name;
  std::string full_name;
  std::string parent_name;
  int64_t     addr = 0;
};

void push_array(Backend* be, std::vector<GrepRow>& rows,
                const char* cmd, const char* kind,
                const char* addr_key, const char* name_key,
                const char* parent_key = nullptr) {
  auto arr = be->cmd_json(cmd);
  if (!arr.is_array()) return;
  for (auto& j : arr) {
    GrepRow r;
    r.kind = kind;
    r.name = json_utils::str(j, name_key);
    // `addr_key == nullptr` means "use the addr/offset auto-detect helper".
    // Use this for r2 record types whose address key is inconsistent across
    // commands (aflj/fj use `addr`; CCj uses `offset`). Concrete keys like
    // `plt`, `vaddr` should still be passed explicitly.
    r.addr = addr_key ? json_utils::i64(j, addr_key)
                      : json_utils::i64_addr(j);
    if (parent_key) r.parent_name = json_utils::str(j, parent_key);
    r.full_name = r.parent_name.empty() ? r.name
                                        : r.parent_name + "!" + r.name;
    rows.push_back(std::move(r));
  }
}

// The full entity set, shared by the flat full-scan cache and the pushdown
// iterator so both stay in lock-step with the source commands.
void build_grep_rows(Backend* be, std::vector<GrepRow>& rows) {
  if (auto* api = be->direct()) {
    auto add = [&](const char* kind, int64_t addr, const std::string& name,
                   const std::string& parent = {}) {
      rows.push_back({kind, name, parent.empty() ? name : parent + "!" + name,
                     parent, addr});
    };
    std::vector<direct::FuncRow> funcs;
    api->funcs_scan(false, false, funcs);
    for (const auto& r : funcs) add("func", r.addr, r.name);
    std::vector<direct::FlagRow> flags;
    api->flags_scan(flags, nullptr, true);
    for (const auto& r : flags) add("flag", r.addr, r.name);
    std::vector<direct::ImportRow> imports;
    api->imports_scan(imports);
    for (const auto& r : imports) add("import", r.addr, r.name, r.module);
    for (const auto& r : table_sources::symbols(be)) {
      if (!r.is_imported && r.bind == "GLOBAL") add("export", r.addr, r.name);
    }
    for (const auto& r : table_sources::sections(be)) add("section", r.addr, r.name);
    std::vector<direct::CommentRow> comments;
    api->comments_scan(comments);
    for (const auto& r : comments) add("comment", r.addr, r.text);
    return;
  }
  push_array(be, rows, "aflj",  "func",    nullptr,  "name");
  push_array(be, rows, "fj",    "flag",    nullptr,  "name");
  push_array(be, rows, "iij",   "import",  "plt",    "name", "libname");
  push_array(be, rows, "iEj",   "export",  "vaddr",  "name");
  push_array(be, rows, "iSj",   "section", "vaddr",  "name");
  // comments: `name` field holds the text.
  auto ccs = be->cmd_json("CCj");
  if (ccs.is_array()) {
    for (auto& j : ccs) {
      GrepRow r;
      r.kind      = "comment";
      r.name      = json_utils::str(j, "name");
      r.full_name = r.name;
      r.addr      = json_utils::i64_addr(j);
      rows.push_back(std::move(r));
    }
  }
}

std::string to_lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

// Case-insensitive SQL-`LIKE`-style match: `%` = any run, `_` = any one char.
bool like_match(const std::string& text_in, const std::string& pattern_in) {
  const std::string text = to_lower(text_in);
  const std::string pattern = to_lower(pattern_in);
  size_t ti = 0, pi = 0, star = std::string::npos, retry = 0;
  while (ti < text.size()) {
    if (pi < pattern.size() && (pattern[pi] == '_' || pattern[pi] == text[ti])) {
      ++ti; ++pi; continue;
    }
    if (pi < pattern.size() && pattern[pi] == '%') {
      star = pi++; retry = ti; continue;
    }
    if (star != std::string::npos) {
      pi = star + 1; ti = ++retry; continue;
    }
    return false;
  }
  while (pi < pattern.size() && pattern[pi] == '%') ++pi;
  return pi == pattern.size();
}

// Pushdown path for `WHERE pattern = '<glob>'`: build the entity set once and
// keep only rows whose name or full_name matches.
class GrepPatternIterator : public xsql::RowIterator {
  std::vector<GrepRow> rows_;
  size_t i_ = 0;
  bool started_ = false;
 public:
  GrepPatternIterator(Backend* be, const std::string& pattern) {
    // A wildcard-free pattern is treated as a substring match (wrap in %…%);
    // patterns containing % or _ are used as-is (anchored glob).
    const bool has_wild =
        pattern.find('%') != std::string::npos ||
        pattern.find('_') != std::string::npos;
    const std::string pat = has_wild ? pattern : ("%" + pattern + "%");
    std::vector<GrepRow> all;
    build_grep_rows(be, all);
    for (auto& r : all) {
      if (like_match(r.name, pat) || like_match(r.full_name, pat))
        rows_.push_back(std::move(r));
    }
  }
  bool next() override {
    if (!started_) started_ = true; else ++i_;
    return i_ < rows_.size();
  }
  bool eof() const override { return started_ && i_ >= rows_.size(); }
  void column(xsql::FunctionContext& ctx, int col) override {
    const GrepRow& r = rows_[i_];
    switch (col) {
      case 0: ctx.result_text(r.kind); break;
      case 1: ctx.result_text(r.name); break;
      case 2: ctx.result_text(r.full_name); break;
      case 3: ctx.result_text(r.parent_name); break;
      case 4: ctx.result_int64(r.addr); break;
      case 5: ctx.result_text(std::string()); break;  // pattern is input-only
      default: ctx.result_null(); break;
    }
  }
  int64_t rowid() const override { return static_cast<int64_t>(i_); }
};
}  // namespace

void register_grep_table(Session& s) {
  auto def = xsql::cached_table<GrepRow>("grep")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 4096; })
    .cache_builder([be = s.backend_ptr()](std::vector<GrepRow>& rows) {
      build_grep_rows(be, rows);
    })
    .column_text ("kind",        [](const GrepRow& r) { return r.kind; })
    .column_text ("name",        [](const GrepRow& r) { return r.name; })
    .column_text ("full_name",   [](const GrepRow& r) { return r.full_name; })
    .column_text ("parent_name", [](const GrepRow& r) { return r.parent_name; })
    .column_int64("addr",        [](const GrepRow& r) { return r.addr; })
    // `pattern` is an input-only pseudo-column (empty on a flat scan); a
    // `pattern = '<glob>'` constraint is pushed down to GrepPatternIterator.
    .column_text ("pattern",     [](const GrepRow&) { return std::string(); })
    .filter_eq_text("pattern",
      [be = s.backend_ptr()](const char* p) -> std::unique_ptr<xsql::RowIterator> {
        return std::make_unique<GrepPatternIterator>(be, p ? p : "");
      }, 25.0, 100.0)
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
