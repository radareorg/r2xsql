// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// binary — binary info summary, canonical key/value/type shape (one row per
// fact). Columns: (key TEXT, value TEXT, type TEXT), type in {string, hex,
// bool, int}.
//
//
// Canonical core keys (family-shared names, values aliased from the raw
// radare2 facts above): tool_name, tool_version, processor (=arch),
// filetype (=bintype), image_base (=baddr, hex), entry_point (=entry),
// endianness (from endian), filename (=file), is_64bit (from bits), and
// min_addr/max_addr derived from the section (iSj) / segment (iSSj) maps
// (omitted when neither map yields addresses). The raw `bits` key doubles as
// the canonical `bits`. md5/sha256 are best-effort core keys and are not
// emitted (radare2's `it` hashing is best-effort and often skipped).

#include <r2xsql/session.hpp>
#include <r2xsql/backend.hpp>
#include <r2xsql/version.hpp>
#include <xsql/vtable.hpp>

#include <cstdint>
#include <cstdio>

#include "tables.hpp"
#include "direct.hpp"
#include "json_utils.hpp"
#include "table_sources.hpp"
#include "table_utils.hpp"

namespace r2xsql {

namespace {
using direct::BinaryRow;

std::string hex_u64(uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::string chomp(std::string s) {
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
  return s;
}

}  // namespace

void register_binary_table(Session& s) {
  auto def = xsql::cached_table<BinaryRow>("binary")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 40; })
    .cache_builder([be = s.backend_ptr()](std::vector<BinaryRow>& rows) {
      auto add = [&rows](const char* key, std::string value, const char* type) {
        rows.push_back({key, std::move(value), type});
      };

      // --- bin info (iIj): arch, bits, bintype, os, baddr, ... -----------
      // Raw keys pass through untouched; type is inferred from the JSON
      // value (bool -> bool, integral number -> int, else string).
      const auto info = table_sources::binary_info(be);
      std::string arch, bits, bintype, os_name;
      bool have_baddr = false;
      uint64_t baddr = 0;
      bool have_endian_big = false, endian_known = false;
      for (const auto& r : info) {
        rows.push_back(r);
        if (r.key == "arch") arch = r.value;
        else if (r.key == "bits") bits = r.value;
        else if (r.key == "bintype") bintype = r.value;
        else if (r.key == "os") os_name = r.value;
        else if (r.key == "baddr" && r.type == "int") {
          baddr = std::stoull(r.value);
          have_baddr = true;
        } else if (r.key == "endian") {
          endian_known = !r.value.empty();
          have_endian_big = r.value == "big" || r.value == "BE" ||
                            r.value == "be" || (r.type == "bool" && r.value == "true");
        }
      }

      // --- tool identity --------------------------------------------------
      add("r2xsql_version", r2xsql::version(), "string");  // raw key (kept)

      // --- radare2 engine identity (`?Vj`'s "version" field -- the LIVE
      //     running engine, not r2xsql's own build-time version above) ------
      {
        if (auto* api = be->direct()) {
          add("radare2_version", api->engine_version(), "string");
        } else {
          auto j = be->cmd_json("?Vj");
          if (j.is_object() && j.contains("version") && j["version"].is_string()) {
            add("radare2_version", j["version"].get<std::string>(), "string");
          }
        }
      }

      // --- input file path (ij -> core.file) ------------------------------
      const std::string file_path = table_sources::file_path(be);
      add("file", file_path, "string");

      // --- entry point + name (iej[0]) -------------------------------------
      std::string entry_hex, entry_name;
      {
        int64_t entry = 0;
        bool have_entry = false;
        if (auto* api = be->direct()) have_entry = api->entry_address(entry);
        else {
          auto j = be->cmd_json("iej");
          if (j.is_array() && !j.empty() && j[0].is_object() &&
              j[0].contains("vaddr") && j[0]["vaddr"].is_number()) {
            entry = json_utils::i64(j[0], "vaddr");
            have_entry = true;
          }
        }
        if (have_entry) {
          entry_hex = hex_u64(static_cast<uint64_t>(entry));
          add("entry", entry_hex, "hex");
          entry_name = chomp(be->cmd("fd @ " + entry_hex));
          if (!entry_name.empty()) add("entry_name", entry_name, "string");
        }
      }

      // --- counts (JSON array lengths, so they agree exactly with the
      //     corresponding tables; the `<cmd>~?` text form over-counts header
      //     and formatting lines) -------------------------------------------
      auto add_count = [&](const char* key, size_t count) {
        std::string value = std::to_string(count);
        add(key, value, "int");
        return value;
      };
      const std::string func_count = add_count("func_count", table_utils::function_starts(be).size());
      const std::string string_count = add_count("string_count", table_sources::strings(be, false).size());
      if (auto* api = be->direct()) {
        std::vector<direct::ImportRow> imports;
        api->imports_scan(imports);
        add_count("import_count", imports.size());
      } else {
        auto imports = be->cmd_json("iij");
        add_count("import_count", imports.is_array() ? imports.size() : 0);
      }
      const auto sections = table_sources::sections(be);
      const auto segments = table_sources::sections(be, true);
      const std::string section_count = add_count("section_count", sections.size());
      add_count("segment_count", segments.size());
      add_count("symbol_count", table_sources::symbols(be).size());

      // --- min/max mapped address, derived from the section map (iSj),
      //     falling back to the segment map (iSSj). Omitted honestly when
      //     neither map yields an address. -----------------------------------
      {
        bool have_range = false;
        uint64_t min_addr = 0, max_addr = 0;
        auto scan = [&](const std::vector<direct::SectionRow>& sections) {
          for (const auto& section : sections) {
            const uint64_t vaddr = section.addr;
            const uint64_t vsize = section.vsize;
            if (!vaddr || !vsize) continue;
            if (!have_range || vaddr < min_addr) min_addr = vaddr;
            if (!have_range || vaddr + vsize > max_addr) max_addr = vaddr + vsize;
            have_range = true;
          }
        };
        scan(sections);
        if (!have_range) scan(segments);
        if (have_range) {
          add("min_addr", hex_u64(min_addr), "hex");
          add("max_addr", hex_u64(max_addr), "hex");
        }
      }

      // --- canonical core keys (family-shared names; values alias the raw
      //     radare2 facts above so both spellings answer) --------------------
      add("tool_name", "r2xsql", "string");
      add("tool_version", r2xsql::version(), "string");
      if (!arch.empty())    add("processor", arch, "string");
      if (!bintype.empty()) add("filetype", bintype, "string");
      if (have_baddr)       add("image_base", hex_u64(baddr), "hex");
      if (!entry_hex.empty()) add("entry_point", entry_hex, "hex");
      if (!bits.empty())    add("is_64bit", bits == "64" ? "true" : "false", "bool");
      if (endian_known)     add("endianness", have_endian_big ? "big" : "little", "string");
      if (!file_path.empty()) add("filename", file_path, "string");

      // --- one-line summary digest (inserted FIRST: agents doing
      //     `SELECT * FROM binary` see the digest up top) --------------------
      std::string summary = arch;
      if (!bits.empty()) summary += " " + bits + "-bit";
      if (!entry_name.empty())      summary += " | entry: " + entry_name + " @ " + entry_hex;
      else if (!entry_hex.empty())  summary += " | entry: " + entry_hex;
      summary += " | funcs: " + func_count +
                 " | sections: " + section_count +
                 " | strings: " + string_count;
      rows.insert(rows.begin(), BinaryRow{"summary", summary, "string"});
    })
    .column_text("key",   [](const BinaryRow& r) { return r.key; })
    .column_text("value", [](const BinaryRow& r) { return r.value; })
    .column_text("type",  [](const BinaryRow& r) { return r.type; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2xsql
