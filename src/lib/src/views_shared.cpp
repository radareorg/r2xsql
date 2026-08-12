// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// views_shared.cpp — the call-graph views every tool in this family ships:
// `callers`, `callees`, `string_refs`. Same names, same columns, same meaning
// everywhere, so a query written against one tool answers on another.
//
// They are ordinary SQL over `xrefs`/`funcs`/`imports`/`strings`, which means
// they inherit those tables' pushdown: `WHERE func_addr = X` against a view
// still reaches the scoped radare2 command rather than enumerating everything.
// That is load-bearing and is pinned by a test, not assumed.
//
// TWO PLACES WHERE THE SIBLING TOOLS' SQL IS WRONG FOR radare2, both measured
// on a real 64-bit PE binary rather than reasoned about:
//
//   1. The sibling views bound a call-graph edge with
//      `to_addr IN (SELECT addr FROM funcs)`. There, an import IS a function
//      (the engine materializes a thunk for it). In radare2 it is not: on
//      that binary, 0 of 95 imports appear in `funcs`. That filter would therefore
//      discard every call into an import — 23 of the 60 real edges, and by far
//      the most interesting ones. So an edge here is one landing on a function
//      *or* an import, expressed as joins that also supply the callee's name.
//
//   2. `from_func IS NOT NULL` is not cosmetic here, it is what makes these
//      views give one answer. radare2 has two ways to enumerate references and
//      they do not agree: the per-function walk behind a full scan cannot see a
//      reference whose source lies outside every analyzed function, while the
//      scoped `axtj` lookup behind the `to_addr` pushdown can. On that binary that
//      is a real 38-vs-34 split on the same logical question, on BOTH backends
//      (so it is radare2's semantics, not ours). Every such row has a NULL
//      `from_func` — it belongs to no function by definition — so filtering
//      them out makes these views return the same rows whichever plan SQLite
//      picks. Removing the filter would reintroduce a plan-dependent answer.

#include <r2xsql/session.hpp>
#include <xsql/database.hpp>

#include "tables.hpp"

namespace r2xsql {

void register_shared_views(Session& s) {
  // callers — who reaches this function.
  //
  // `is_code` rather than `type = 'CALL'` on purpose: a tail call compiles to a
  // jump, and radare2 reports it as CODE. Bounding the target to a function or
  // an import is what separates those real edges from the intra-function jumps
  // that make up most CODE references (124 of 134 on that same binary).
  s.db().exec(R"(
    CREATE VIEW IF NOT EXISTS callers AS
    SELECT
      x.to_addr                                        AS func_addr,
      x.from_addr                                      AS caller_addr,
      COALESCE(cf.name, printf('sub_%X', x.from_func)) AS caller_name,
      x.from_func                                      AS caller_func_addr
    FROM xrefs x
    LEFT JOIN funcs   cf ON cf.addr = x.from_func
    LEFT JOIN funcs   tf ON tf.addr = x.to_addr
    LEFT JOIN imports ti ON ti.addr = x.to_addr
    WHERE x.is_code = 1
      AND x.from_func IS NOT NULL
      AND (tf.addr IS NOT NULL OR ti.addr IS NOT NULL)
  )");

  // callees — what this function reaches. The callee may be a function or an
  // import, so its name comes from whichever matched.
  s.db().exec(R"(
    CREATE VIEW IF NOT EXISTS callees AS
    SELECT
      x.from_func                                                 AS func_addr,
      COALESCE(sf.name, printf('sub_%X', x.from_func))            AS func_name,
      x.to_addr                                                   AS callee_addr,
      COALESCE(tf.name, ti.name, printf('sub_%X', x.to_addr))     AS callee_name
    FROM xrefs x
    LEFT JOIN funcs   sf ON sf.addr = x.from_func
    LEFT JOIN funcs   tf ON tf.addr = x.to_addr
    LEFT JOIN imports ti ON ti.addr = x.to_addr
    WHERE x.is_code = 1
      AND x.from_func IS NOT NULL
      AND (tf.addr IS NOT NULL OR ti.addr IS NOT NULL)
  )");

  // names — every named address radare2 knows.
  //
  // radare2 has no separate symbol table: its FLAGS are the name table, so this
  // is a projection of `flags` rather than a new source. A view, not a table,
  // for exactly that reason — it costs no extra command and cannot drift from
  // what `flags` reports.
  //
  // DELIBERATELY NOT CURATED. radare2's flags include 800 strings and 18
  // registers on a small PE, which are not "names" in the sense the sibling
  // tools mean. The tempting move is to keep only the flagspaces that look like
  // symbols — and that is inventing a classification radare2 never made. Every
  // flag is exposed with the space radare2 actually put it in, and the caller
  // filters: `WHERE namespace = 'imports'`, `WHERE namespace <> 'strings'`, etc.
  //
  // `symbol_kind` (canonical-optional) is absent on purpose: nothing in radare2
  // reports it, and deriving it from a name prefix is the guess that
  // `flags.space` itself used to be.
  s.db().exec(R"(
    CREATE VIEW IF NOT EXISTS names AS
    SELECT
      addr           AS addr,
      name           AS name,
      realname       AS realname,
      space          AS namespace
    FROM flags
  )");

  // entities — the family-recognizable name for the composite search set
  // `grep` already builds (funcs/flags/imports/exports/sections/comments),
  // exposed under the name the sibling analysis tools use for "every named
  // thing, classified". A thin projection, not a second scan: it reads the
  // exact same cache `grep` does.
  //
  // DEVIATION, RECORDED NOT SILENT: `kind` here is r2xsql's OWN, already-
  // shipped vocabulary (`func`/`flag`/`import`/`export`/`section`/`comment`),
  // not the vocabulary the sibling tools use for their own `kind`/`entities`
  // surface. No shared vocabulary has been agreed across the family yet, and
  // rather than invent one unilaterally here, this view ships r2xsql's own
  // answer as-is. A `WHERE kind = 'function'` written against a sibling tool
  // matches ZERO rows here — the r2xsql spelling is `WHERE kind = 'func'`.
  // Do not assume this column is portable; every surface that documents this
  // view says so explicitly.
  //
  // `pattern` is deliberately not carried through: it is `grep`'s own
  // LIKE-pushdown input, not part of what "every named entity" means.
  s.db().exec(R"(
    CREATE VIEW IF NOT EXISTS entities AS
    SELECT kind, name, full_name, parent_name, addr
    FROM grep
  )");

  // string_refs — which function reads which string.
  //
  // `string_value` is the view's own family-shared column name; the base column
  // it reads is `strings.content`, which is now the canonical name too (it was
  // `text`, renamed in a clean break rather than left for this view to hide).
  s.db().exec(R"(
    CREATE VIEW IF NOT EXISTS string_refs AS
    SELECT
      s.addr                                          AS string_addr,
      s.content                                       AS string_value,
      s.length                                        AS string_length,
      x.from_addr                                     AS ref_addr,
      x.from_func                                     AS func_addr,
      COALESCE(f.name, printf('sub_%X', x.from_func)) AS func_name
    FROM strings s
    JOIN xrefs x ON x.to_addr = s.addr
    LEFT JOIN funcs f ON f.addr = x.from_func
    WHERE x.from_func IS NOT NULL
  )");
}

}  // namespace r2xsql
