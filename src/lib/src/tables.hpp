// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// Internal header: table registration functions.

#pragma once

namespace r2sql {

class Session;

// Each register_X function builds a virtual table definition that closes
// over a long-lived state object owned by the Session, and registers it
// with `session.db()`. All tables are read-only by default; writable
// tables (comments, flags, bookmarks) additionally route mutations
// through `session.backend()`.

void register_binary_table(Session& s);
void register_funcs_table(Session& s);
void register_locals_table(Session& s);
void register_blocks_table(Session& s);
void register_bytes_table(Session& s);
void register_cfg_edges_table(Session& s);
void register_switch_tables_table(Session& s);
void register_function_frames_table(Session& s);
void register_data_items_table(Session& s);
void register_byte_search_table(Session& s);
void register_dominators_table(Session& s);
void register_post_dominators_table(Session& s);
void register_loops_table(Session& s);
void register_instructions_table(Session& s);
void register_operands_table(Session& s);
void register_esil_tables(Session& s);  // esil_ops / esil_operands + the ir_ops family views
void register_xrefs_table(Session& s);
void register_strings_table(Session& s);
void register_imports_table(Session& s);
void register_exports_table(Session& s);
void register_sections_table(Session& s);
void register_segments_table(Session& s);
void register_io_maps_table(Session& s);
void register_flags_table(Session& s);
void register_comments_table(Session& s);
void register_bookmarks_table(Session& s);
void register_grep_table(Session& s);
void register_decompiler_table_if_available(Session& s);
void register_types_table(Session& s);
void register_types_members_table(Session& s);
void register_projects_table(Session& s);
void register_runtime_settings_table(Session& s);
void register_true_believers_table(Session& s);  // true_believers table

}  // namespace r2sql
