// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
// Internal header: table registration functions.

#pragma once

namespace r2xsql {

class Session;

// Each register_X function builds a virtual table definition that closes
// over a long-lived state object owned by the Session, and registers it
// with `session.db()`. All tables are read-only by default; writable
// tables (comments, flags, bookmarks) additionally route mutations
// through `session.backend()`.

void register_binary_table(Session& s);
void register_bininfo_table(Session& s);  // one-row typed binary metadata (iIj), extends `binary`
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
void register_patches_table(Session& s);  // io.cache byte-patch overlay (wci-only commit)
void register_grep_table(Session& s);
void register_decompiler_table_if_available(Session& s);
void register_types_table(Session& s);
void register_types_members_table(Session& s);
void register_projects_table(Session& s);
void register_rop_gadgets_table(Session& s);
void register_rop_gadget_instructions_table(Session& s);
void register_syscalls_table(Session& s);
void register_calling_conventions_table(Session& s);
void register_classes_table(Session& s);
void register_class_methods_table(Session& s);
void register_registers_table(Session& s);  // static per-arch register profile (arpj)
void register_relocs_table(Session& s);     // relocation table (irj)
void register_libs_table(Session& s);       // linked library list (ilj)
void register_demangle_table(Session& s);   // one-row RBin demangler
void register_assemble_table(Session& s);   // one-row assembler (pa)
void register_search_asm_table(Session& s); // assemble-then-search (/a)
void register_read_cstr_table(Session& s);  // arbitrary-address cstring read (pszj)
void register_runtime_settings_table(Session& s);

// The family-shared call-graph views (callers / callees / string_refs) — plain
// SQL over the tables above, so this runs after every one of them.
void register_shared_views(Session& s);

}  // namespace r2xsql
