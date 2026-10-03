// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// direct_libr.cpp — the libr (in-process radare2) side of the `direct.hpp`
// seam. Compiled ONLY into the `r2xsql_libr` OBJECT library, alongside
// `backend_libr.cpp`; the core `r2xsql` library links no radare2 and never
// sees this TU.
//

#include "direct.hpp"
#include <nlohmann/json.hpp>

#include <r_core.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace r2xsql::direct {

namespace {

// `r_list_foreach` expands to `pos = it->data` with `data` a void*: legal C, a
// hard error in C++. Same walk, done type-safely.
template <typename T, typename F>
void for_each_rlist(RList* list, F&& fn) {
  if (!list) return;
  for (RListIter* it = list->head; it; it = it->n) {
    if (it->data) fn(static_cast<T*>(it->data));
  }
}

// `afxj` and `axfj` both print `r_anal_ref_type_tostring(ref->type)`
// unconditionally, so a zero-typed ref reads back as the literal "NULL".
std::string ref_type_string(RAnalRefType type) {
  const char* s = r_anal_ref_type_tostring(type);
  return s ? s : "";
}

std::string ref_type_string_axtj(RAnalRefType type) {
  return type ? ref_type_string(type) : std::string();
}

void set_owner(XrefRow& r, RCore* core, ut64 addr) {
  RAnalFunction* fcn = r_anal_get_fcn_in(core->anal, addr, R_ANAL_FCN_TYPE_NULL);
  if (fcn) {
    r.from_func     = static_cast<int64_t>(fcn->addr);
    r.has_from_func = true;
  }
}

// Every producer takes the owning backend's mutex, the same one `Backend::cmd`
// takes — the in-r2 plugin shares one core between its interactive and concurrent
// callers, so a direct read must not interleave with a command. It is a
// plain std::mutex, so a producer must NEVER call back into `Backend::cmd`:
// that is a self-deadlock, not a slow path. If a future port needs a command
// mid-producer, run it before taking the lock.
class LibrApi : public Api {
 public:
  LibrApi(RCore* core, std::mutex& mu) : core_(core), mu_(mu) {}

  size_t estimate_count(Collection collection) override {
    std::lock_guard lock(mu_);
    if (!core_) return 0;
    switch (collection) {
      case Collection::Functions: return r_list_length(core_->anal->fcns);
      case Collection::Flags: return r_flag_count(core_->flags, nullptr);
      case Collection::Imports: {
        RVecRBinImport* imports = r_bin_get_imports_vec(core_->bin);
        return imports ? RVecRBinImport_length(imports) : 0;
      }
      case Collection::Entries: return r_list_length(r_bin_get_entries(core_->bin));
      case Collection::Exports: {
        RVecRBinSymbol* symbols = r_bin_get_symbols_vec(core_->bin);
        return symbols ? RVecRBinSymbol_length(symbols) : 0;
      }
      case Collection::Strings: {
        RVecRBinString* strings = r_bin_get_strings(core_->bin);
        return strings ? RVecRBinString_length(strings) : 0;
      }
      case Collection::Sections:
      case Collection::Segments: {
        RVecRBinSection* sections = r_bin_get_sections_vec(core_->bin);
        if (!sections) return 0;
        size_t count = 0;
        RBinSection* section;
        R_VEC_FOREACH(sections, section) {
          if (section->is_segment == (collection == Collection::Segments)) ++count;
        }
        return count;
      }
      case Collection::Maps: {
        RIOBank* bank = r_io_bank_get(core_->io, core_->io->bank);
        return bank ? r_list_length(bank->maprefs) : 0;
      }
    }
    return 0;
  }

  std::string demangle(const std::string& mangled,
                       const std::string& lang, std::string& error) override {
    std::lock_guard lock(mu_);
    error = "Cannot demangle string";
    if (!core_ || !core_->bin) return {};
    const char* selected_lang = lang.empty()
        ? r_config_get(core_->config, "bin.lang") : lang.c_str();
    if ((!selected_lang || !*selected_lang) && lang.empty()) {
      error = "Set the language in `e bin.lang` or pass a second argument";
    }
    RBinFile temporary_file = {};
    RBinFile* file = core_->bin->cur;
    if (!file) {
      temporary_file.rbin = core_->bin;
      file = &temporary_file;
    }
    char* result = r_bin_demangle(file, selected_lang, mangled.c_str(), 0, false);
    if (!result) return {};
    std::string demangled(result);
    free(result);
    return demangled;
  }

  std::string search(const std::string& command) override {
    std::lock_guard lock(mu_);
    if (!core_) return {};
    RConfigHold* hold = r_config_hold_new(core_->config);
    if (!hold) return {};
    r_config_hold(hold, "search.in", nullptr);
    r_config_set(core_->config, "search.in", "io.maps.x");
    char* result = r_core_call_str_at(core_, core_->addr, command.c_str());
    r_config_hold_restore(hold);
    r_config_hold_free(hold);
    std::string out = result ? result : "";
    free(result);
    return out;
  }

  bool function_is_start(int64_t addr) override {
    std::lock_guard lock(mu_);
    return core_ && core_->anal &&
        r_anal_get_function_at(core_->anal, static_cast<ut64>(addr));
  }

  bool function_owner(int64_t addr, int64_t& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return false;
    RAnalFunction* fcn = r_anal_get_fcn_in(core_->anal, addr, R_ANAL_FCN_TYPE_NULL);
    if (!fcn) return false;
    out = fcn->addr;
    return true;
  }

  void function_starts(std::vector<int64_t>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    for_each_rlist<RAnalFunction>(core_->anal->fcns, [&](RAnalFunction* fcn) {
      out.push_back(fcn->addr);
    });
  }

  bool function_details(int64_t addr, bool with_prototype, FuncRow& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return false;
    RAnalFunction* fcn = r_anal_get_function_at(core_->anal, addr);
    if (!fcn) return false;
    out.addr = fcn->addr;
    out.stackframe = fcn->maxstack;
    if (const char* cc = r_anal_function_cc(fcn)) out.calltype = cc;
    if (with_prototype) {
      if (char* sig = r_anal_function_format_sig(core_->anal, fcn, nullptr,
                                                nullptr, nullptr, nullptr)) {
        r_str_trim(sig);
        out.prototype = sig;
        free(sig);
      }
    }
    return true;
  }

  bool calling_convention_exists(const std::string& name) override {
    std::lock_guard lock(mu_);
    return core_ && core_->anal && r_anal_cc_exist(core_->anal, name.c_str());
  }

  void syscalls_scan(std::vector<SyscallRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal || !core_->anal->syscall) return;
    RList* list = r_syscall_list(core_->anal->syscall);
    const char* arch = r_config_get(core_->config, "asm.arch");
    const char* os = r_config_get(core_->config, "asm.os");
    for_each_rlist<RSyscallItem>(list, [&](RSyscallItem* item) {
      out.push_back({item->name ? item->name : "", item->num,
                     arch ? arch : "", os ? os : ""});
    });
    r_list_free(list);
  }

  void registers_scan(std::vector<RegisterRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal || !core_->anal->reg) return;
    RReg* reg = core_->anal->reg;
    std::map<std::string, std::string> roles;
    for (int i = 0; i < R_REG_ALIAS_LAST; i++) {
      const char* name = r_reg_alias_getname(reg, static_cast<RRegAlias>(i));
      const char* role = r_reg_alias_tostring(static_cast<RRegAlias>(i));
      if (!name || !role) continue;
      auto& joined = roles[name];
      if (!joined.empty()) joined += ',';
      joined += role;
    }
    const char* arch = r_config_get(core_->config, "asm.arch");
    const std::string bits = std::to_string(r_config_get_i(core_->config, "asm.bits"));
    for (int i = 0; i < R_REG_TYPE_LAST; i++) {
      for_each_rlist<RRegItem>(reg->regset[i].regs, [&](RRegItem* item) {
        RegisterRow r;
        r.name = item->name ? item->name : "";
        const char* type = r_reg_type_tostring(item->type);
        r.type = type ? type : "";
        r.size = item->size;
        r.offset = item->offset;
        r.arch = arch ? arch : "";
        r.bits = bits;
        auto it = roles.find(r.name);
        if (it != roles.end()) r.role = it->second;
        out.push_back(std::move(r));
      });
    }
  }

  void calling_conventions_scan(std::vector<CallingConventionRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    std::vector<std::string> names;
    sdb_foreach(core_->anal->sdb_cc, [](void* user, const char* key, const char* value) {
      if (!strcmp(value, "cc")) static_cast<std::vector<std::string>*>(user)->push_back(key);
      return true;
    }, &names);
    std::sort(names.begin(), names.end());
    for (const auto& name : names) {
      CallingConventionRow r;
      r.name = name;
      const char* cc = name.c_str();
      if (const char* ret = r_anal_cc_ret(core_->anal, cc, 0)) {
        r.ret = ret;
        for (int i = 0; ; i++) {
          const char* value = r_anal_cc_ret(core_->anal, cc, i);
          if (!value) break;
          r.rets.emplace_back(value);
        }
        const int max = r_anal_cc_max_arg(core_->anal, cc);
        for (int i = 0; i < max; i++) {
          if (const char* arg = r_anal_cc_argloc(core_->anal, cc, i, 0, -1)) r.args.emplace_back(arg);
        }
        if (const char* arg = r_anal_cc_argloc(core_->anal, cc, max, 0, -1)) r.argn = arg;
      }
      out.push_back(std::move(r));
    }
  }

  std::vector<std::string> class_names() {
    std::vector<std::string> names;
    r_anal_class_foreach(core_->anal, [](void* user, const char* key, const char*) {
      static_cast<std::vector<std::string>*>(user)->push_back(key);
      return true;
    }, &names);
    std::sort(names.begin(), names.end());
    return names;
  }

  void classes_scan(std::vector<ClassRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    for (const auto& name : class_names()) {
      ClassRow r;
      r.name = name;
      RVecAnalBaseClass* bases = r_anal_class_base_get_all(core_->anal, name.c_str());
      if (bases && !RVecAnalBaseClass_empty(bases)) {
        const char* base = RVecAnalBaseClass_at(bases, 0)->class_name;
        if (base && *base) r.base_name = base;
      }
      RVecAnalBaseClass_free(bases);
      RVecAnalVTable* tables = r_anal_class_vtable_get_all(core_->anal, name.c_str());
      if (tables && !RVecAnalVTable_empty(tables)) r.vtable_addr = RVecAnalVTable_at(tables, 0)->addr;
      RVecAnalVTable_free(tables);
      out.push_back(std::move(r));
    }
  }

  void class_methods_scan(std::vector<ClassMethodRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    for (const auto& name : class_names()) {
      RVecAnalMethod* methods = r_anal_class_method_get_all(core_->anal, name.c_str());
      if (!methods) continue;
      RAnalMethod* method;
      R_VEC_FOREACH(methods, method) {
        ClassMethodRow r;
        r.class_name = name;
        r.name = method->name ? method->name : "";
        r.addr = method->addr;
        if (method->vtable_offset >= 0) r.vtable_offset = method->vtable_offset;
        out.push_back(std::move(r));
      }
      RVecAnalMethod_free(methods);
    }
  }

  void libs_scan(std::vector<LibRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->bin) return;
    for_each_rlist<char>(r_bin_get_libs(core_->bin), [&](char* name) {
      out.push_back({name});
    });
  }

  void projects_scan(std::vector<ProjectRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_) return;
    char* path = r_file_abspath(r_config_get(core_->config, "dir.projects"));
    if (!path) return;
    RList* entries = r_sys_dir(path);
    for_each_rlist<char>(entries, [&](char* name) {
      if (r_core_is_project(core_, name)) out.push_back({name});
    });
    r_list_free(entries);
    free(path);
  }

  std::string engine_version() override {
    std::string version = r_core_version();
    return version.substr(0, version.find('-'));
  }

  std::string file_path() override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->bin || !core_->io) return {};
    RBinInfo* info = r_bin_get_info(core_->bin);
    RIODesc* desc = r_io_desc_get(core_->io, r_io_fd_get_current(core_->io));
    const char* path = info ? info->file : (desc ? desc->name : nullptr);
    if (!path && desc) path = desc->uri;
    return path ? path : "";
  }

  bool entry_address(int64_t& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->bin) return false;
    const RList* entries = r_bin_get_entries(core_->bin);
    if (!entries) return false;
    for (RListIter* it = entries->head; it; it = it->n) {
      auto* e = static_cast<RBinAddr*>(it->data);
      if (!e || e->type != R_BIN_ENTRY_TYPE_PROGRAM) continue;
      out = r_config_get_b(core_->config, "io.va") && e->paddr != UT64_MAX
          ? r_bin_get_vaddr(core_->bin, e->paddr, e->vaddr) : e->paddr;
      return true;
    }
    return false;
  }

  void binary_info(std::vector<BinaryRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->bin) return;
    RBinInfo* info = r_bin_get_info(core_->bin);
    RBinFile* file = r_bin_cur(core_->bin);
    RBinObject* obj = r_bin_cur_object(core_->bin);
    if (!info || !file || !obj) return;
    auto str = [&](const char* key, const char* value) {
      out.push_back({key, value ? value : "", "string"});
    };
    auto boolean = [&](const char* key, bool value) {
      out.push_back({key, value ? "true" : "false", "bool"});
    };
    auto number = [&](const char* key, ut64 value) {
      if (value < UT64_MAX - 1) out.push_back({key, std::to_string(value), "int"});
    };
    bool havecode = info->arch || obj->entries;
    RBinSection* section;
    R_VEC_FOREACH(&obj->sections_vec, section) havecode |= (section->perm & R_PERM_X) != 0;
    int bits = info->bits;
    if (bits < 1) bits = r_config_get_i(core_->config, "asm.bits");
    if (bits < 1) bits = R_SYS_BITS;
    Sdb* file_info = sdb_ns(file->sdb, "info", false);
    const bool pe = info->rclass && !strcmp(info->rclass, "pe");
    const bool mdmp = info->rclass && !strcmp(info->rclass, "mdmp");
    str("arch", info->arch);
    if (R_STR_ISNOTEMPTY(info->cpu)) str("cpu", info->cpu);
    number("baddr", r_bin_get_baddr(core_->bin));
    number("binsz", r_bin_get_size(core_->bin));
    str("bintype", info->rclass);
    if (R_STR_ISNOTEMPTY(info->charset)) str("charset", info->charset);
    number("bits", bits);
    boolean("canary", info->has_canary);
    if (info->has_nobtcfi) boolean("nobtcfi", true);
    if (info->dbglink) str("dbglink", info->dbglink);
    boolean("injprot", info->has_libinjprot);
    if (info->has_retguard != -1) boolean("retguard", info->has_retguard);
    str("class", info->bclass);
    if (info->actual_checksum) str("cmp.csum", info->actual_checksum);
    str("compiled", file_info ? sdb_const_get(file_info, "image_file_header.TimeDateStamp_string", nullptr) : nullptr);
    str("compiler", info->compiler);
    const char* flags = mdmp ? sdb_const_get(file->sdb, "mdmp.flags", nullptr) : nullptr;
    if (!flags) flags = info->flags;
    if (R_STR_ISNOTEMPTY(flags)) str("flags", flags);
    if (R_STR_ISNOTEMPTY(info->abi)) str("abi", info->abi);
    boolean("crypto", info->has_crypto);
    str("dbg_file", info->debug_file_name);
    str("endian", info->big_endian ? "big" : "little");
    boolean("havecode", havecode);
    if (havecode) {
      if (info->claimed_checksum) str("hdr.csum", info->claimed_checksum);
      str("guid", info->guid);
      str("intrp", info->intrp);
      number("laddr", r_bin_get_laddr(core_->bin));
      if (info->lang && *info->lang != '?') str("lang", info->lang);
      boolean("linenum", info->dbg_info & R_BIN_DBG_LINENUMS);
      boolean("lsyms", info->dbg_info & R_BIN_DBG_SYMS);
      str("machine", info->machine);
      boolean("nx", info->has_nx);
      str("os", info->os);
      if (pe) boolean("overlay", info->pe_overlay);
      str("cc", info->default_cc);
      boolean("pic", info->has_pi);
      boolean("relocs", info->dbg_info & R_BIN_DBG_RELOCS);
      Sdb* object_info = sdb_ns(obj->kv, "info", false);
      const char* relro = object_info ? sdb_const_get(object_info, "elf.relro", nullptr) : nullptr;
      if (R_STR_ISNOTEMPTY(relro)) str("relro", relro);
      str("rpath", info->rpath);
      if (pe) boolean("signed", info->signature);
      boolean("sanitize", info->has_sanitizers);
      boolean("static", r_list_empty(obj->libs) || (info->dbg_info & R_BIN_DBG_STATIC));
      if (mdmp) {
        const int streams = sdb_num_get(file->sdb, "mdmp.streams", nullptr);
        if (streams != -1) number("streams", streams);
      }
      boolean("stripped", info->dbg_info & R_BIN_DBG_STRIPPED);
      boolean("uncaps", info->dbg_info & R_BIN_DBG_UNCAPS);
      str("subsys", info->subsystem);
      boolean("va", info->has_va);
    }
    nlohmann::json checksums = nlohmann::json::object();
    for (const auto& hash : info->sum) {
      if (!hash.type) break;
      checksums[hash.type] = {{"hex", hex_bytes(hash.buf, hash.len)}};
    }
    out.push_back({"checksums", checksums.dump(), "string"});
  }

  void relocs_scan(std::vector<RelocRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->bin) return;
    RIODesc* desc = r_io_desc_get(core_->io, r_io_fd_get_current(core_->io));
#if R2_ABIVERSION >= 144
    if (desc && r_io_desc_info(desc).isdbg) return;
#else
    if (desc && r_io_desc_is_dbg(desc)) return;
#endif
    RVecRBinReloc* relocs = r_bin_get_relocs(core_->bin);
    // `irj` applies pending relocations when requested, including the IO
    // cache/overlay routing used for relocatable object files.
    const bool apply = r_config_get_b(core_->config, "bin.relocs.apply");
    const bool cache = r_config_get_b(core_->config, "bin.cache");
    if ((apply || cache) && core_->bin->cur) {
      if (cache) {
        // `cachemode` is a bool, so radare2's own `cachemode & R_PERM_W` in
        // cbin.c is always 0 and always sets io.cache; test the bool itself.
        if (!core_->io->cachemode) r_config_set_b(core_->config, "io.cache", true);
        core_->bin->iob.overlay_write_at = apply ? r_io_cache_write_at : r_io_write_at;
      }
      relocs = r_bin_patch_relocs(core_->bin->cur);
      if (apply) {
        if (cache) core_->bin->iob.overlay_write_at = r_io_vwrite_to_overlay_at;
        else r_io_drain_overlay(core_->io);
      }
    }
    if (!relocs) return;
    const char* lang = r_config_get(core_->config, "bin.lang");
    const bool keep_lib = r_config_get_b(core_->config, "bin.demangle.pfxlib");
    RBinReloc* reloc;
    R_VEC_FOREACH(relocs, reloc) {
      RelocRow r;
      r.addr = reloc->vaddr;
      r.paddr = reloc->paddr;
      r.ntype = reloc->ntype;
      r.is_ifunc = reloc->is_ifunc;
      switch (reloc->type) {
        case 1: case 2: case 4: case 8: case 16: case 24: case 32: case 48: case 64:
          r.type = std::string(reloc->additive ? "ADD_" : "SET_") + std::to_string(reloc->type);
          break;
        default: r.type = "UNKNOWN"; break;
      }
      const char* name = reloc->import ? r_bin_name_tostring(reloc->import->name) :
          (reloc->symbol ? r_bin_name_tostring(reloc->symbol->name) : nullptr);
      if (R_STR_ISNOTEMPTY(name)) {
        r.name = name;
        const ut64 addr = reloc->paddr == UT64_MAX ? reloc->paddr :
            r_bin_get_vaddr(core_->bin, reloc->paddr, reloc->vaddr);
        char* demname = r_bin_demangle(core_->bin->cur, lang, name, addr, keep_lib);
        if (R_STR_ISNOTEMPTY(demname)) r.demname = demname;
        free(demname);
      }
      if (reloc->symbol) r.sym_vaddr = reloc->symbol->vaddr;
      out.push_back(std::move(r));
    }
  }

  std::map<std::string, std::string> type_names() {
    // Releases with lazy type loading need to refresh the target database
    // before a direct Sdb walk. This is a no-op once the target is loaded.
    r_anal_types_reload(core_->anal, nullptr, nullptr, nullptr);
    std::map<std::string, std::string> names;
    sdb_foreach(core_->anal->sdb_types, [](void* user, const char* key, const char* value) {
      if (strchr(key, '.')) return true;
      for (const char* kind : {"atomic", "type", "struct", "union", "enum", "typedef", "func"}) {
        if (!strcmp(value, kind)) {
          static_cast<std::map<std::string, std::string>*>(user)->emplace(key, kind);
          break;
        }
      }
      return true;
    }, &names);
    return names;
  }

  void type_members(const std::string& name, const std::string& kind,
                    std::vector<MemberRow>& out) {
    Sdb* db = core_->anal->sdb_types;
    if (kind == "enum") {
      RList* members = r_type_get_enum(db, name.c_str());
      for_each_rlist<RTypeEnum>(members, [&](RTypeEnum* member) {
        MemberRow r;
        r.type_name = name;
        r.parent_kind = kind;
        r.member_name = member->name ? member->name : "";
        r.array_size = 0;
        r.value = r_num_math(nullptr, member->val);
        out.push_back(std::move(r));
      });
      r_list_free(members);
      return;
    }
    if (kind != "struct" && kind != "union") return;
    const std::string key = kind + "." + name;
    char* members = sdb_get(db, key.c_str(), nullptr);
    if (!members) return;
    int64_t offset = 0;
    const int count = r_str_split(members, ',');
    for (int i = 0; i < count; i++) {
      const char* member = r_str_word_get0(members, i);
      if (!member || !*member) continue;
      int array_size = 1;
      char* type = r_type_get_member(db, (key + "." + member).c_str(), nullptr, &array_size);
      if (!type) continue;
      MemberRow r;
      r.type_name = name;
      r.parent_kind = kind;
      r.member_name = member;
      r.member_type = type;
      r.array_size = array_size > 0 ? array_size : 1;
      r.size = std::max<ut64>(1, r_anal_type_bitsize(core_->anal, type) / 8) * r.array_size;
      r.offset = offset;
      if (kind == "struct") offset += r.size;
      out.push_back(std::move(r));
      free(type);
    }
    free(members);
  }

  bool type_create(const std::string& name, const std::string& kind) override {
    std::lock_guard lock(mu_);
    const std::string declaration = kind + " " + name + " {};";
    char* error = nullptr;
    char* parsed = r_anal_cparse(core_->anal, declaration.c_str(), &error);
    free(error);
    if (!parsed) return false;
    r_anal_save_parsed_type(core_->anal, parsed);
    free(parsed);
    return sdb_exists(core_->anal->sdb_types, name.c_str());
  }

  bool type_delete(const std::string& name) override {
    std::lock_guard lock(mu_);
    r_anal_remove_parsed_type(core_->anal, name.c_str());
    return !sdb_exists(core_->anal->sdb_types, name.c_str());
  }

  bool io_map_create(int64_t addr, uint64_t size, int64_t paddr,
                     const std::string& perm, const std::string& name) override {
    std::lock_guard lock(mu_);
    const int fd = r_io_fd_get_current(core_->io);
    RIOMap* map = r_io_map_add(core_->io, fd, r_str_rwx(perm.c_str()),
                              static_cast<ut64>(paddr), static_cast<ut64>(addr), size);
    if (!map) return false;
    if (!name.empty()) r_io_map_set_name(map, name.c_str());
    return true;
  }

  bool io_map_delete(int64_t id) override {
    std::lock_guard lock(mu_);
    r_io_map_del(core_->io, static_cast<ut32>(id));
    return !r_io_map_get(core_->io, static_cast<ut32>(id));
  }

  void types_scan(std::vector<TypeRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    Sdb* db = core_->anal->sdb_types;
    for (const auto& [name, kind] : type_names()) {
      TypeRow r;
      r.ordinal = out.size();
      r.name = name;
      r.kind = kind;
      r.size = -1;
      char* format = nullptr;
      if (kind == "type") {
        const char* size = sdb_const_get(db, ("type." + name + ".size").c_str(), nullptr);
        r.size = size ? atoi(size) : -1;
        format = sdb_get(db, ("type." + name).c_str(), nullptr);
      } else if (kind == "struct" || kind == "union") {
        format = r_type_format(db, name.c_str());
        if (format) {
          std::vector<MemberRow> members;
          type_members(name, kind, members);
          r.size = 0;
          for (const auto& member : members) {
            const int64_t size = member.size * member.array_size;
            if (kind == "struct") r.size += size;
            else r.size = std::max(r.size, size);
          }
        }
      }
      if (format) {
        r_str_trim(format);
        r.format = format;
        free(format);
      }
      out.push_back(std::move(r));
    }
  }

  void type_members_scan(std::vector<MemberRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    for (const auto& [name, kind] : type_names()) {
      if (kind == "struct" || kind == "union") {
        char* format = r_type_format(core_->anal->sdb_types, name.c_str());
        if (!format) continue;
        free(format);
      }
      type_members(name, kind, out);
    }
    std::sort(out.begin(), out.end(), [](const MemberRow& a, const MemberRow& b) {
      if (a.type_name != b.type_name) return a.type_name < b.type_name;
      return a.offset < b.offset;
    });
  }

  // Mirrors the command path's `aflj` + `afxj @ <fn>` per function.
  void xrefs_scan(std::vector<XrefRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    for_each_rlist<RAnalFunction>(core_->anal->fcns, [&](RAnalFunction* fcn) {
      RVecAnalRef* refs = r_anal_function_get_refs(fcn);
      if (!refs) return;
      RAnalRef* ref;
      R_VEC_FOREACH (refs, ref) {
        XrefRow r;
        // Refs FROM a function: the varying source is `ref->at`, the target is
        // `ref->addr`. This is the OPPOSITE of `r_anal_xrefs_get` below, where
        // `at` comes back equal to the queried address on every row. Reading
        // `at` for both yields the right row COUNT and entirely wrong data.
        r.from_addr = static_cast<int64_t>(ref->at);
        r.to_addr   = static_cast<int64_t>(ref->addr);
        r.set_type(ref_type_string(ref->type));
        r.from_func     = static_cast<int64_t>(fcn->addr);
        r.has_from_func = true;
        out.push_back(std::move(r));
      }
      RVecAnalRef_free(refs);
    });
  }

  // Mirrors `axtj @ <to_addr>`.
  void xrefs_to(int64_t to_addr, std::vector<XrefRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    RVecAnalRef* refs = r_anal_xrefs_get(core_->anal, static_cast<ut64>(to_addr));
    if (!refs) return;
    RAnalRef* ref;
    R_VEC_FOREACH (refs, ref) {
      XrefRow r;
      // Refs TO an address: `at` is the queried end (constant on every row),
      // so the source is `ref->addr`.
      r.from_addr = static_cast<int64_t>(ref->addr);
      r.to_addr   = to_addr;
      r.set_type(ref_type_string_axtj(ref->type));
      set_owner(r, core_, ref->addr);
      out.push_back(std::move(r));
    }
    RVecAnalRef_free(refs);
  }

  // Mirrors one iteration of the scan — `afxj @ <func_addr>`, which resolves
  // the function containing the address and lists its references.
  void xrefs_in_func(int64_t func_addr, std::vector<XrefRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    RAnalFunction* fcn = r_anal_get_function_at(core_->anal, func_addr);
    // `from_func` is a function START, so an address merely inside a function
    // matches nothing. Without this, `afxj`'s "resolve the containing function"
    // behaviour would return that function's rows under a from_func the caller
    // never asked for — rows that violate the very constraint being pushed down.
    if (!fcn || static_cast<int64_t>(fcn->addr) != func_addr) return;
    RVecAnalRef* refs = r_anal_function_get_refs(fcn);
    if (!refs) return;
    RAnalRef* ref;
    R_VEC_FOREACH (refs, ref) {
      XrefRow r;
      r.from_addr = static_cast<int64_t>(ref->at);
      r.to_addr   = static_cast<int64_t>(ref->addr);
      r.set_type(ref_type_string(ref->type));
      r.from_func     = func_addr;
      r.has_from_func = true;
      out.push_back(std::move(r));
    }
    RVecAnalRef_free(refs);
  }

  // Mirrors `axfj @ <from_addr>`, including its owner resolution: `axfj` emits
  // no `fcn_name`/`fcn_addr` at all, so the command path resolves the owning
  // function of the source address itself with one extra `afij`.
  void xrefs_from(int64_t from_addr, std::vector<XrefRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    RVecAnalRef* refs = r_anal_refs_get(core_->anal, static_cast<ut64>(from_addr));
    if (!refs) return;
    XrefRow owner;                       // resolved once, as the command path does
    set_owner(owner, core_, static_cast<ut64>(from_addr));
    RAnalRef* ref;
    R_VEC_FOREACH (refs, ref) {
      XrefRow r;
      // Refs FROM an address: `at` is the queried end, `addr` is the target.
      r.from_addr = static_cast<int64_t>(ref->at);
      r.to_addr   = static_cast<int64_t>(ref->addr);
      r.set_type(ref_type_string(ref->type));
      r.from_func     = owner.from_func;
      r.has_from_func = owner.has_from_func;
      out.push_back(std::move(r));
    }
    RVecAnalRef_free(refs);
  }

  // Mirrors `p8 <len> @ <addr>` — the same IO read, without rendering the bytes
  // to a hex string and parsing them back.
  bool read_bytes(int64_t addr, size_t len, std::vector<uint8_t>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->io || len == 0) return false;
    std::vector<uint8_t> buf(len);
    if (!r_io_read_at(core_->io, static_cast<ut64>(addr), buf.data(),
                      static_cast<int>(len))) {
      return false;
    }
    out = std::move(buf);
    return true;
  }

  // Mirrors `aflj`, whose per-function object radare2 builds in
  // `fcn_print_json` (libr/core/canal.c). Every field below uses the SAME call
  // that emitter uses — three of them are NOT the obvious struct member, and
  // each was verified against that function rather than guessed:
  //
  //   * `name` is `r_core_anal_fcn_name`, not `fcn->name`: it applies the
  //     demangler when `bin.demangle` is on, so the raw member can differ.
  //   * `calltype` is `r_anal_function_cc`, not `fcn->callconv`: the member can
  //     still hold the unresolved "dyncc" marker until that call resolves it.
  //   * `edges` is `r_anal_function_count_edges`, not a hand count of each
  //     block's jump/fail targets. Those can disagree, and only one of them is
  //     what `aflj` prints.
  //
  // A field-by-field parity test against the command path guards all nine.
  void funcs_scan(bool with_prototype, bool with_cost,
                  std::vector<FuncRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    for_each_rlist<RAnalFunction>(core_->anal->fcns, [&](RAnalFunction* fcn) {
      FuncRow r;
      fill_func_row(fcn, with_prototype, with_cost, r);
      out.push_back(std::move(r));
    });
  }

  // One function, by its exact START address: the `WHERE addr = X` lookup a
  // JOIN or correlated subquery onto `funcs` issues per outer row. An address
  // inside a function (not its entry) answers false, as `addr = X` requires.
  bool func_at(int64_t addr, bool with_prototype, bool with_cost,
               FuncRow& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return false;
    RAnalFunction* fcn =
        r_anal_get_function_at(core_->anal, static_cast<ut64>(addr));
    if (!fcn) return false;
    fill_func_row(fcn, with_prototype, with_cost, out);
    return true;
  }

  // Reads one function into a FuncRow -- shared by `funcs_scan` and `func_at`
  // so a filtered row and a scanned row can never drift. Caller holds `mu_`.
  void fill_func_row(RAnalFunction* fcn, bool with_prototype, bool with_cost,
                     FuncRow& r) {
    r.addr = static_cast<int64_t>(fcn->addr);
    if (char* name = r_core_anal_fcn_name(core_, fcn)) {
      r.name = name;
      free(name);
    }
    r.size = static_cast<int64_t>(r_anal_function_linear_size(fcn));
    r.nbbs = static_cast<int64_t>(r_list_length(fcn->bbs));
    int ebbs = 0;
    r.edges = r_anal_function_count_edges(fcn, &ebbs);
    r.cc    = r_anal_function_complexity(fcn);
    if (const char* t = r_anal_functiontype_tostring(fcn->type)) r.type = t;
    // `aflj` omits `calltype` entirely when radare2 has none, which reads
    // back as the empty string — so an absent convention must stay empty
    // rather than becoming some default.
    if (const char* cc = r_anal_function_cc(fcn)) r.calltype = cc;

    // The fields `aflj` emits and the table used to drop. Same calls
    // `fcn_print_json` makes, in the same order.
    r.end_addr    = static_cast<int64_t>(r_anal_function_max_addr(fcn));
    r.ninstrs     = r_anal_function_instrcount(fcn);
    r.stackframe  = fcn->maxstack;
    if (with_cost) r.cost = r_anal_function_cost(fcn);
    r.tracecov    = r_anal_function_coverage(fcn);
    r.is_noreturn = fcn->is_noreturn;
    r.is_pure     = r_anal_function_purity(fcn);
    // `recursive` has no single call behind it: radare2 computes it inline
    // (a static helper) as "does this function call itself". Same test here.
    if (RVecAnalRef* calls = r_core_anal_fcn_get_calls(core_, fcn)) {
      RAnalRef* callref;
      R_VEC_FOREACH (calls, callref) {
        if (callref->addr == fcn->addr) { r.is_recursive = true; break; }
      }
      RVecAnalRef_free(calls);
    }
    if (with_prototype) {
      // `aflj` fills `signature` by running `afcf`, which is
      // r_anal_function_format_sig with the function's own name (the NULL
      // default below), then trimming. Note this is a DIFFERENT function
      // from r_anal_function_get_signature_string, which formats its own way.
      if (char* sig = r_anal_function_format_sig(core_->anal, fcn, nullptr,
                                                 nullptr, nullptr, nullptr)) {
        r_str_trim(sig);
        r.prototype = sig;
        free(sig);
      }
    }
  }

  // Reads one RAnalBlock into BlockData — shared by both `blocks_in_func` and
  // `blocks_scan` below so the two can never drift on what a block carries.
  static void fill_block(RAnalBlock* b, BlockData& d) {
    d.addr = static_cast<int64_t>(b->addr);
    d.size = static_cast<int64_t>(b->size);
    if (b->jump != UT64_MAX) { d.has_jump = true; d.jump = static_cast<int64_t>(b->jump); }
    if (b->fail != UT64_MAX) { d.has_fail = true; d.fail = static_cast<int64_t>(b->fail); }
    if (b->switch_op) {
      RAnalSwitchOp* sw = b->switch_op;
      d.has_switch = true;
      d.switch_instr_addr = static_cast<int64_t>(sw->addr);
      d.switch_has_min = true; d.switch_min = static_cast<int64_t>(sw->min_val);
      d.switch_has_max = true; d.switch_max = static_cast<int64_t>(sw->max_val);
      d.switch_has_default = true; d.switch_default = static_cast<int64_t>(sw->def_val);
      // sw->daddr (the jump table's own memory address) is deliberately NOT
      // read here — see BlockData's comment in direct.hpp for why it never
      // reaches `switch_tables.table_addr`.
      for_each_rlist<RAnalCaseOp>(sw->cases, [&](RAnalCaseOp* cop) {
        SwitchCaseData sc;
        sc.addr  = static_cast<int64_t>(cop->addr);
        sc.jump  = static_cast<int64_t>(cop->jump);
        sc.value = static_cast<int64_t>(cop->value);
        d.switch_cases.push_back(sc);
      });
    }
  }

  // Mirrors `afbj @ <func_addr>`: one function's block list, read straight
  // from `fcn->bbs` instead of parsed JSON.
  void blocks_in_func(int64_t func_addr, std::vector<BlockData>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    RAnalFunction* fcn = r_anal_get_fcn_in(core_->anal, static_cast<ut64>(func_addr),
                                           R_ANAL_FCN_TYPE_NULL);
    // afbj resolves the function CONTAINING the address; the pushdown these
    // tables use is always keyed on a function START, so mirror that here too
    // — an address merely inside a function must not silently answer for it.
    if (!fcn || static_cast<int64_t>(fcn->addr) != func_addr) return;
    for_each_rlist<RAnalBlock>(fcn->bbs, [&](RAnalBlock* b) {
      BlockData d;
      fill_block(b, d);
      out.push_back(std::move(d));
    });
  }

  // Mirrors `aflj` + N×`afbj @ <fa>`: every function's block list, read
  // straight from `core->anal->fcns` + each function's `fcn->bbs` — no
  // commands at all.
  void blocks_scan(
      std::vector<std::pair<int64_t, std::vector<BlockData>>>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    for_each_rlist<RAnalFunction>(core_->anal->fcns, [&](RAnalFunction* fcn) {
      std::vector<BlockData> blocks;
      for_each_rlist<RAnalBlock>(fcn->bbs, [&](RAnalBlock* b) {
        BlockData d;
        fill_block(b, d);
        blocks.push_back(std::move(d));
      });
      out.emplace_back(static_cast<int64_t>(fcn->addr), std::move(blocks));
    });
  }

  static std::string base_delta_ref(const char* base, int64_t delta) {
    const std::string b = base ? base : "";
    char buf[48];
    if (delta < 0) {
      const uint64_t magnitude = uint64_t{0} - static_cast<uint64_t>(delta);
      std::snprintf(buf, sizeof(buf), "%s-0x%llx", b.c_str(),
                    static_cast<unsigned long long>(magnitude));
    } else {
      std::snprintf(buf, sizeof(buf), "%s+0x%llx", b.c_str(),
                    static_cast<unsigned long long>(delta));
    }
    return std::string(buf);
  }

  // Mirrors `aflj` + N×`afvj @ <fa>`: every function's variables/arguments,
  // read straight from `fcn->vars` — no command, no per-function JSON DOM.
  // Reproduces three quirks of `r_anal_var_list_show` (the literal `afvj`
  // emitter, `libr/anal/var.c:1888-2033`) verified by reading that function,
  // not assumed from the struct:
  //
  //   * For a REG-kind var, `delta` is a REGISTER INDEX (resolved through
  //     `r_reg_index_get`), not a byte offset — unlike SPV/BPV, where it is
  //     added to `fcn->maxstack`/`fcn->bp_off`.
  //   * A REG-kind var whose index does not resolve is DROPPED entirely, not
  //     emitted with an empty ref — reproduced with `continue`, not a
  //     placeholder row, so a row-count mismatch would surface a real bug.
  //   * A REG-kind var's `kind` is always the literal "reg", never "arg",
  //     regardless of `isarg` — SPV/BPV report "arg"/"var" from `isarg`.
  //
  // `storage` uses r2xsql's OWN naming (see LocalRow's comment in
  // direct.hpp): SPV -> "stack", BPV -> "spv" — the opposite of what the
  // letters suggest.
  void locals_scan(std::vector<LocalRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return;
    for_each_rlist<RAnalFunction>(core_->anal->fcns, [&](RAnalFunction* fcn) {
      RAnalVar** it;
      R_VEC_FOREACH(&fcn->vars, it) {
        RAnalVar* var = *it;
        if (!var || !var->name || !*var->name) continue;

        LocalRow r;
        r.func_addr = static_cast<int64_t>(fcn->addr);
        r.name      = var->name;
        r.type      = var->type ? var->type : "";
        r.size      = 0;  // afvj carries no size on either leg

        switch (var->kind) {
          case R_ANAL_VAR_KIND_REG: {
            RRegItem* ri = r_reg_index_get(core_->anal->reg, var->delta);
            if (!ri) continue;  // afvj silently omits this row too
            r.kind        = "reg";
            r.storage     = "reg";
            r.storage_ref = ri->name ? ri->name : "";
            break;
          }
          case R_ANAL_VAR_KIND_SPV: {
            const char* spreg = r_reg_alias_getname(core_->anal->reg, R_REG_ALIAS_SP);
            r.kind        = var->isarg ? "arg" : "var";
            r.storage     = "stack";
            r.storage_ref = base_delta_ref(spreg ? spreg : "SP",
                                           static_cast<int64_t>(var->delta) + fcn->maxstack);
            break;
          }
          case R_ANAL_VAR_KIND_BPV: {
            const char* bpreg = r_reg_alias_getname(core_->anal->reg, R_REG_ALIAS_BP);
            r.kind        = var->isarg ? "arg" : "var";
            r.storage     = "spv";
            r.storage_ref = base_delta_ref(bpreg ? bpreg : "BP",
                                           static_cast<int64_t>(var->delta) + fcn->bp_off);
            break;
          }
          default:
            continue;
        }
        out.push_back(std::move(r));
      }
    });
  }

  // Decode mask for `instructions`' REPORTED-DATA columns -- matches what the
  // command path's own `pdfj`/`pdj` emitter requests for JSON output
  // (`ds->decode_mask`, `disasm.c:1049-1051`: BASIC|HINT|VAL|DISASM, plus
  // ESIL unconditionally since `for_json` is always true for pdfj/pdj) MINUS
  // `R_ARCH_OP_MASK_DISASM` -- that mask only fills `RAnalOp->mnemonic`,
  // rendered text this producer never reads (mnemonic/disasm always come
  // from the unchanged command path; see InsnRow's comment in direct.hpp).
  static constexpr RAnalOpMask kInsnMask = static_cast<RAnalOpMask>(
      R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT | R_ARCH_OP_MASK_VAL |
      R_ARCH_OP_MASK_ESIL);

  static std::string hex_bytes(const uint8_t* p, size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
      out.push_back(digits[p[i] >> 4]);
      out.push_back(digits[p[i] & 0xf]);
    }
    return out;
  }

  // Decodes one RAnalOp at `addr` from `buf[off..)` (`buf_len - off` bytes
  // available) into an InsnRow. Mirrors the command path's own invalid-decode
  // row (`libr/core/disasm.c:7881-7897`) on a decode failure: size=1,
  // `bytes` = that one raw byte, `type` = "invalid", no esil/family key
  // (json_utils reads an absent key as ""). Returns the number of bytes
  // consumed (always >= 1), so callers advance the same amount pdfj/pdj do.
  static int decode_one_insn(RAnal* anal, ut64 addr, const uint8_t* buf,
                             int buf_len, int64_t func_addr, InsnRow& r) {
    r.addr      = static_cast<int64_t>(addr);
    r.func_addr = func_addr;
    RAnalOp op;
    int ret = r_anal_op(anal, &op, addr, buf, buf_len, kInsnMask);
    if (ret < 1 || op.size < 1) {
      r.size    = 1;
      r.bytes   = hex_bytes(buf, 1);
      r.op_type = "invalid";
      r_anal_op_fini(&op);
      return 1;
    }
    r.size  = op.size;
    r.bytes = hex_bytes(buf, static_cast<size_t>(op.size));
    r.esil  = R_STRBUF_SAFEGET(&op.esil);
    if (const char* t = r_anal_optype_tostring(op.type)) r.op_type = t;
    if (const char* f = r_anal_op_family_tostring(op.family)) r.family = f;
    const int consumed = op.size;
    r_anal_op_fini(&op);
    return consumed;
  }

  // One function's instructions, walked over `fcn->bbs` SORTED BY ADDRESS --
  // matching `pdfj`'s own `bb_cmpaddr` sort (`cmd_print.inc.c`), which is
  // what makes a non-contiguous function (a block below the function's own
  // entry address -- real, e.g. a shared-prologue PE entry point) come out
  // right: measured live against this exact shape on a 64-bit PE's `entry0`
  // and confirmed exact parity.
  void instructions_for_func(RAnalFunction* fcn, std::vector<InsnRow>& out) {
    struct Bb { ut64 addr; int size; };
    std::vector<Bb> bbs;
    for_each_rlist<RAnalBlock>(fcn->bbs, [&](RAnalBlock* b) {
      if (b->size > 0) bbs.push_back({b->addr, static_cast<int>(b->size)});
    });
    std::sort(bbs.begin(), bbs.end(),
              [](const Bb& a, const Bb& b) { return a.addr < b.addr; });

    std::vector<uint8_t> buf;
    for (const Bb& bb : bbs) {
      buf.assign(static_cast<size_t>(bb.size), 0);
      if (!r_io_read_at(core_->io, bb.addr, buf.data(), bb.size)) continue;
      int i = 0;
      while (i < bb.size) {
        InsnRow r;
        int consumed = decode_one_insn(core_->anal, bb.addr + i, buf.data() + i,
                                       bb.size - i, static_cast<int64_t>(fcn->addr), r);
        out.push_back(std::move(r));
        i += consumed;
      }
    }
  }

  // Mirrors `pdfj @ <func_addr>` minus disasm/mnemonic. `out` is left empty
  // if `func_addr` is not a function start -- the same START-only contract
  // `blocks_in_func`/`xrefs_in_func` already enforce, and the shape
  // `tables_instructions.cpp`'s existing `func_addr` pushdown already has
  // (an address merely inside a function must not silently answer for it).
  void instructions_in_func(int64_t func_addr, std::vector<InsnRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal || !core_->io) return;
    RAnalFunction* fcn = r_anal_get_fcn_in(core_->anal, static_cast<ut64>(func_addr),
                                           R_ANAL_FCN_TYPE_NULL);
    if (!fcn || static_cast<int64_t>(fcn->addr) != func_addr) return;
    instructions_for_func(fcn, out);
  }

  // Mirrors `aflj` + N x `pdfj @ <fa>` minus disasm/mnemonic: every
  // function's instructions, in `core->anal->fcns` order (the same order
  // `aflj` walks), each row's `func_addr` naming its owner.
  void instructions_scan(std::vector<InsnRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal || !core_->io) return;
    for_each_rlist<RAnalFunction>(core_->anal->fcns, [&](RAnalFunction* fcn) {
      instructions_for_func(fcn, out);
    });
  }

  // Mirrors `pdj <count> @ <start_addr>` minus disasm/mnemonic: a linear
  // walk, NOT bb-scoped (see InsnRow's comment in direct.hpp for why
  // `func_addr` stays 0 on every row here). Refills its read buffer from IO
  // whenever fewer than 32 bytes remain -- the same low-water threshold the
  // command path's own `pdj` loop uses (`disasm.c`, `i >= nb_bytes - 32`,
  // confirmed by measurement), since the longest x86 instruction is under
  // 16 bytes and every other arch this project targets is shorter still.
  void instructions_range(int64_t start_addr, int64_t count,
                          std::vector<InsnRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal || !core_->io || count <= 0) return;
    constexpr int kBufSize = 256;
    constexpr int kLowWater = 32;
    std::vector<uint8_t> buf(kBufSize, 0);
    ut64 addr = static_cast<ut64>(start_addr);
    int off = 0;
    if (!r_io_read_at(core_->io, addr, buf.data(), kBufSize)) return;
    for (int64_t n = 0; n < count; ++n) {
      if (off >= kBufSize - kLowWater) {
        addr += static_cast<ut64>(off);
        if (!r_io_read_at(core_->io, addr, buf.data(), kBufSize)) break;
        off = 0;
      }
      InsnRow r;
      int consumed = decode_one_insn(core_->anal, addr + static_cast<ut64>(off),
                                     buf.data() + off, kBufSize - off,
                                     /*func_addr=*/0, r);
      out.push_back(std::move(r));
      off += consumed;
    }
  }

  // Mirrors `fj` (full dump) + N x `fs <name>; fj; fs *` (real-space
  // attribution) -- read straight off `RFlagItem` via `r_flag_foreach`, one
  // pass, no command, no per-flagspace re-listing at all.
  //
  // `r_flag_foreach` (FOREACH_BODY(true), flag.c:1316-1335) walks the flag
  // database's `by_addr` skiplist unconditionally -- unlike the `fj` COMMAND,
  // which is filtered to the currently-selected flagspace
  // (`r_flag_foreach_space(f, r_flag_space_cur(f), ...)`, flag.c:551/595) --
  // so this producer needs no `fs`/session-state save-select-restore dance:
  // `fi->space->name` is the real flagspace already, read straight off the
  // item.
  //
  // `realname` reproduces `print_flag_json`'s own POINTER-EQUALITY test
  // (flag.c:429: `if (fi->realname && fi->name != fi->realname)`), not a
  // string-content comparison: `set_name` (flag.c:181-186) points a fresh
  // flag's `realname` at the exact same pooled string as `name` until
  // something (e.g. demangling) gives it a genuinely distinct one, so the
  // common case must read back "" here too, exactly as the command path's
  // `fj` does when the JSON key is absent.
  void flags_scan(std::vector<FlagRow>& out, const char* space, bool current_space) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->flags) return;
    RSpace* selected = space ? r_flag_space_get(core_->flags, space) :
        (current_space ? r_flag_space_cur(core_->flags) : nullptr);
    if (space && !selected) return;
    struct Ctx {
      std::vector<FlagRow>* out;
    } ctx{&out};
    r_flag_foreach_space(
        core_->flags, selected,
        [](RFlagItem* fi, void* user) -> bool {
          auto* c = static_cast<Ctx*>(user);
          FlagRow r;
          r.addr = static_cast<int64_t>(fi->addr);
          r.size = static_cast<int64_t>(fi->size);
          r.name = fi->name ? fi->name : "";
          r.realname = (fi->realname && fi->name != fi->realname) ? fi->realname : "";
          r.space = (fi->space && fi->space->name) ? fi->space->name : "";
          c->out->push_back(std::move(r));
          return true;  // never stop early -- a full scan
        },
        &ctx);
  }

  bool flag_at(const std::string& name, const std::string& space, int64_t addr) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->flags) return false;
    RFlagItem* item = r_flag_get(core_->flags, name.c_str());
    return item && item->addr == static_cast<ut64>(addr) && item->space &&
        space == item->space->name;
  }

  // Mirrors `izj` (`_print_strings`'s JSON branch, libr/core/cbin.c). That
  // command handler already calls `r_bin_get_strings` itself -- this walks
  // the SAME `RVecRBinString` in the SAME order the command path re-parses
  // from JSON, so the two producers agree row-for-row positionally, not just
  // by content. `section` has no backing field on `RBinString` -- resolved
  // per row via `r_bin_get_section_at`; `vaddr` is rebased through
  // `r_bin_get_vaddr`; `type` is rendered through `r_bin_string_type`. The
  // `r_bin_string_filter`/`bin.str.min`/`bin.str.max` gate the emitter
  // applies is reproduced here too (defaults are permissive: both 0).
  void strings_scan(bool with_content, std::vector<StringRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->bin) return;
    RVecRBinString* list = r_bin_get_strings(core_->bin);
    if (!list) return;
    RBinObject* obj = r_bin_cur_object(core_->bin);
    const int minstr = r_config_get_i(core_->config, "bin.str.min");
    const int maxstr = r_config_get_i(core_->config, "bin.str.max");
    RBinString* s;
    R_VEC_FOREACH(list, s) {
      const ut64 vaddr = r_config_get_b(core_->config, "io.va") && s->paddr != UT64_MAX
          ? r_bin_get_vaddr(core_->bin, s->paddr, s->vaddr) : s->paddr;
      if (!r_bin_string_filter(core_->bin, s->string, vaddr)) continue;
      if (static_cast<int>(s->length) < minstr) continue;
      if (maxstr && static_cast<int>(s->length) > maxstr) continue;

      StringRow r;
      r.addr   = static_cast<int64_t>(vaddr);
      r.length = static_cast<int64_t>(s->length);
      r.size = static_cast<int64_t>(s->size);
      RBinSection* sec = obj ? r_bin_get_section_at(obj, s->paddr, 0) : nullptr;
      r.section = (sec && sec->name) ? sec->name : "";
      if (const char* t = r_bin_string_type(s->type)) r.type = t;
      if (with_content) r.content = s->string ? s->string : "";
      r.paddr = static_cast<int64_t>(s->paddr);
      out.push_back(std::move(r));
    }
  }

  // Mirrors `bin_sections` (libr/core/cbin.c), which drives BOTH `iSj`
  // (`want_segment=false`) and `iSSj` (`want_segment=true`) off the SAME
  // `RVecRBinSection`, filtered by `is_segment` in opposite directions.
  // `perm` is rendered through `r_str_srwx_i`, not the raw bitmask; `addr`
  // downgrades to no rebase for a section lacking R_PERM_R, matching the
  // emitter's own `va_sect` branch exactly.
  void sections_scan(bool want_segment, std::vector<SectionRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->bin || !core_->bin->cur) return;
    // `iSj`/`iSSj` select the binary's descriptor before reading sections.
    // Preserve that selection for subsequent physical IO reads.
    r_io_use_fd(core_->io, core_->bin->cur->fd);
    RVecRBinSection* secs = r_bin_get_sections_vec(core_->bin);
    if (!secs) return;
    const bool io_va = r_config_get_b(core_->config, "io.va");
    RBinSection* s;
    R_VEC_FOREACH(secs, s) {
      if (s->is_segment != want_segment) continue;
      const int64_t addr = io_va && !(s->perm & R_PERM_R) ? s->vaddr :
          (io_va && s->paddr != UT64_MAX
              ? r_bin_get_vaddr(core_->bin, s->paddr, s->vaddr) : s->paddr);
      SectionRow r;
      r.addr  = addr;
      r.vsize = static_cast<int64_t>(s->vsize);
      r.paddr = static_cast<int64_t>(s->paddr);
      r.size  = static_cast<int64_t>(s->size);
      r.name  = s->name ? s->name : "";
      if (const char* p = r_str_srwx_i(static_cast<int>(s->perm))) r.perm = p;
      out.push_back(std::move(r));
    }
  }

  // Mirrors `bin_imports` (libr/core/cbin.c) field-by-field: `name` goes
  // through `r_bin_name_tostring` then (if `bin.demangle`) `r_bin_demangle`,
  // reshaped to "sym.imp.<demangled>" on success; `addr` ("plt") is
  // `r_core_bin_impaddr`, computed from the PRE-demangle name and gated on
  // `info->has_lit`. Every helper here is a public `R_API` call -- none of
  // this reimplements radare2's demangling or address-resolution logic.
  void imports_scan(std::vector<ImportRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->bin) return;
    RBinInfo* info = r_bin_get_info(core_->bin);
    if (!info) return;
    const bool bin_demangle = r_config_get_b(core_->config, "bin.demangle");
    const bool keep_lib = r_config_get_b(core_->config, "bin.demangle.pfxlib");
    const bool lit = info->has_lit;
    const bool va = r_config_get_b(core_->config, "io.va");

    RVecRBinImport* imports = r_bin_get_imports_vec(core_->bin);
    if (!imports) return;
    RBinImport* imp;
    R_VEC_FOREACH(imports, imp) {
      char* iname = r_bin_name_tostring(imp->name);
      std::string symname = iname ? iname : "";

      int64_t addr = lit
          ? static_cast<int64_t>(r_core_bin_impaddr(core_->bin, va ? 1 : 0, symname.c_str()))
          : 0;

      if (bin_demangle) {
        char* dname = r_bin_demangle(core_->bin->cur, nullptr, symname.c_str(),
                                      static_cast<ut64>(addr), keep_lib);
        if (dname && *dname) symname = std::string("sym.imp.") + dname;
        free(dname);
      }
      if (core_->bin->prefix) {
        symname = std::string(core_->bin->prefix) + "." + symname;
      }

      ImportRow r;
      r.ordinal = static_cast<int64_t>(imp->ordinal);
      r.bind    = imp->bind ? imp->bind : "";
      r.type    = imp->type ? imp->type : "";
      r.name    = symname;
      r.module  = imp->libname ? imp->libname : "";
      r.addr    = (addr && addr != static_cast<int64_t>(UT64_MAX)) ? addr : 0;
      out.push_back(std::move(r));
    }
  }

  // Merges one incoming row into the by-address map, byte-for-byte the same
  // rule as `tables_exports.cpp`'s own `merge_row`: richer (`prefer_fields`)
  // data replaces sparse fields at a duplicate address; sparse data never
  // overwrites something already there.
  static void merge_entry(std::map<int64_t, EntryRow>& by_addr, EntryRow incoming,
                           bool prefer_fields) {
    auto [it, inserted] = by_addr.emplace(incoming.addr, incoming);
    if (inserted) return;
    EntryRow& current = it->second;
    auto merge_text = [prefer_fields](std::string& dst, const std::string& src) {
      if (!src.empty() && (prefer_fields || dst.empty())) dst = src;
    };
    if (incoming.size != 0 && (prefer_fields || current.size == 0)) current.size = incoming.size;
    merge_text(current.type, incoming.type);
    merge_text(current.bind, incoming.bind);
    merge_text(current.name, incoming.name);
  }

  void io_maps_scan(std::vector<IoMapRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->io) return;
    RIOBank* bank = r_io_bank_get(core_->io, core_->io->bank);
    if (!bank || !bank->maprefs) return;
    for (RListIter* it = bank->maprefs->tail; it; it = it->p) {
      auto* ref = static_cast<RIOMapRef*>(it->data);
      RIOMap* map = r_io_map_get_by_ref(core_->io, ref);
      if (!map) continue;
      out.push_back({static_cast<int64_t>(r_io_map_begin(map)),
          static_cast<int64_t>(r_io_map_end(map)), static_cast<int64_t>(map->delta),
          map->id, map->fd, r_str_rwx_i(map->perm & R_PERM_RWX),
          map->name ? map->name : ""});
    }
  }

  void patches_scan(std::vector<PatchRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->io) return;
    auto* layer = static_cast<RIOCacheLayer*>(r_list_last(core_->io->cache.layers));
    if (!layer || !layer->vec) return;
    RIOCacheItem** it;
    R_VEC_FOREACH(layer->vec, it) {
      RIOCacheItem* item = *it;
      PatchRow r;
      r.addr = r_itv_begin(item->itv);
      r.size = r_itv_size(item->itv);
      char* original = r_hex_bin2strdup(item->odata, r.size);
      char* patched = r_hex_bin2strdup(item->data, r.size);
      r.original_bytes = original ? original : "";
      r.patched_bytes = patched ? patched : "";
      free(original);
      free(patched);
      r.committed = item->written;
      out.push_back(std::move(r));
    }
    if (!out.empty()) out.back().is_stack_top = true;
  }

  void symbols_scan(std::vector<SymbolRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->bin) return;
    RVecRBinSymbol* symbols = r_bin_get_symbols_vec(core_->bin);
    if (!symbols) return;
    RBinSymbol* sym;
    R_VEC_FOREACH(symbols, sym) {
      const char* display_name = r_bin_name_tostring(sym->name);
      if (!display_name) continue;
      SymbolRow r;
      r.addr = sym->paddr == UT64_MAX ? sym->vaddr :
          (r_config_get_b(core_->config, "io.va")
              ? r_bin_get_vaddr(core_->bin, sym->paddr, sym->vaddr) : sym->paddr);
#if R2_ABIVERSION >= 136
      r.size = sym->attr.size;
#else
      r.size = sym->size;
#endif
      r.type = sym->type ? sym->type : "";
      r.bind = sym->bind ? sym->bind : "";
      r.is_imported = sym->is_imported;
      const char* name = r_bin_name_tostring2(sym->name, 'o');
      if (!name) name = display_name;
      if (name) {
        char* escaped = r_str_escape_utf8(name, false, true);
        r.name = escaped ? escaped : name;
        free(escaped);
      }
      out.push_back(std::move(r));
    }
  }

  // Mirrors `tables_exports.cpp`'s cache_builder exactly: `r_bin_get_entries`
  // (RBinAddr, `R_BIN_ENTRY_TYPE_PROGRAM` only -- the same filter `iej`'s
  // handler uses) merged with `r_bin_get_symbols_vec` filtered by
  // `its_an_export` (`!is_imported && bind == "GLOBAL"`, reproduced rather
  // than called since the real helper is `static` in radare2). `iej` never
  // emits name/size/bind (only `type`, when non-empty) -- reproduced by
  // leaving those fields at their defaults on the entry-point pass.
  // `entries.name` is the ORIGINAL name (`r_bin_name_tostring2(.., 'o')`),
  // NOT the demangled one -- that lives under a "demname" key this table
  // never reads.
  void entries_scan(std::vector<EntryRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->bin) return;
    std::map<int64_t, EntryRow> by_addr;

    const RList* entries = r_bin_get_entries(core_->bin);
    for_each_rlist<RBinAddr>(const_cast<RList*>(entries), [&](RBinAddr* e) {
      if (e->type != R_BIN_ENTRY_TYPE_PROGRAM) return;
      const int64_t vaddr = (e->paddr == UT64_MAX)
          ? static_cast<int64_t>(e->vaddr)
          : static_cast<int64_t>(r_bin_get_vaddr(core_->bin, e->paddr, e->vaddr));
      EntryRow r;
      r.addr = vaddr;
      if (const char* t = r_bin_entry_type_string(e->type)) {
        if (*t) r.type = t;
      }
      merge_entry(by_addr, r, false);
    });

    RVecRBinSymbol* symbols = r_bin_get_symbols_vec(core_->bin);
    if (symbols) {
      RBinSymbol* sym;
      R_VEC_FOREACH(symbols, sym) {
        if (sym->is_imported) continue;
        if (!sym->bind || strcmp(sym->bind, R_BIN_BIND_GLOBAL_STR) != 0) continue;
        const int64_t vaddr = (sym->paddr == UT64_MAX)
            ? static_cast<int64_t>(sym->vaddr)
            : static_cast<int64_t>(r_bin_get_vaddr(core_->bin, sym->paddr, sym->vaddr));
        EntryRow r;
        r.addr = vaddr;
#if R2_ABIVERSION >= 136
        r.size = static_cast<int64_t>(sym->attr.size);
#else
        r.size = static_cast<int64_t>(sym->size);
#endif
        r.type = sym->type ? sym->type : "";
        r.bind = sym->bind ? sym->bind : "";
        char* orig = r_bin_name_tostring2(sym->name, 'o');
        char* name = orig ? orig : r_bin_name_tostring(sym->name);
        if (name) {
          char* esc = r_str_escape_utf8(name, false, true);
          r.name = esc ? esc : name;
          free(esc);
        }
        merge_entry(by_addr, r, true);
      }
    }

    out.reserve(by_addr.size());
    for (auto& [addr, row] : by_addr) out.push_back(std::move(row));
  }

  // Mirrors `CCj` (`r_meta_print_list_all(anal, R_META_TYPE_COMMENT, 'j', ...)`
  // -> `print_meta_list` with addr/from/to all UT64_MAX, so none of that
  // function's function-scoping/range filtering applies to a full scan).
  // Walks `core->anal->meta` (an `RIntervalTree`) directly instead of
  // building and re-parsing a JSON array.
  //
  // `r_interval_tree_foreach`'s own macro expansion assigns the node's
  // `void* data` straight into a typed pointer -- legal C, a hard error in
  // C++ (the same trap `for_each_rlist` above works around for `RList`), so
  // this walks the underlying rbtree iterator directly instead of using the
  // macro.
  void comments_scan(std::vector<CommentRow>& out) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal || !core_->anal->meta.root) return;
    // `r_meta_print`'s own space guard: if a meta-space is currently
    // selected (`CS <name>`), only items in that exact space are visible;
    // if none is selected (the common case), every item is, regardless of
    // its own space. Read once, outside the loop -- selecting a space is
    // session state, not per-row.
    RSpace* cur_space = r_spaces_current(&core_->anal->meta_spaces);
    RIntervalTreeIter it;
    for (it = r_rbtree_first(&core_->anal->meta.root->node); r_rbtree_iter_has(&it);
         r_rbtree_iter_next(&it)) {
      RIntervalNode* node = r_interval_tree_iter_get(&it);
      if (!node || !node->data) continue;
      RAnalMetaItem* item = static_cast<RAnalMetaItem*>(node->data);
      if (item->type != R_META_TYPE_COMMENT) continue;
      if (cur_space && item->space != cur_space) continue;
      // A NULL `str` (e.g. from `CCu ""`) is a real interval-tree node that
      // `CCj` never prints -- skip it here too, rather than emit a
      // placeholder row `CCj` would never have shown.
      if (!item->str) continue;

      CommentRow r;
      r.addr = static_cast<int64_t>(node->start);
      // Same public R_API calls the CCj emitter itself makes for these two
      // fields -- NOT the literal "comment", and NOT a copy of item->str.
      // `r_meta_type_tostring(R_META_TYPE_COMMENT)` resolves to the literal
      // "CCu" (the write command, not a description of the meta kind); a
      // comment containing a newline/tab/quote/backslash/non-ASCII byte is
      // rendered through `r_str_escape` into its escaped TEXT form on the
      // JSON render path, exactly as production's CCj already does today.
      if (const char* t = r_meta_type_tostring(item->type)) r.type = t;
      if (char* esc = r_str_escape(item->str)) {
        r.text = esc;
        free(esc);
      }
      out.push_back(std::move(r));
    }
  }

  // Mirrors `CCu`'s own logic exactly (`cmd_meta.inc.c`'s `case 'u'`
  // handler), NOT just `r_meta_set_string` alone: skip the write when the
  // EXISTING comment at `addr` already contains `text` as a byte substring
  // (`strstr`). This is production behavior on the command path today --
  // reproduced here, not invented or "fixed" by this port.
  bool comment_set(int64_t addr, const std::string& text) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return false;
    const ut64 a = static_cast<ut64>(addr);
    const char* old = r_meta_get_string(core_->anal, R_META_TYPE_COMMENT, a);
    if (old && strstr(old, text.c_str())) return true;  // CCu's own no-op case
    return r_meta_set_string(core_->anal, R_META_TYPE_COMMENT, a, text.c_str());
  }

  // Mirrors `fr <old> <new>` (`cmd_flag.inc.c`'s `case 'r'` handler): a
  // plain by-name lookup + rename, no address needed at all (see the
  // rationale on `Api::flag_rename` in direct.hpp).
  bool flag_rename(const std::string& old_name, const std::string& new_name) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->flags) return false;
    RFlagItem* item = r_flag_get(core_->flags, old_name.c_str());
    if (!item) return false;
    return r_flag_rename(core_->flags, item, new_name.c_str());
  }

  // Mirrors `afvn <new> <old> @ <func_addr>` (`cmd_anal.inc.c`'s `case 'n'`
  // under `afv`): resolve the function, resolve the variable by its OLD
  // name, rename it. No other side effect (see the rationale on
  // `Api::var_rename` in direct.hpp).
  bool var_rename(int64_t func_addr, const std::string& old_name,
                   const std::string& new_name) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return false;
    RAnalFunction* fcn = r_anal_get_function_at(core_->anal, static_cast<ut64>(func_addr));
    if (!fcn) return false;
    RAnalVar* var = r_anal_function_get_var_byname(fcn, old_name.c_str());
    if (!var) return false;
    return r_anal_var_rename(core_->anal, var, new_name.c_str());
  }

  // Mirrors `afvt <name> <type> @ <func_addr>` (`cmd_anal.inc.c`'s
  // `case 't'` under `afv`): resolve the function, resolve the variable by
  // name, set its type. `r_anal_var_set_type` is `void` -- success is
  // "the variable was found", matching the command handler's own
  // `R_LOG_ERROR ("Cant find variable named %s")` failure shape.
  bool var_set_type(int64_t func_addr, const std::string& name,
                     const std::string& type) override {
    std::lock_guard lock(mu_);
    if (!core_ || !core_->anal) return false;
    RAnalFunction* fcn = r_anal_get_function_at(core_->anal, static_cast<ut64>(func_addr));
    if (!fcn) return false;
    RAnalVar* var = r_anal_function_get_var_byname(fcn, name.c_str());
    if (!var) return false;
    r_anal_var_set_type(core_->anal, var, type.c_str());
    return true;
  }

 private:
  RCore*      core_ = nullptr;
  std::mutex& mu_;
};

}  // namespace

std::unique_ptr<Api> make_libr_api(void* core, std::mutex& core_mutex) {
  if (!core) return nullptr;
  return std::make_unique<LibrApi>(static_cast<RCore*>(core), core_mutex);
}

}  // namespace r2xsql::direct
