/*
 * Remote-Custom Linker for NeoZygisk-fork
 * 
 * This file is a derivative work based on CSOLoader.
 * Original Author: ThePedroo (Copyright (c) 2025)
 * C++ rewrite and modifications by: maxsteeel (Copyright (c) 2026)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "remote_custom_linker.hpp"

#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <link.h>
#include <sys/stat.h>

#include "daemon.hpp"
#include "logging.hpp"
#include "utils.hpp"
#include "elf_utils.hpp"

#ifdef __LP64__
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_SYM ELF64_R_SYM
#else
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_SYM ELF32_R_SYM
#endif

using MapInfoList = UniqueList<MapInfo>;

struct SymbolCache {
    uintptr_t local_start = 0;
    uintptr_t local_end = 0;
    uintptr_t diff = 0;
};

static uintptr_t smart_resolve_symbol(const char* sym_name,
                                      const MapInfoList& local_maps,
                                      const MapInfoList& remote_maps,
                                      SymbolCache& cache) {
    void* local_addr = dlsym(RTLD_DEFAULT, sym_name);
    if (!local_addr) return 0;
    uintptr_t l_addr = (uintptr_t)local_addr;

    if (l_addr >= cache.local_start && l_addr < cache.local_end) {
        return l_addr + cache.diff;
    }

    uintptr_t local_base = 0;
    const char* actual_path = nullptr;
    size_t found_idx = 0;

    for (size_t i = 0; i < local_maps.size; ++i) {
        if (l_addr >= local_maps.data[i].start && l_addr < local_maps.data[i].end) {
            actual_path = local_maps.data[i].path;
            found_idx = i;
            break;
        }
    }

    if (!actual_path || actual_path[0] == '\0') return 0;

    for (size_t i = found_idx + 1; i > 0; --i) {
        const MapInfo& m = local_maps.data[i - 1];
        if (m.offset == 0 && __builtin_strcmp(m.path, actual_path) == 0) {
            local_base = m.start;
            break;
        }
    }
    if (local_base == 0) return 0;

    uintptr_t remote_base = 0;
    for (size_t i = 0; i < remote_maps.size; ++i) {
        const MapInfo& m = remote_maps.data[i];
        if (m.offset == 0 && m.path[0] == actual_path[0] && __builtin_strcmp(m.path, actual_path) == 0) {
            remote_base = m.start;
            break;
        }
    }

    if (remote_base != 0) {
        cache.local_start = local_maps.data[found_idx].start;
        cache.local_end = local_maps.data[found_idx].end;
        cache.diff = remote_base - local_base;
        return l_addr + cache.diff;
    }

    return 0;
}

static bool resolve_symbol_addr(const elf_dyn_info *info, uintptr_t load_bias, size_t sym_idx, uintptr_t *out_addr,
                                const MapInfoList& local_maps, const MapInfoList& remote_maps, SymbolCache& cache) {
    
    if (sym_idx >= info->nsyms) return false;
    const ElfW(Sym)& sym = info->symtab[sym_idx];

    if (sym.st_shndx != SHN_UNDEF) { 
        *out_addr = load_bias + sym.st_value; 
        return true; 
    }

    if (sym.st_name == 0 || sym.st_name >= info->strsz) return false;
    const char *name = &info->strtab[sym.st_name];

    ElfW(Addr) local_val = 0;
    if (find_dynsym_value(info, name, &local_val) && local_val != 0) {
        *out_addr = load_bias + local_val;
        return true;
    }

    if (__builtin_strcmp(name, "__register_frame") == 0 || __builtin_strcmp(name, "__deregister_frame") == 0) { 
        *out_addr = 0; 
        return true; 
    }

    uintptr_t smart_addr = smart_resolve_symbol(name, local_maps, remote_maps, cache);
    if (smart_addr != 0) {
        *out_addr = smart_addr; 
        return true;
    }

    return false;
}

__attribute__((noinline))
static bool process_remote_relocation(
    const elf_dyn_info* info, uintptr_t load_bias, unsigned current_type,
    unsigned current_sym_idx, ElfW(Addr) addend, const MapInfoList& local_maps, 
    const MapInfoList& remote_maps, SymbolCache& cache, ElfW(Addr)* out_value) {
    
    ElfW(Addr) value = 0;

#if defined(__aarch64__)
    switch (current_type) {
        case R_AARCH64_RELATIVE: 
            value = load_bias + addend; 
            break;
        case R_AARCH64_GLOB_DAT:
        case R_AARCH64_JUMP_SLOT:
        case R_AARCH64_ABS64: {
            uintptr_t sym_addr = 0;
            if (unlikely(!resolve_symbol_addr(info, load_bias, current_sym_idx, &sym_addr, local_maps, remote_maps, cache))) return false;
            value = sym_addr ? sym_addr + addend : 0;
            break;
        }
        default: return false;
    }
#elif defined(__x86_64__)
    switch (current_type) {
        case R_X86_64_RELATIVE: 
            value = load_bias + addend; 
            break;
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
        case R_X86_64_64: {
            uintptr_t sym_addr = 0;
            if (unlikely(!resolve_symbol_addr(info, load_bias, current_sym_idx, &sym_addr, local_maps, remote_maps, cache))) return false;
            value = sym_addr ? sym_addr + addend : 0;
            break;
        }
        default: return false;
    }
#elif defined(__arm__)
    switch (current_type) {
        case R_ARM_RELATIVE: 
            value = load_bias + addend; 
            break;
        case R_ARM_GLOB_DAT:
        case R_ARM_JUMP_SLOT:
        case R_ARM_ABS32: {
            uintptr_t sym_addr = 0;
            if (unlikely(!resolve_symbol_addr(info, load_bias, current_sym_idx, &sym_addr, local_maps, remote_maps, cache))) return false;
            if (sym_addr == 0) value = 0;
            else if (current_type == R_ARM_ABS32) value = sym_addr + addend;
            else value = sym_addr;
            break;
        }
        default: return false;
    }
#elif defined(__i386__)
    switch (current_type) {
        case R_386_RELATIVE: 
            value = load_bias + addend; 
            break;
        case R_386_GLOB_DAT:
        case R_386_JMP_SLOT:
        case R_386_32: {
            uintptr_t sym_addr = 0;
            if (unlikely(!resolve_symbol_addr(info, load_bias, current_sym_idx, &sym_addr, local_maps, remote_maps, cache))) return false;
            if (sym_addr == 0) value = 0;
            else if (current_type == R_386_32) value = sym_addr + addend;
            else value = sym_addr;
            break;
        }
        default: return false;
    }
#else
    if (current_type == 0) value = load_bias + addend;
    else return false;
#endif

    *out_value = value;
    return true;
}

template <typename RelType, bool IsRela>
__attribute__((noinline))
static bool apply_relocations(int pid, void* file_map, const ElfW(Phdr)* phdr, size_t phnum,
                                     const elf_dyn_info *info, uintptr_t load_bias, ElfW(Addr) vaddr,
                                     size_t sz, const MapInfoList& local_maps,
                                     const MapInfoList& remote_maps, SymbolCache& cache) {
    off_t off = 0;
    if (!vaddr_to_offset(phdr, phnum, vaddr, &off)) return false;

    size_t count = sz / sizeof(RelType);
    RelType* rels = reinterpret_cast<RelType*>(reinterpret_cast<uint8_t*>(file_map) + off);

    for (size_t i = 0; i < count; i++) {
        const RelType& r = rels[i];
        unsigned type = ELF_R_TYPE(r.r_info);
        if (type == 0) continue;

        ElfW(Addr) addend = 0;
        off_t target_off = 0;
        bool locally_writable = vaddr_to_offset(phdr, phnum, r.r_offset, &target_off);

        if constexpr (IsRela) {
            addend = r.r_addend;
        } else {
            if (locally_writable) {
                addend = *reinterpret_cast<ElfW(Addr)*>((uintptr_t)file_map + target_off);
            } else {
                if (unlikely(!read_proc(pid, load_bias + r.r_offset, &addend, sizeof(addend)))) return false;
            }
        }

        ElfW(Addr) value = 0;
        if (unlikely(!process_remote_relocation(info, load_bias, type, ELF_R_SYM(r.r_info), addend, local_maps, remote_maps, cache, &value))) {
            return false;
        }

        if (locally_writable) {
            *reinterpret_cast<ElfW(Addr)*>((uintptr_t)file_map + target_off) = value;
        } else {
            write_proc(pid, load_bias + r.r_offset, &value, sizeof(value));
        }
    }
    return true;
}

// ---------------- MAIN ----------------
bool remote_custom_linker_load_and_resolve_entry(int local_pid, int remote_pid, struct user_regs_struct *regs,
                                                 const char *lib_path, uintptr_t *out_base,
                                                 size_t *out_total_size, uintptr_t *out_entry,
                                                 uintptr_t *out_init_array, size_t *out_init_count) {
    const struct user_regs_struct regs_saved = *regs;
    int pid = remote_pid;

    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);

    MapInfoList local_maps; MapInfoList remote_maps;
    MapInfo::Scan(local_pid, [&](const MapInfo& m) { local_maps.push_back(m); return false; });
    MapInfo::Scan(remote_pid, [&](const MapInfo& m) { remote_maps.push_back(m); return false; });

    UniqueFd fd(open(lib_path, O_RDONLY | O_CLOEXEC));
    if (unlikely(fd < 0)) return false;

    struct stat st;
    if (unlikely(fstat(fd, &st) != 0)) return false;
    void* file_map = mmap(nullptr, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (unlikely(file_map == MAP_FAILED)) return false;
    MmapGuard map_guard{file_map, (size_t)st.st_size};

    ElfW(Ehdr) eh;
    ElfW(Phdr) phdr[64];
    ElfW(Addr) min_vaddr = 0;
    size_t map_size = 0;

    if (unlikely(!compute_load_layout(fd, page_size, &eh, phdr, &min_vaddr, &map_size))) return false;

    uintptr_t syscall_gadget = find_syscall_gadget(remote_pid);
    if (!syscall_gadget) {
        LOGE("Failed to find syscall gadget for Remote-Custom Linker");
        return false;
    }

    struct user_regs_struct call_regs = regs_saved;

    long args_mmap_anon[] = {0, (long)map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0};
    uintptr_t remote_base = remote_syscall(pid, call_regs, syscall_gadget, SYS_mmap, args_mmap_anon, 6);

    if (!remote_base || remote_base == (uintptr_t)MAP_FAILED) {
        LOGE("Failed to allocate anonymous memory in remote process");
        return false;
    }

    uintptr_t load_bias = remote_base - min_vaddr;
    elf_dyn_info dinfo;
    if (!elf_load_dyn_info(file_map, true, &eh, phdr, &dinfo)) return false;

    SymbolCache cache;

    if (dinfo.rela_sz && dinfo.rela_vaddr) apply_relocations<ElfW(Rela), true>(pid, file_map, phdr, eh.e_phnum, &dinfo, load_bias, dinfo.rela_vaddr, dinfo.rela_sz, local_maps, remote_maps, cache);
    if (dinfo.rel_sz && dinfo.rel_vaddr) apply_relocations<ElfW(Rel), false>(pid, file_map, phdr, eh.e_phnum, &dinfo, load_bias, dinfo.rel_vaddr, dinfo.rel_sz, local_maps, remote_maps, cache);
    if (dinfo.jmprel_sz && dinfo.jmprel_vaddr) {
        if (dinfo.pltrel_type == DT_RELA) apply_relocations<ElfW(Rela), true>(pid, file_map, phdr, eh.e_phnum, &dinfo, load_bias, dinfo.jmprel_vaddr, dinfo.jmprel_sz, local_maps, remote_maps, cache);
        else apply_relocations<ElfW(Rel), false>(pid, file_map, phdr, eh.e_phnum, &dinfo, load_bias, dinfo.jmprel_vaddr, dinfo.jmprel_sz, local_maps, remote_maps, cache);
    }

    struct SegInfo { uintptr_t addr; size_t len; int prot; };
    SegInfo segs[32];
    size_t seg_count = 0;

    for (int i = 0; i < eh.e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue;
        uintptr_t seg_start = phdr[i].p_vaddr + load_bias;
        uintptr_t seg_page = page_start(seg_start, page_size);
        uintptr_t seg_end = phdr[i].p_vaddr + phdr[i].p_memsz + load_bias;
        uintptr_t seg_page_end = page_end(seg_end, page_size);
        size_t seg_page_len = seg_page_end - seg_page;

        if (phdr[i].p_filesz > 0) {
            void* local_src = (void*)((uintptr_t)file_map + phdr[i].p_offset);
            if (!write_proc(pid, seg_start, local_src, phdr[i].p_filesz)) {
                LOGE("Failed to write PT_LOAD segment to remote process");
                return false;
            }
        }

        int prot = 0;
        if (phdr[i].p_flags & PF_R) prot |= PROT_READ;
        if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC;
        if (seg_count < 32) segs[seg_count++] = {seg_page, seg_page_len, prot};
    }

    for (size_t k = 0; k < seg_count; k++) {
        const auto& s = segs[k];
        if (s.prot == (PROT_READ | PROT_WRITE)) continue;
        long args_mprotect[] = {(long)s.addr, (long)s.len, s.prot};
        remote_syscall(pid, call_regs, syscall_gadget, SYS_mprotect, args_mprotect, 3);
    }

    ElfW(Addr) entry_value = 0;
    if (!find_dynsym_value(&dinfo, "entry", &entry_value)) return false;

    *out_base = remote_base;
    *out_total_size = map_size;
    *out_entry = load_bias + entry_value;
    *out_init_array = dinfo.init_array_vaddr ? (load_bias + dinfo.init_array_vaddr) : 0;
    *out_init_count = dinfo.init_arraysz ? (dinfo.init_arraysz / sizeof(ElfW(Addr))) : 0;

    return true;
}
