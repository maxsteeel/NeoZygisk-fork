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
#include <vector>
#include <string>
#include <memory>
#include <sys/uio.h>
#include <sys/stat.h>
#include <linux/memfd.h>
#include <sys/utsname.h>

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

static uintptr_t smart_resolve_symbol(const char* sym_name, int local_pid, int remote_pid) {
    void* local_addr = dlsym(RTLD_DEFAULT, sym_name);
    if (!local_addr) return 0;

    static thread_local uintptr_t cached_local_start = 0;
    static thread_local uintptr_t cached_local_end = 0;
    static thread_local uintptr_t cached_local_base = 0;
    static thread_local uintptr_t cached_remote_start = 0;
    uintptr_t l_addr = (uintptr_t)local_addr;

    if (cached_local_start != 0 && l_addr >= cached_local_start && l_addr < cached_local_end) {
        uintptr_t offset = l_addr - cached_local_base;
        return cached_remote_start + offset;
    }

    uintptr_t local_base = 0;
    uintptr_t map_start = 0, map_end = 0;
    char actual_path[256] = {0};

    uintptr_t last_base = 0;
    char last_path[256] = {0};

    // Find the local memory section
    MapInfo::Scan(local_pid, [&](const MapInfo& m) {
        if (m.offset == 0) {
            last_base = m.start;
            strlcpy(last_path, m.path, sizeof(last_path));
        }
        if (l_addr >= m.start && l_addr < m.end) {
            map_start = m.start;
            map_end = m.end;
            strlcpy(actual_path, m.path, sizeof(actual_path));
            if (last_path[0] != '\0' && strcmp(last_path, m.path) == 0) {
                local_base = last_base;
            }
            return true; // Stop scanning
        }
        return false;
    });

    if (actual_path[0] == '\0') return 0;

    // If the base was 0, we look for offset 0 explicitly
    if (local_base == 0) {
        MapInfo::Scan(local_pid, [&](const MapInfo& m) {
            if (m.offset == 0 && strcmp(actual_path, m.path) == 0) {
                local_base = m.start;
                return true; // Stop scanning
            }
            return false;
        });
    }
    if (local_base == 0) return 0;

    uintptr_t offset = l_addr - local_base;
    uintptr_t remote_base = 0;

    // Find the corresponding base in the remote process
    MapInfo::Scan(remote_pid, [&](const MapInfo& m) {
        if (m.offset == 0 && strcmp(actual_path, m.path) == 0) {
            remote_base = m.start;
            return true; // Stop scanning
        }
        return false;
    });

    if (remote_base != 0) {
        cached_local_start = map_start;
        cached_local_end = map_end;
        cached_local_base = local_base;
        cached_remote_start = remote_base;
        return remote_base + offset;
    }

    return 0;
}

static bool resolve_symbol_addr(const elf_dyn_info *info,
                                int local_pid, int remote_pid,
                                const char** needed_paths, size_t needed_count,
                                uintptr_t load_bias, size_t sym_idx, uintptr_t *out_addr) {
    
    if (sym_idx >= info->nsyms) return false;
    const ElfW(Sym)& sym = info->symtab[sym_idx];

    if (sym.st_shndx != SHN_UNDEF) { *out_addr = (uintptr_t)load_bias + (uintptr_t)sym.st_value; return true; }
    if (sym.st_name == 0 || sym.st_name >= info->strsz) return false;

    const char *name = &info->strtab[sym.st_name];
    if (!name || !*name) return false;

    ElfW(Addr) local_val = 0;
    if (find_dynsym_value(info, name, &local_val) && local_val != 0) {
        *out_addr = (uintptr_t)load_bias + local_val;
        return true;
    }

    if (strcmp(name, "__register_frame") == 0 || strcmp(name, "__deregister_frame") == 0) { 
        *out_addr = 0; return true; 
    }

    uintptr_t smart_addr = smart_resolve_symbol(name, local_pid, remote_pid);
    if (smart_addr != 0) {
        *out_addr = smart_addr;
        return true;
    }

    for (size_t k = 0; k < needed_count; k++) {
        const char* mod_path = needed_paths[k];
        if (!mod_path || !*mod_path) continue;
        void *addr = find_func_addr(remote_pid, mod_path, name);
        if (addr) { *out_addr = (uintptr_t)addr; return true; }
    }
    
    return false;
}

static bool write_remote_addr(int pid, uintptr_t addr, ElfW(Addr) value) { return write_proc(pid, addr, &value, sizeof(value)); }
[[maybe_unused]] static bool read_remote_addr(int pid, uintptr_t addr, ElfW(Addr) *out) { return read_proc(pid, addr, out, sizeof(*out)); }

static inline bool process_remote_relocation(
    int pid, uintptr_t load_bias, const elf_dyn_info* info, int local_pid, int remote_pid,
    const char** needed_paths, size_t needed_count,
    uintptr_t target, unsigned current_type, unsigned current_sym_idx,
    ElfW(Addr) current_addend, bool is_rela
) {
    ElfW(Addr) value = 0;

#if defined(__aarch64__)
    if (current_type == R_AARCH64_RELATIVE) value = (ElfW(Addr))load_bias + (ElfW(Addr))current_addend;
    else if (current_type == R_AARCH64_GLOB_DAT || current_type == R_AARCH64_JUMP_SLOT || current_type == R_AARCH64_ABS64) {
        uintptr_t sym_addr = 0;
        if (!resolve_symbol_addr(info, local_pid, remote_pid, needed_paths, needed_count, load_bias, current_sym_idx, &sym_addr)) return false;
        value = sym_addr ? (ElfW(Addr))sym_addr + (ElfW(Addr))current_addend : 0;
    } else return false;
#elif defined(__x86_64__)
    if (current_type == R_X86_64_RELATIVE) value = (ElfW(Addr))load_bias + (ElfW(Addr))current_addend;
    else if (current_type == R_X86_64_GLOB_DAT || current_type == R_X86_64_JUMP_SLOT || current_type == R_X86_64_64) {
        uintptr_t sym_addr = 0;
        if (!resolve_symbol_addr(info, local_pid, remote_pid, needed_paths, needed_count, load_bias, current_sym_idx, &sym_addr)) return false;
        value = sym_addr ? (ElfW(Addr))sym_addr + (ElfW(Addr))current_addend : 0;
    } else return false;
#elif defined(__arm__)
    if (current_type == R_ARM_RELATIVE) {
        ElfW(Addr) addend_rel = 0;
        if (is_rela) addend_rel = current_addend;
        else if (!read_remote_addr(pid, target, &addend_rel)) return false;
        value = (ElfW(Addr))load_bias + addend_rel;
    } else if (current_type == R_ARM_GLOB_DAT || current_type == R_ARM_JUMP_SLOT || current_type == R_ARM_ABS32) {
        uintptr_t sym_addr = 0;
        if (!resolve_symbol_addr(info, local_pid, remote_pid, needed_paths, needed_count, load_bias, current_sym_idx, &sym_addr)) return false;
        if (sym_addr == 0) value = 0;
        else if (current_type == R_ARM_ABS32) {
            ElfW(Addr) addend_rel = 0;
            if (is_rela) addend_rel = current_addend;
            else if (!read_remote_addr(pid, target, &addend_rel)) return false;
            value = (ElfW(Addr))sym_addr + addend_rel;
        } else value = (ElfW(Addr))sym_addr;
    } else return false;
#elif defined(__i386__)
    if (current_type == R_386_RELATIVE) {
        ElfW(Addr) addend_rel = 0;
        if (is_rela) addend_rel = current_addend;
        else if (!read_remote_addr(pid, target, &addend_rel)) return false;
        value = (ElfW(Addr))load_bias + addend_rel;
    } else if (current_type == R_386_GLOB_DAT || current_type == R_386_JMP_SLOT || current_type == R_386_32) {
        uintptr_t sym_addr = 0;
        if (!resolve_symbol_addr(info, local_pid, remote_pid, needed_paths, needed_count, load_bias, current_sym_idx, &sym_addr)) return false;
        if (sym_addr == 0) value = 0;
        else if (current_type == R_386_32) {
            ElfW(Addr) addend_rel = 0;
            if (is_rela) addend_rel = current_addend;
            else if (!read_remote_addr(pid, target, &addend_rel)) return false;
            value = (ElfW(Addr))sym_addr + addend_rel;
        } else value = (ElfW(Addr))sym_addr;
    } else return false;
#else
    if (current_type == 0) value = (ElfW(Addr))load_bias + (ElfW(Addr))current_addend;
    else return false;
#endif

    return write_remote_addr(pid, target, value);
}


static bool apply_rela_section(int pid, void* file_map, [[maybe_unused]] const std::unique_ptr<ElfW(Phdr)[]>& phdr, size_t phnum,
                               const elf_dyn_info *info, int local_pid, 
                               int remote_pid, const char** needed_paths, 
                               size_t needed_count, uintptr_t load_bias, ElfW(Addr) rela_vaddr, size_t rela_sz) {
    off_t rela_off = 0;
    if (!vaddr_to_offset(phdr, phnum, rela_vaddr, &rela_off)) return false;

    size_t count = rela_sz / sizeof(ElfW(Rela));
    ElfW(Rela)* rels = reinterpret_cast<ElfW(Rela)*>(reinterpret_cast<uint8_t*>(file_map) + rela_off);

    for (size_t i = 0; i < count; i++) {
        const ElfW(Rela)& r = rels[i];
        if (!process_remote_relocation(pid, load_bias, info, local_pid, remote_pid, needed_paths, needed_count,
            (uintptr_t)load_bias + (uintptr_t)r.r_offset, ELF_R_TYPE(r.r_info), ELF_R_SYM(r.r_info), r.r_addend, true)) {
            return false;
        }
    }
    return true;
}

static bool apply_rel_section(int pid, void* file_map, [[maybe_unused]] const std::unique_ptr<ElfW(Phdr)[]>& phdr, size_t phnum,
                              const elf_dyn_info *info, int local_pid, 
                              int remote_pid, const char** needed_paths,
                              size_t needed_count, uintptr_t load_bias, ElfW(Addr) rel_vaddr, size_t rel_sz) {
    off_t rel_off = 0;
    if (!vaddr_to_offset(phdr, phnum, rel_vaddr, &rel_off)) return false;

    size_t count = rel_sz / sizeof(ElfW(Rel));
    ElfW(Rel)* rels = reinterpret_cast<ElfW(Rel)*>(reinterpret_cast<uint8_t*>(file_map) + rel_off);

    for (size_t i = 0; i < count; i++) {
        const ElfW(Rel)& r = rels[i];
        if (!process_remote_relocation(pid, load_bias, info, local_pid, remote_pid, needed_paths, needed_count,
            (uintptr_t)load_bias + (uintptr_t)r.r_offset, ELF_R_TYPE(r.r_info), ELF_R_SYM(r.r_info), 0, false)) {
            return false;
        }
    }
    return true;
}

static bool is_memfd_supported_by_kernel() {
    static int supported = -1;
    if (supported != -1) return supported == 1;

    struct utsname uts;
    if (uname(&uts) != 0) {
        supported = 1; // Default to true if uname fails
        return true;
    }

    int major = 0, minor = 0;
    const char *p = uts.release;
    while (*p >= '0' && *p <= '9') {
        major = major * 10 + (*p - '0');
        p++;
    }
    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9') {
            minor = minor * 10 + (*p - '0');
            p++;
        }
    }

    if (major > 3 || (major == 3 && minor >= 17)) {
        supported = 1;
    } else {
        supported = 0;
    }
    return supported == 1;
}

static long remote_mmap_offset_arg(off_t file_offset, size_t page_size) {
  #if defined(__NR_mmap2) && defined(SYS_mmap) && SYS_mmap == __NR_mmap2
    return (long)(file_offset / (off_t)page_size);
  #else
    (void)page_size;
    return (long)file_offset;
  #endif
}

// ---------------- MAIN ----------------
bool remote_custom_linker_load_and_resolve_entry(int local_pid, int remote_pid, struct user_regs_struct *regs,
                                                 const char *lib_path, uintptr_t *out_base,
                                                 size_t *out_total_size, uintptr_t *out_entry,
                                                 uintptr_t *out_init_array, size_t *out_init_count) {
    const struct user_regs_struct regs_saved = *regs;
    int pid = remote_pid;

    long page_size_long = sysconf(_SC_PAGESIZE);
    size_t page_size = (size_t)page_size_long;

    UniqueFd fd(open(lib_path, O_RDONLY | O_CLOEXEC));
    if (fd < 0) return false;

    // Map the file locally
    struct stat st;
    if (fstat(fd, &st) != 0) return false;
    void* file_map = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_map == MAP_FAILED) return false;

    ElfW(Ehdr) eh;
    std::unique_ptr<ElfW(Phdr)[]> phdr;
    ElfW(Addr) min_vaddr = 0;
    size_t map_size = 0;

    if (!compute_load_layout(fd, page_size, &eh, phdr, &min_vaddr, &map_size)) { 
        munmap(file_map, st.st_size);
        return false; 
    }

    uintptr_t syscall_gadget = find_syscall_gadget(local_pid, remote_pid);
    if (!syscall_gadget) {
        LOGE("Failed to find syscall gadget for Remote-Custom Linker");
        munmap(file_map, st.st_size);
        return false;
    }

    size_t path_len = strlen(lib_path) + 1;
    const char* fake_name = "jit-cache";
    size_t fake_name_len = strlen(fake_name) + 1;

    uintptr_t remote_str_block = regs_saved.REG_SP - ALIGN_UP(path_len + fake_name_len, 16);
    uintptr_t remote_fake_name = remote_str_block + path_len;

    char* str_buffer = (char*)alloca(path_len + fake_name_len);
    memset(str_buffer, 0, path_len + fake_name_len);
    memcpy(str_buffer, lib_path, path_len);
    memcpy(str_buffer + path_len, fake_name, fake_name_len);
    write_proc(pid, remote_str_block, str_buffer, path_len + fake_name_len);

    struct user_regs_struct call_regs = regs_saved;
    call_regs.REG_SP = remote_str_block;

    long args_open[] = {AT_FDCWD, (long)remote_str_block, O_RDONLY | O_CLOEXEC, 0};
    long remote_fd = remote_syscall(pid, call_regs, syscall_gadget, SYS_openat, args_open, 4);

    if (remote_fd < 0) {
        LOGE("Failed to open remote file via raw syscall");
        munmap(file_map, st.st_size);
        return false;
    }

    long memfd = -1;
    if (is_memfd_supported_by_kernel()) {
        long args_memfd[] = {(long)remote_fake_name, MFD_CLOEXEC};
        memfd = remote_syscall(pid, call_regs, syscall_gadget, SYS_memfd_create, args_memfd, 2);
    }

    uintptr_t remote_base = 0;

    if (memfd >= 0) {
        long args_ftruncate[] = {memfd, (long)map_size};
        remote_syscall(pid, call_regs, syscall_gadget, SYS_ftruncate, args_ftruncate, 2);

        long args_mmap_shared[] = {0, (long)map_size, PROT_NONE, MAP_SHARED, memfd, 0};
        remote_base = remote_syscall(pid, call_regs, syscall_gadget, SYS_mmap, args_mmap_shared, 6);

        long args_close_memfd[] = {memfd};
        remote_syscall(pid, call_regs, syscall_gadget, SYS_close, args_close_memfd, 1);
    } else {
        long args_mmap_anon[] = {0, (long)map_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0};
        remote_base = remote_syscall(pid, call_regs, syscall_gadget, SYS_mmap, args_mmap_anon, 6);
    }

    if (!remote_base || remote_base == (uintptr_t)MAP_FAILED) {
        long args_close_fd[] = {remote_fd};
        remote_syscall(pid, call_regs, syscall_gadget, SYS_close, args_close_fd, 1);
        munmap(file_map, st.st_size);
        return false;
    }

    uintptr_t load_bias = remote_base - (uintptr_t)min_vaddr;
    struct SegInfo { uintptr_t addr; size_t len; int prot; };
    SegInfo segs[32];
    size_t seg_count = 0;
    char* tail_zeros = (char*)alloca(page_size);
    memset(tail_zeros, 0, page_size);

    for (int i = 0; i < eh.e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue;
        uintptr_t seg_start = (uintptr_t)phdr[i].p_vaddr + load_bias;
        uintptr_t seg_page = page_start(seg_start, page_size);
        uintptr_t seg_end = (uintptr_t)phdr[i].p_vaddr + (uintptr_t)phdr[i].p_memsz + load_bias;
        uintptr_t seg_page_end = page_end(seg_end, page_size);
        size_t seg_page_len = (size_t)(seg_page_end - seg_page);

        bool is_writable = (phdr[i].p_flags & PF_W) != 0;
        off_t file_page_offset = (off_t)page_start((uintptr_t)phdr[i].p_offset, page_size);
        uintptr_t file_end = (uintptr_t)phdr[i].p_vaddr + (uintptr_t)phdr[i].p_filesz + load_bias;
        uintptr_t file_page_end = page_end(file_end, page_size);

        if (phdr[i].p_filesz > 0) {
            long offset_arg = remote_mmap_offset_arg(file_page_offset, page_size);
            long args_mmap_seg[] = {(long)seg_page, (long)(file_page_end - seg_page), PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, remote_fd, offset_arg};
            uintptr_t seg_map = remote_syscall(pid, call_regs, syscall_gadget, SYS_mmap, args_mmap_seg, 6);
            if (!seg_map || seg_map == (uintptr_t)MAP_FAILED) { munmap(file_map, st.st_size); return false; }

            if (is_writable && file_page_end > file_end) {
                size_t tail_len = (size_t)(file_page_end - file_end);
                size_t written = 0;
                while (written < tail_len) {
                    size_t to_write = (tail_len - written > page_size) ? page_size : (tail_len - written);
                    write_proc(pid, file_end + written, tail_zeros, to_write);
                    written += to_write;
                }
            }
        }
        if (seg_page_end > file_page_end) {
            long args_mmap_bss[] = {(long)file_page_end, (long)(seg_page_end - file_page_end), PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0};
            uintptr_t bss_map = remote_syscall(pid, call_regs, syscall_gadget, SYS_mmap, args_mmap_bss, 6);
            if (!bss_map || bss_map == (uintptr_t)MAP_FAILED) { munmap(file_map, st.st_size); return false; }
        }
        int prot = 0;
        if (phdr[i].p_flags & PF_R) prot |= PROT_READ;
        if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC;
        if (seg_count < 32) {
            segs[seg_count++] = {seg_page, seg_page_len, prot};
        }
    }

    long args_close_fd[] = {remote_fd};
    remote_syscall(pid, call_regs, syscall_gadget, SYS_close, args_close_fd, 1);

    elf_dyn_info dinfo;
    // Pass the local memory map directly.
    if (!elf_load_dyn_info(file_map, true, &eh, phdr, &dinfo)) {
        munmap(file_map, st.st_size);
        return false;
    }

    size_t needed_count = dinfo.needed_count;
    const char** needed_paths = (const char**)alloca(needed_count * sizeof(const char*));

    // Only store the sonames directly from the string table.
    // find_func_addr resolves sonames dynamically via MapInfo::Scan. No need for find_remote_module_path.
    for (size_t i = 0; i < needed_count; i++) {
        size_t off = dinfo.needed_str_offsets[i];
        needed_paths[i] = (off < dinfo.strsz) ? &dinfo.strtab[off] : "";
    }

    // Apply relocations passing the local file_map
    if (dinfo.rela_sz && dinfo.rela_vaddr) apply_rela_section(pid, file_map, phdr, eh.e_phnum, &dinfo, local_pid, remote_pid, needed_paths, needed_count, load_bias, dinfo.rela_vaddr, dinfo.rela_sz);
    if (dinfo.rel_sz && dinfo.rel_vaddr) apply_rel_section(pid, file_map, phdr, eh.e_phnum, &dinfo, local_pid, remote_pid, needed_paths, needed_count, load_bias, dinfo.rel_vaddr, dinfo.rel_sz);
    if (dinfo.jmprel_sz && dinfo.jmprel_vaddr) {
        if (dinfo.pltrel_type == DT_RELA) apply_rela_section(pid, file_map, phdr, eh.e_phnum, &dinfo, local_pid, remote_pid, needed_paths, needed_count, load_bias, dinfo.jmprel_vaddr, dinfo.jmprel_sz);
        else apply_rel_section(pid, file_map, phdr, eh.e_phnum, &dinfo, local_pid, remote_pid, needed_paths, needed_count, load_bias, dinfo.jmprel_vaddr, dinfo.jmprel_sz);
    }

    for (size_t k = 0; k < seg_count; k++) {
        const auto& s = segs[k];
        if (s.prot == (PROT_READ | PROT_WRITE)) continue;
        long args_mprotect[] = {(long)s.addr, (long)s.len, s.prot};
        remote_syscall(pid, call_regs, syscall_gadget, SYS_mprotect, args_mprotect, 3);
    }

    ElfW(Addr) entry_value = 0;
    if (!find_dynsym_value(&dinfo, "entry", &entry_value)) {
        munmap(file_map, st.st_size);
        return false; 
    }

    *out_base = remote_base;
    *out_total_size = map_size;
    *out_entry = (uintptr_t)load_bias + (uintptr_t)entry_value;
    *out_init_array = dinfo.init_array_vaddr ? ((uintptr_t)load_bias + dinfo.init_array_vaddr) : 0;
    *out_init_count = dinfo.init_arraysz ? (dinfo.init_arraysz / sizeof(ElfW(Addr))) : 0;

    // We no longer need the local file mapping. Clean it up.
    munmap(file_map, st.st_size);

    return true;
}
