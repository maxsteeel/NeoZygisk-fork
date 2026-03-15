#include "remote_csoloader.hpp"

#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <link.h>
#include <vector>
#include <string>
#include <linux/memfd.h>

#include "daemon.hpp"
#include "logging.hpp"
#include "utils.hpp"

#ifndef ALIGN_DOWN
#define ALIGN_DOWN(x, a) ((x) & ~((a)-1))
#endif
#ifndef ALIGN_UP
#define ALIGN_UP(x, a) (((x) + ((a)-1)) & ~((a)-1))
#endif

static uintptr_t page_start(uintptr_t addr, size_t page_size) { return ALIGN_DOWN(addr, page_size); }
static uintptr_t page_end(uintptr_t addr, size_t page_size) { return ALIGN_DOWN(addr + page_size - 1, page_size); }

static bool read_loop_offset(int fd, void *buf, size_t count, off_t offset) {
    char *ptr = (char *)buf;
    size_t remain = count;
    while (remain > 0) {
        ssize_t n = pread(fd, ptr, remain, offset);
        if (n < 0) { if (errno == EINTR) continue; return false; }
        if (n == 0) return false;
        ptr += n; offset += n; remain -= n;
    }
    return true;
}

static bool compute_load_layout(int fd, size_t page_size, ElfW(Ehdr) *eh,
                                std::vector<ElfW(Phdr)>& out_phdr, ElfW(Addr) *out_min_vaddr,
                                size_t *out_map_size) {
    if (!read_loop_offset(fd, eh, sizeof(*eh), 0)) return false;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return false;

    size_t phdr_sz = (size_t)eh->e_phnum * sizeof(ElfW(Phdr));
    out_phdr.resize(eh->e_phnum);
    if (!read_loop_offset(fd, out_phdr.data(), phdr_sz, (off_t)eh->e_phoff)) return false;

    ElfW(Addr) lo = (ElfW(Addr))UINTPTR_MAX;
    ElfW(Addr) hi = 0;

    for (int i = 0; i < eh->e_phnum; i++) {
        if (out_phdr[i].p_type != PT_LOAD) continue;
        if (out_phdr[i].p_vaddr < lo) lo = out_phdr[i].p_vaddr;
        ElfW(Addr) end = out_phdr[i].p_vaddr + out_phdr[i].p_memsz;
        if (end > hi) hi = end;
    }

    if (hi <= lo) return false;
    *out_min_vaddr = (ElfW(Addr))page_start((uintptr_t)lo, page_size);
    *out_map_size = (size_t)(page_end((uintptr_t)hi, page_size) - *out_min_vaddr);
    return true;
}

static bool vaddr_to_offset(const std::vector<ElfW(Phdr)>& phdr, ElfW(Addr) vaddr, off_t *out_off) {
    for (const auto& p : phdr) {
        if (p.p_type != PT_LOAD) continue;
        ElfW(Addr) seg_start = p.p_vaddr;
        ElfW(Addr) seg_end = p.p_vaddr + p.p_filesz;
        if (vaddr < seg_start || vaddr >= seg_end) continue;
        *out_off = (off_t)p.p_offset + (off_t)(vaddr - seg_start);
        return true;
    }
    return false;
}

static const char *find_remote_module_path(const std::vector<MapInfo>& remote_map, const char *soname) {
    for (const auto& m : remote_map) {
        if (m.offset != 0) continue;
        const char *filename = strrchr(m.path, '/');
        filename = filename ? filename + 1 : m.path;
        if (strcmp(filename, soname) == 0) return m.path;
    }
    return nullptr;
}

struct elf_dyn_info {
    off_t dyn_off = 0; size_t dyn_sz = 0;
    off_t symtab_off = 0; off_t strtab_off = 0;
    off_t rel_off = 0; size_t rel_sz = 0;
    off_t rela_off = 0; size_t rela_sz = 0;
    off_t jmprel_off = 0; size_t jmprel_sz = 0;
    int pltrel_type = 0; size_t syment = 0;
    size_t strsz = 0; size_t nsyms = 0;
    ElfW(Addr) init_array_vaddr = 0; size_t init_arraysz = 0;
    std::vector<char> strtab; std::vector<size_t> needed_str_offsets;
};

static bool elf_load_dyn_info(int fd, [[maybe_unused]] const ElfW(Ehdr) *eh, const std::vector<ElfW(Phdr)>& phdr, elf_dyn_info *out) {
    const ElfW(Phdr) *dyn_phdr = nullptr;
    for (const auto& p : phdr) { if (p.p_type == PT_DYNAMIC) { dyn_phdr = &p; break; } }
    if (!dyn_phdr || dyn_phdr->p_filesz == 0) return false;

    out->dyn_off = (off_t)dyn_phdr->p_offset;
    out->dyn_sz = (size_t)dyn_phdr->p_filesz;
    size_t dyn_count = out->dyn_sz / sizeof(ElfW(Dyn));
    std::vector<ElfW(Dyn)> dyn(dyn_count);
    if (!read_loop_offset(fd, dyn.data(), dyn_count * sizeof(ElfW(Dyn)), out->dyn_off)) return false;

    ElfW(Addr) symtab_vaddr = 0, strtab_vaddr = 0, gnu_hash_vaddr = 0, rel_vaddr = 0, rela_vaddr = 0, jmprel_vaddr = 0;
    size_t rel_sz = 0, rela_sz = 0, jmprel_sz = 0, strsz = 0, syment = 0;

    for (size_t i = 0; i < dyn_count; i++) {
        uintptr_t tag = (uintptr_t)dyn[i].d_tag;
        switch (tag) {
            case DT_SYMTAB: symtab_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
            case DT_STRTAB: strtab_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
            case DT_STRSZ: strsz = (size_t)dyn[i].d_un.d_val; break;
            case DT_SYMENT: syment = (size_t)dyn[i].d_un.d_val; break;
            case DT_REL: rel_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
            case DT_RELSZ: rel_sz = (size_t)dyn[i].d_un.d_val; break;
            case DT_RELA: rela_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
            case DT_RELASZ: rela_sz = (size_t)dyn[i].d_un.d_val; break;
            case DT_JMPREL: jmprel_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
            case DT_PLTRELSZ: jmprel_sz = (size_t)dyn[i].d_un.d_val; break;
            case DT_PLTREL: out->pltrel_type = (int)dyn[i].d_un.d_val; break;
            case DT_GNU_HASH: gnu_hash_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
            case DT_NEEDED: out->needed_str_offsets.push_back((size_t)dyn[i].d_un.d_val); break;
            case DT_INIT_ARRAY: out->init_array_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
            case DT_INIT_ARRAYSZ: out->init_arraysz = (size_t)dyn[i].d_un.d_val; break;
            case DT_NULL: i = dyn_count; break;
        }
    }

    if (!syment) syment = sizeof(ElfW(Sym));
    if (!symtab_vaddr || !strtab_vaddr || !strsz) return false;
    if (!vaddr_to_offset(phdr, symtab_vaddr, &out->symtab_off) || !vaddr_to_offset(phdr, strtab_vaddr, &out->strtab_off)) return false;

    if (rel_vaddr && rel_sz) { if (!vaddr_to_offset(phdr, rel_vaddr, &out->rel_off)) return false; out->rel_sz = rel_sz; }
    if (rela_vaddr && rela_sz) { if (!vaddr_to_offset(phdr, rela_vaddr, &out->rela_off)) return false; out->rela_sz = rela_sz; }
    if (jmprel_vaddr && jmprel_sz) { if (!vaddr_to_offset(phdr, jmprel_vaddr, &out->jmprel_off)) return false; out->jmprel_sz = jmprel_sz; }

    out->strtab.resize(strsz + 1);
    if (!read_loop_offset(fd, out->strtab.data(), strsz, out->strtab_off)) return false;
    out->strtab[strsz] = '\0';
    out->syment = syment;
    out->strsz = strsz;

    if (gnu_hash_vaddr) {
        off_t gnu_hash_off = 0;
        if (vaddr_to_offset(phdr, gnu_hash_vaddr, &gnu_hash_off)) {
            uint32_t header[4];
            if (read_loop_offset(fd, header, sizeof(header), gnu_hash_off)) {
                uint32_t nbuckets = header[0];
                uint32_t symoffset = header[1];
                uint32_t bloom_size = header[2];
                off_t buckets_off = gnu_hash_off + 16 + (off_t)(bloom_size * sizeof(ElfW(Addr)));
                
                uint32_t max_bucket = 0;
                for (uint32_t b = 0; b < nbuckets; b++) {
                    uint32_t bucket_val;
                    if (!read_loop_offset(fd, &bucket_val, sizeof(bucket_val), buckets_off + (off_t)(b * 4))) break;
                    if (bucket_val > max_bucket) max_bucket = bucket_val;
                }

                if (max_bucket >= symoffset) {
                    off_t chains_off = buckets_off + (off_t)(nbuckets * 4);
                    uint32_t chain_idx = max_bucket - symoffset;
                    uint32_t chain_val;
                    while (read_loop_offset(fd, &chain_val, sizeof(chain_val), chains_off + (off_t)(chain_idx * 4))) {
                        if (chain_val & 1) { out->nsyms = max_bucket + 1; break; }
                        max_bucket++; chain_idx++;
                    }
                    if (!out->nsyms) out->nsyms = max_bucket + 1;
                } else out->nsyms = symoffset;
            }
        }
    }
    return true;
}

static bool find_dynsym_value(int fd, const elf_dyn_info *info, const char *sym_name, ElfW(Addr) *out_value) {
    for (size_t i = 0; i < info->nsyms; i++) {
        ElfW(Sym) sym;
        if (!read_loop_offset(fd, &sym, sizeof(sym), info->symtab_off + (off_t)(i * info->syment))) break;
        if (sym.st_name == 0 || sym.st_name >= info->strsz) continue;
        const char *name = &info->strtab[sym.st_name];
        if (strcmp(name, sym_name) != 0 || sym.st_shndx == SHN_UNDEF) continue;
        *out_value = sym.st_value;
        return true;
    }
    return false;
}

#ifdef __LP64__
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_SYM ELF64_R_SYM
#else
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_SYM ELF32_R_SYM
#endif

static uintptr_t smart_resolve_symbol(const char* sym_name, const std::vector<MapInfo>& local_map, const std::vector<MapInfo>& remote_map) {
    void* local_addr = dlsym(RTLD_DEFAULT, sym_name);
    if (!local_addr) return 0;

    std::string actual_path;
    uintptr_t local_base = 0;
    uintptr_t last_base = 0;
    const char* last_path = nullptr;

    for (const auto& m : local_map) {
        if (m.offset == 0) {
            last_base = m.start;
            last_path = m.path;
        }
        if ((uintptr_t)local_addr >= m.start && (uintptr_t)local_addr < m.end) {
            actual_path = m.path;
            if (last_path && strcmp(last_path, m.path) == 0) {
                local_base = last_base;
            }
            break;
        }
    }

    if (actual_path.empty()) return 0;

    if (local_base == 0) {
        for (const auto& m : local_map) {
            if (m.offset == 0 && actual_path == m.path) {
                local_base = m.start;
                break;
            }
        }
    }
    if (local_base == 0) return 0;

    uintptr_t offset = (uintptr_t)local_addr - local_base;

    for (const auto& m : remote_map) {
        if (m.path == actual_path && m.offset == 0) {
            return m.start + offset;
        }
    }
    return 0;
}

static bool resolve_symbol_addr(int fd, const elf_dyn_info *info,
                                const std::vector<MapInfo>& local_map,
                                const std::vector<MapInfo>& remote_map,
                                const std::vector<const char*>& needed_paths,
                                uintptr_t load_bias, size_t sym_idx, uintptr_t *out_addr) {
    ElfW(Sym) sym;
    if (!read_loop_offset(fd, &sym, sizeof(sym), info->symtab_off + (off_t)(sym_idx * info->syment))) return false;

    if (sym.st_shndx != SHN_UNDEF) { *out_addr = (uintptr_t)load_bias + (uintptr_t)sym.st_value; return true; }
    if (sym.st_name == 0 || sym.st_name >= info->strsz) return false;

    const char *name = &info->strtab[sym.st_name];
    if (!name || !*name) return false;

    ElfW(Addr) local_val = 0;
    if (find_dynsym_value(fd, info, name, &local_val) && local_val != 0) {
        *out_addr = (uintptr_t)load_bias + local_val;
        return true;
    }

    if (strcmp(name, "__register_frame") == 0 || strcmp(name, "__deregister_frame") == 0) { 
        *out_addr = 0; return true; 
    }

    uintptr_t smart_addr = smart_resolve_symbol(name, local_map, remote_map);
    if (smart_addr != 0) {
        *out_addr = smart_addr;
        return true;
    }

    for (const auto& mod_path : needed_paths) {
        if (!mod_path || !*mod_path) continue;
        void *addr = find_func_addr(local_map, remote_map, mod_path, name);
        if (addr) { *out_addr = (uintptr_t)addr; return true; }
    }
    
    return false;
}

static bool write_remote_addr(int pid, uintptr_t addr, ElfW(Addr) value) { return write_proc(pid, addr, &value, sizeof(value)); }
[[maybe_unused]] static bool read_remote_addr(int pid, uintptr_t addr, ElfW(Addr) *out) { return read_proc(pid, addr, out, sizeof(*out)); }

static bool apply_rela_section(int pid, int fd, [[maybe_unused]] const elf_dyn_info *info,
                               [[maybe_unused]] const std::vector<MapInfo>& local_map,
                               [[maybe_unused]] const std::vector<MapInfo>& remote_map,
                               [[maybe_unused]] const std::vector<const char*>& needed_paths,
                               uintptr_t load_bias, off_t rela_off, size_t rela_sz) {
    size_t count = rela_sz / sizeof(ElfW(Rela));
    for (size_t i = 0; i < count; i++) {
        ElfW(Rela) r;
        if (!read_loop_offset(fd, &r, sizeof(r), rela_off + (off_t)(i * sizeof(r)))) return false;

        [[maybe_unused]] unsigned type = (unsigned)ELF_R_TYPE(r.r_info);
        [[maybe_unused]] unsigned sym = (unsigned)ELF_R_SYM(r.r_info);
        uintptr_t target = (uintptr_t)load_bias + (uintptr_t)r.r_offset;
        ElfW(Addr) value = 0;

#if defined(__aarch64__)
        if (type == R_AARCH64_RELATIVE) value = (ElfW(Addr))load_bias + (ElfW(Addr))r.r_addend;
        else if (type == R_AARCH64_GLOB_DAT || type == R_AARCH64_JUMP_SLOT || type == R_AARCH64_ABS64) {
            uintptr_t sym_addr = 0;
            if (!resolve_symbol_addr(fd, info, local_map, remote_map, needed_paths, load_bias, sym, &sym_addr)) return false;
            value = sym_addr ? (ElfW(Addr))sym_addr + (ElfW(Addr))r.r_addend : 0;
        } else return false;
#elif defined(__x86_64__)
        if (type == R_X86_64_RELATIVE) value = (ElfW(Addr))load_bias + (ElfW(Addr))r.r_addend;
        else if (type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT || type == R_X86_64_64) {
            uintptr_t sym_addr = 0;
            if (!resolve_symbol_addr(fd, info, local_map, remote_map, needed_paths, load_bias, sym, &sym_addr)) return false;
            value = sym_addr ? (ElfW(Addr))sym_addr + (ElfW(Addr))r.r_addend : 0;
        } else return false;
#else
        if (type == 0) value = (ElfW(Addr))load_bias + (ElfW(Addr))r.r_addend;
        else return false;
#endif
        if (!write_remote_addr(pid, target, value)) return false;
    }
    return true;
}

static bool apply_rel_section(int pid, int fd, [[maybe_unused]] const elf_dyn_info *info,
                              [[maybe_unused]] const std::vector<MapInfo>& local_map,
                              [[maybe_unused]] const std::vector<MapInfo>& remote_map,
                              [[maybe_unused]] const std::vector<const char*>& needed_paths,
                              uintptr_t load_bias, off_t rel_off, size_t rel_sz) {
    size_t count = rel_sz / sizeof(ElfW(Rel));
    for (size_t i = 0; i < count; i++) {
        ElfW(Rel) r;
        if (!read_loop_offset(fd, &r, sizeof(r), rel_off + (off_t)(i * sizeof(r)))) return false;

        [[maybe_unused]] unsigned type = (unsigned)ELF_R_TYPE(r.r_info);
        [[maybe_unused]] unsigned sym = (unsigned)ELF_R_SYM(r.r_info);
        uintptr_t target = (uintptr_t)load_bias + (uintptr_t)r.r_offset;
        [[maybe_unused]] ElfW(Addr) addend = 0; 
        ElfW(Addr) value = 0;

#if defined(__arm__)
        if (type == R_ARM_RELATIVE) {
            if (!read_remote_addr(pid, target, &addend)) return false;
            value = (ElfW(Addr))load_bias + addend;
        } else if (type == R_ARM_GLOB_DAT || type == R_ARM_JUMP_SLOT || type == R_ARM_ABS32) {
            uintptr_t sym_addr = 0;
            if (!resolve_symbol_addr(fd, info, local_map, remote_map, needed_paths, load_bias, sym, &sym_addr)) return false;
            if (sym_addr == 0) value = 0;
            else if (type == R_ARM_ABS32) {
                if (!read_remote_addr(pid, target, &addend)) return false;
                value = (ElfW(Addr))sym_addr + addend;
            } else value = (ElfW(Addr))sym_addr;
        } else return false;
#elif defined(__i386__)
        if (type == R_386_RELATIVE) {
            if (!read_remote_addr(pid, target, &addend)) return false;
            value = (ElfW(Addr))load_bias + addend;
        } else if (type == R_386_GLOB_DAT || type == R_386_JMP_SLOT || type == R_386_32) {
            uintptr_t sym_addr = 0;
            if (!resolve_symbol_addr(fd, info, local_map, remote_map, needed_paths, load_bias, sym, &sym_addr)) return false;
            if (sym_addr == 0) value = 0;
            else if (type == R_386_32) {
                if (!read_remote_addr(pid, target, &addend)) return false;
                value = (ElfW(Addr))sym_addr + addend;
            } else value = (ElfW(Addr))sym_addr;
        } else return false;
#else
        return false;
#endif
        if (!write_remote_addr(pid, target, value)) return false;
    }
    return true;
}

// ---------------- MAIN ----------------
bool remote_csoloader_load_and_resolve_entry(int pid, struct user_regs_struct *regs,
                                             uintptr_t libc_return_addr, 
                                             const std::vector<MapInfo>& local_map,
                                             const std::vector<MapInfo>& remote_map, 
                                             const char *libc_path,
                                             const char *lib_path, uintptr_t *out_base,
                                             size_t *out_total_size, uintptr_t *out_entry,
                                             uintptr_t *out_init_array, size_t *out_init_count) {
    const struct user_regs_struct regs_saved = *regs;

    long page_size_long = sysconf(_SC_PAGESIZE);
    size_t page_size = (size_t)page_size_long;

    UniqueFd fd(open(lib_path, O_RDONLY | O_CLOEXEC));
    if (fd < 0) return false;

    ElfW(Ehdr) eh;
    std::vector<ElfW(Phdr)> phdr;
    ElfW(Addr) min_vaddr = 0;
    size_t map_size = 0;

    if (!compute_load_layout(fd, page_size, &eh, phdr, &min_vaddr, &map_size)) { return false; }

    void *mmap_addr = find_func_addr(local_map, remote_map, libc_path, "mmap");
    void *mprotect_addr = find_func_addr(local_map, remote_map, libc_path, "mprotect");
    void *open_addr = find_func_addr(local_map, remote_map, libc_path, "open");
    void *close_addr = find_func_addr(local_map, remote_map, libc_path, "close");
    void *syscall_addr = find_func_addr(local_map, remote_map, libc_path, "syscall");
    void *munmap_addr = find_func_addr(local_map, remote_map, libc_path, "munmap");
    if (!mmap_addr || !mprotect_addr || !open_addr || !close_addr || !syscall_addr || !munmap_addr) { return false; }

    size_t path_len = strlen(lib_path) + 1;
    long args_mmap1[] = {0, (long)path_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0};
    struct user_regs_struct call_regs = regs_saved;
    uintptr_t remote_path = remote_call(pid, call_regs, (uintptr_t)mmap_addr, libc_return_addr, args_mmap1, 6);
    if (!remote_path || remote_path == (uintptr_t)MAP_FAILED) { return false; }
    write_proc(pid, remote_path, lib_path, path_len);

    long args_open[] = {(long)remote_path, O_RDONLY | O_CLOEXEC, 0};
    call_regs = regs_saved;
    long remote_fd = (long)remote_call(pid, call_regs, (uintptr_t)open_addr, libc_return_addr, args_open, 3);

    char zeros[512] = {0};
    for (size_t offset = 0; offset < path_len; offset += sizeof(zeros)) {
        size_t chunk = (path_len - offset < sizeof(zeros)) ? (path_len - offset) : sizeof(zeros);
        write_proc(pid, remote_path + offset, zeros, chunk);
    }

    long args_munmap1[] = {(long)remote_path, (long)path_len};
    call_regs = regs_saved;
    remote_call(pid, call_regs, (uintptr_t)munmap_addr, libc_return_addr, args_munmap1, 2);

    if (remote_fd < 0) { return false; }

    long memfd_syscall_num = 0;
#if defined(__aarch64__)
    memfd_syscall_num = 279;
#elif defined(__x86_64__)
    memfd_syscall_num = 319;
#elif defined(__arm__)
    memfd_syscall_num = 385;
#elif defined(__i386__)
    memfd_syscall_num = 356;
#endif

    long args_mmap2[] = {0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0};
    call_regs = regs_saved;
    uintptr_t name_addr = remote_call(pid, call_regs, (uintptr_t)mmap_addr, libc_return_addr, args_mmap2, 6);
    const char* fake_name = "jit-cache";
    write_proc(pid, name_addr, fake_name, strlen(fake_name) + 1);

    long args_syscall_memfd[] = {memfd_syscall_num, (long)name_addr, MFD_CLOEXEC};
    call_regs = regs_saved;
    long memfd = (long)remote_call(pid, call_regs, (uintptr_t)syscall_addr, libc_return_addr, args_syscall_memfd, 3);

    long args_munmap2[] = {(long)name_addr, 4096};
    if (munmap_addr) {
        call_regs = regs_saved;
        remote_call(pid, call_regs, (uintptr_t)munmap_addr, libc_return_addr, args_munmap2, 2);
    }

    uintptr_t remote_base = 0;

    if (memfd >= 0) {
        long ftruncate_syscall = 0;
#if defined(__aarch64__)
        ftruncate_syscall = 46;
#elif defined(__x86_64__)
        ftruncate_syscall = 77;
#elif defined(__arm__)
        ftruncate_syscall = 93;
#elif defined(__i386__)
        ftruncate_syscall = 93;
#endif
        long args_syscall_ftruncate[] = {ftruncate_syscall, memfd, (long)map_size};
        call_regs = regs_saved;
        remote_call(pid, call_regs, (uintptr_t)syscall_addr, libc_return_addr, args_syscall_ftruncate, 3);

        long args_mmap_shared[] = {0, (long)map_size, PROT_NONE, MAP_SHARED, memfd, 0};
        call_regs = regs_saved;
        remote_base = remote_call(pid, call_regs, (uintptr_t)mmap_addr, libc_return_addr, args_mmap_shared, 6);

        long args_close[] = {memfd};
        call_regs = regs_saved;
        remote_call(pid, call_regs, (uintptr_t)close_addr, libc_return_addr, args_close, 1);
    } else {
        LOGW("CSOLoader: memfd_create failed, falling back to anonymous memory");
        long args_mmap_anon[] = {0, (long)map_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0};
        call_regs = regs_saved;
        remote_base = remote_call(pid, call_regs, (uintptr_t)mmap_addr, libc_return_addr, args_mmap_anon, 6);
    }

    if (!remote_base || remote_base == (uintptr_t)MAP_FAILED) { return false; }

    uintptr_t load_bias = remote_base - (uintptr_t)min_vaddr;
    struct SegInfo { uintptr_t addr; size_t len; int prot; };
    std::vector<SegInfo> segs;

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
            call_regs = regs_saved;
            long args_mmap_seg[] = {(long)seg_page, (long)(file_page_end - seg_page), PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, remote_fd, (long)file_page_offset};
            uintptr_t seg_map = remote_call(pid, call_regs, (uintptr_t)mmap_addr, libc_return_addr, args_mmap_seg, 6);
            if (!seg_map || seg_map == (uintptr_t)MAP_FAILED) return false;

            if (is_writable && file_page_end > file_end) {
                size_t tail_len = (size_t)(file_page_end - file_end);
                char zeros[512] = {0};
                for (size_t offset = 0; offset < tail_len; offset += sizeof(zeros)) {
                    size_t chunk = (tail_len - offset < sizeof(zeros)) ? (tail_len - offset) : sizeof(zeros);
                    write_proc(pid, file_end + offset, zeros, chunk);
                }
            }
        }
        if (seg_page_end > file_page_end) {
            call_regs = regs_saved;
            long args_mmap_bss[] = {(long)file_page_end, (long)(seg_page_end - file_page_end), PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0};
            uintptr_t bss_map = remote_call(pid, call_regs, (uintptr_t)mmap_addr, libc_return_addr, args_mmap_bss, 6);
            if (!bss_map || bss_map == (uintptr_t)MAP_FAILED) return false;
        }
        int prot = 0;
        if (phdr[i].p_flags & PF_R) prot |= PROT_READ;
        if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC;
        segs.push_back({seg_page, seg_page_len, prot});
    }

    call_regs = regs_saved;
    long args_close_fd[] = {remote_fd};
    remote_call(pid, call_regs, (uintptr_t)close_addr, libc_return_addr, args_close_fd, 1);

    elf_dyn_info dinfo;
    if (!elf_load_dyn_info(fd, &eh, phdr, &dinfo)) return false;

    std::vector<const char*> needed_paths(dinfo.needed_str_offsets.size(), nullptr);
    for (size_t i = 0; i < dinfo.needed_str_offsets.size(); i++) {
        size_t off = dinfo.needed_str_offsets[i];
        if (off < dinfo.strsz) {
            const char *soname = &dinfo.strtab[off];
            const char *path = find_remote_module_path(remote_map, soname);
            if (path) needed_paths[i] = path;
        }
    }

    if (dinfo.rela_sz && dinfo.rela_off) apply_rela_section(pid, fd, &dinfo, local_map, remote_map, needed_paths, load_bias, dinfo.rela_off, dinfo.rela_sz);
    if (dinfo.rel_sz && dinfo.rel_off) apply_rel_section(pid, fd, &dinfo, local_map, remote_map, needed_paths, load_bias, dinfo.rel_off, dinfo.rel_sz);
    if (dinfo.jmprel_sz && dinfo.jmprel_off) {
        if (dinfo.pltrel_type == DT_RELA) apply_rela_section(pid, fd, &dinfo, local_map, remote_map, needed_paths, load_bias, dinfo.jmprel_off, dinfo.jmprel_sz);
        else apply_rel_section(pid, fd, &dinfo, local_map, remote_map, needed_paths, load_bias, dinfo.jmprel_off, dinfo.jmprel_sz);
    }

    for (const auto& s : segs) {
        call_regs = regs_saved;
        long args_mprotect[] = {(long)s.addr, (long)s.len, s.prot};
        remote_call(pid, call_regs, (uintptr_t)mprotect_addr, libc_return_addr, args_mprotect, 3);
    }

    ElfW(Addr) entry_value = 0;
    if (!find_dynsym_value(fd, &dinfo, "entry", &entry_value)) { return false; }

    *out_base = remote_base;
    *out_total_size = map_size;
    *out_entry = (uintptr_t)load_bias + (uintptr_t)entry_value;
    *out_init_array = dinfo.init_array_vaddr ? ((uintptr_t)load_bias + dinfo.init_array_vaddr) : 0;
    *out_init_count = dinfo.init_arraysz ? (dinfo.init_arraysz / sizeof(ElfW(Addr))) : 0;

    return true;
}
