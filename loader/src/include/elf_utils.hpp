#pragma once

#include <elf.h>
#include <link.h>
#include <sys/types.h>
#include <vector>
#include <cstdint>
#include <memory>

#ifndef ALIGN_DOWN
#define ALIGN_DOWN(x, a) ((x) & ~((a)-1))
#endif
#ifndef ALIGN_UP
#define ALIGN_UP(x, a) (((x) + ((a)-1)) & ~((a)-1))
#endif

#ifndef ELF_ST_TYPE
#ifdef __LP64__
#define ELF_ST_TYPE ELF64_ST_TYPE
#else
#define ELF_ST_TYPE ELF32_ST_TYPE
#endif
#endif

#ifndef PAC_STRIP
#if defined(__aarch64__)
#define PAC_STRIP(addr) ((uintptr_t)(addr) & 0xFFFFFFFFFFFFULL)
#else
#define PAC_STRIP(addr) (addr)
#endif
#endif

static inline uintptr_t page_start(uintptr_t addr, size_t page_size) { return ALIGN_DOWN(addr, page_size); }
static inline uintptr_t page_end(uintptr_t addr, size_t page_size) { return ALIGN_DOWN(addr + page_size - 1, page_size); }

struct elf_dyn_info {
    off_t dyn_off = 0; size_t dyn_sz = 0;
    off_t symtab_off = 0; off_t strtab_off = 0;
    off_t rel_off = 0; size_t rel_sz = 0;
    off_t rela_off = 0; size_t rela_sz = 0;
    off_t jmprel_off = 0; size_t jmprel_sz = 0;
    int pltrel_type = 0; size_t syment = 0;
    size_t strsz = 0; size_t nsyms = 0;
    ElfW(Addr) init_array_vaddr = 0; size_t init_arraysz = 0;

    ElfW(Addr) init_vaddr = 0;
    ElfW(Addr) fini_vaddr = 0;
    ElfW(Addr) fini_array_vaddr = 0; size_t fini_arraysz = 0;

    ElfW(Addr) eh_frame_hdr_vaddr = 0; size_t eh_frame_hdr_sz = 0;

    ElfW(Addr) relro_vaddr = 0; size_t relro_sz = 0;

    size_t tls_mod_id = 0;
    ElfW(Addr) tls_segment_vaddr = 0;
    size_t tls_segment_memsz = 0;
    size_t tls_segment_filesz = 0;
    size_t tls_segment_align = 0;

    off_t android_rel_off = 0; size_t android_rel_sz = 0;
    bool android_is_rela = false;

    off_t relr_off = 0; size_t relr_sz = 0;

    uint32_t gnu_symndx = 0;
    uint32_t gnu_shift2 = 0;
    std::unique_ptr<ElfW(Addr)[]> gnu_bloom_filter;
    size_t gnu_bloom_filter_size = 0;
    std::unique_ptr<uint32_t[]> gnu_buckets;
    size_t gnu_buckets_size = 0;
    std::unique_ptr<uint32_t[]> gnu_chains;
    size_t gnu_chains_size = 0;
    std::unique_ptr<uint32_t[]> sysv_buckets;
    uint32_t sysv_nbucket = 0;
    std::unique_ptr<uint32_t[]> sysv_chains;
    uint32_t sysv_nchain = 0;
    std::unique_ptr<ElfW(Half)[]> versym;
    std::unique_ptr<char[]> strtab;
    size_t needed_str_offsets[128];
    size_t needed_count = 0;
    std::unique_ptr<ElfW(Sym)[]> symtab;
};

bool read_loop_offset(int fd, void *buf, size_t count, off_t offset);

bool compute_load_layout(int fd, size_t page_size, ElfW(Ehdr) *eh,
                         std::unique_ptr<ElfW(Phdr)[]>& out_phdr, ElfW(Addr) *out_min_vaddr,
                         size_t *out_map_size);

bool vaddr_to_offset(const std::unique_ptr<ElfW(Phdr)[]>& phdr, size_t phnum, ElfW(Addr) vaddr, off_t *out_off);

bool elf_load_dyn_info(int fd, const ElfW(Ehdr) *eh, const std::unique_ptr<ElfW(Phdr)[]>& phdr, elf_dyn_info *out);

bool find_dynsym_value(const elf_dyn_info *info, const char *sym_name, ElfW(Addr) *out_value, uint8_t *out_type = nullptr);
