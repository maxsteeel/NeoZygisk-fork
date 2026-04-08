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

#ifndef PAC_STRIP
#if defined(__aarch64__)
#define PAC_STRIP(addr) ((uintptr_t)(addr) & 0xFFFFFFFFFFFFULL)
#else
#define PAC_STRIP(addr) (addr)
#endif
#endif

static inline uintptr_t page_start(uintptr_t addr, size_t page_size) { return ALIGN_DOWN(addr, page_size); }
static inline uintptr_t page_end(uintptr_t addr, size_t page_size) { return ALIGN_DOWN(addr + page_size - 1, page_size); }
static inline constexpr uint32_t calc_gnu_hash(const char* str) {
    uint32_t h = 5381;
    for (; *str != '\0'; ++str) {
        h = (h << 5) + h + *str;
    }
    return h;
}

struct elf_dyn_info {
    ElfW(Addr) rel_vaddr = 0; size_t rel_sz = 0;
    ElfW(Addr) rela_vaddr = 0; size_t rela_sz = 0;
    ElfW(Addr) jmprel_vaddr = 0; size_t jmprel_sz = 0;
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

    ElfW(Addr) android_rel_vaddr = 0; size_t android_rel_sz = 0;
    bool android_is_rela = false;
    ElfW(Addr) relr_vaddr = 0; size_t relr_sz = 0;

    uint32_t gnu_symndx = 0;
    uint32_t gnu_shift2 = 0;
    const ElfW(Addr)* gnu_bloom_filter = nullptr;
    size_t gnu_bloom_filter_size = 0;
    const uint32_t* gnu_buckets = nullptr;
    size_t gnu_buckets_size = 0;
    const uint32_t* gnu_chains = nullptr;
    
    const char* strtab = nullptr;
    size_t needed_str_offsets[128];
    size_t needed_count = 0;
    ElfW(Sym)* symtab = nullptr;
};

bool read_loop_offset(int fd, void *buf, size_t count, off_t offset);

bool compute_load_layout(int fd, size_t page_size, ElfW(Ehdr) *eh,
                         std::unique_ptr<ElfW(Phdr)[]>& out_phdr, ElfW(Addr) *out_min_vaddr,
                         size_t *out_map_size);

bool vaddr_to_offset(const std::unique_ptr<ElfW(Phdr)[]>& phdr, size_t phnum, ElfW(Addr) vaddr, off_t *out_off);

bool elf_load_dyn_info(void* memory_map, bool is_raw_file, const ElfW(Ehdr) *eh, const std::unique_ptr<ElfW(Phdr)[]>& phdr, elf_dyn_info *out);

bool find_dynsym_value(const elf_dyn_info *info, const char *sym_name, ElfW(Addr) *out_value, uint8_t *out_type = nullptr);

void* resolve_symbol(const char* lib_name, const char* sym_name);
