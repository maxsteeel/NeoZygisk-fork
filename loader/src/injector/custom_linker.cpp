/*
 * Custom Linker for NeoZygisk-fork
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

#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>

#include <string>
#include <vector>
#include <mutex>
#include <functional>

#include "logging.hpp"
#include "files.hpp"

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

#ifndef STT_GNU_IFUNC
#define STT_GNU_IFUNC 10
#endif

static std::mutex g_custom_regions_lock;
struct CustomRegion {
    uintptr_t base;
    size_t size;

    std::vector<std::function<void()>> destructors;
};
static std::vector<CustomRegion> g_custom_regions;

bool is_custom_linker_address(const void* addr) {
    uintptr_t ptr = reinterpret_cast<uintptr_t>(addr);
    std::lock_guard<std::mutex> lock(g_custom_regions_lock);
    for (const auto& reg : g_custom_regions) {
        if (ptr >= reg.base && ptr < reg.base + reg.size) return true;
    }
    return false;
}

void custom_linker_unload(void* handle) {
    uintptr_t base = reinterpret_cast<uintptr_t>(handle);
    std::lock_guard<std::mutex> lock(g_custom_regions_lock);
    for (auto it = g_custom_regions.begin(); it != g_custom_regions.end(); ++it) {
        if (it->base == base) {
            for (const auto& destructor : it->destructors) {
                destructor();
            }

            munmap(handle, it->size);
            g_custom_regions.erase(it);
            return;
        }
    }
}

struct CustomTlsInfo {
    size_t module_id;
    pthread_key_t key;
};

struct LoadedModule;

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

    size_t tls_mod_id = 0;
    ElfW(Addr) tls_segment_vaddr = 0;
    size_t tls_segment_memsz = 0;
    size_t tls_segment_filesz = 0;
    size_t tls_segment_align = 0;

    off_t android_rel_off = 0; size_t android_rel_sz = 0;
    bool android_is_rela = false;

    off_t relr_off = 0; size_t relr_sz = 0;

    std::vector<char> strtab; std::vector<size_t> needed_str_offsets;
    std::vector<ElfW(Sym)> symtab;
};

struct LoadedModule {
    std::string path;
    uintptr_t load_bias;
    uintptr_t base;
    size_t size;
    elf_dyn_info dinfo;

    bool eh_registered = false;
    uintptr_t eh_frame_ptr = 0;
};

static bool elf_load_dyn_info(int fd, [[maybe_unused]] const ElfW(Ehdr) *eh, const std::vector<ElfW(Phdr)>& phdr, elf_dyn_info *out) {
    const ElfW(Phdr) *dyn_phdr = nullptr;
    for (const auto& p : phdr) { if (p.p_type == PT_DYNAMIC) { dyn_phdr = &p; break; } }
    if (!dyn_phdr || dyn_phdr->p_filesz == 0) return false;

    out->dyn_off = (off_t)dyn_phdr->p_offset;

    for (const auto& p : phdr) {
        if (p.p_type == PT_GNU_EH_FRAME) {
            out->eh_frame_hdr_vaddr = p.p_vaddr;
            out->eh_frame_hdr_sz = p.p_memsz;
        }
    }

    out->dyn_sz = (size_t)dyn_phdr->p_filesz;
    size_t dyn_count = out->dyn_sz / sizeof(ElfW(Dyn));
    std::vector<ElfW(Dyn)> dyn(dyn_count);
    if (!read_loop_offset(fd, dyn.data(), dyn_count * sizeof(ElfW(Dyn)), out->dyn_off)) return false;

    ElfW(Addr) symtab_vaddr = 0, strtab_vaddr = 0, gnu_hash_vaddr = 0, rel_vaddr = 0, rela_vaddr = 0, jmprel_vaddr = 0;
    size_t rel_sz = 0, rela_sz = 0, jmprel_sz = 0, strsz = 0, syment = 0;

    ElfW(Addr) android_rel_vaddr = 0; size_t android_rel_sz = 0; bool android_is_rela = false;
    ElfW(Addr) relr_vaddr = 0; size_t relr_sz = 0;

    out->tls_mod_id = 0;
    for (const auto& p : phdr) {
        if (p.p_type == PT_TLS) {
            out->tls_segment_vaddr = p.p_vaddr;
            out->tls_segment_memsz = p.p_memsz;
            out->tls_segment_filesz = p.p_filesz;
            out->tls_segment_align = p.p_align;
        }
    }

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
            case DT_INIT: out->init_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
            case DT_FINI: out->fini_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
            case DT_FINI_ARRAY: out->fini_array_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
            case DT_FINI_ARRAYSZ: out->fini_arraysz = (size_t)dyn[i].d_un.d_val; break;
#ifdef __ANDROID__
            case DT_ANDROID_RELA: android_rel_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; android_is_rela = true; break;
            case DT_ANDROID_RELASZ: android_rel_sz = (size_t)dyn[i].d_un.d_val; break;
            case DT_ANDROID_REL: android_rel_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; android_is_rela = false; break;
            case DT_ANDROID_RELSZ: android_rel_sz = (size_t)dyn[i].d_un.d_val; break;
            case DT_ANDROID_RELR:
            case DT_RELR: relr_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
            case DT_ANDROID_RELRSZ:
            case DT_RELRSZ: relr_sz = (size_t)dyn[i].d_un.d_val; break;
#endif
            case DT_NULL: i = dyn_count; break;
        }
    }

    if (!syment) syment = sizeof(ElfW(Sym));
    if (!symtab_vaddr || !strtab_vaddr || !strsz) return false;
    if (!vaddr_to_offset(phdr, symtab_vaddr, &out->symtab_off) || !vaddr_to_offset(phdr, strtab_vaddr, &out->strtab_off)) return false;

    if (rel_vaddr && rel_sz) { if (!vaddr_to_offset(phdr, rel_vaddr, &out->rel_off)) return false; out->rel_sz = rel_sz; }
    if (rela_vaddr && rela_sz) { if (!vaddr_to_offset(phdr, rela_vaddr, &out->rela_off)) return false; out->rela_sz = rela_sz; }
    if (jmprel_vaddr && jmprel_sz) { if (!vaddr_to_offset(phdr, jmprel_vaddr, &out->jmprel_off)) return false; out->jmprel_sz = jmprel_sz; }

    if (android_rel_vaddr && android_rel_sz) {
        if (vaddr_to_offset(phdr, android_rel_vaddr, &out->android_rel_off)) {
            out->android_rel_sz = android_rel_sz;
            out->android_is_rela = android_is_rela;
        }
    }

    if (relr_vaddr && relr_sz) {
        if (vaddr_to_offset(phdr, relr_vaddr, &out->relr_off)) {
            out->relr_sz = relr_sz;
        }
    }

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
                bool fast_path_success = false;

                // Only use the fast path if nbuckets is reasonable (e.g. <= 1M elements, 4MB)
                if (nbuckets <= 1024 * 1024) {
                    std::vector<uint32_t> buckets(nbuckets);
                    if (read_loop_offset(fd, buckets.data(), nbuckets * sizeof(uint32_t), buckets_off)) {
                        for (uint32_t b = 0; b < nbuckets; b++) {
                            if (buckets[b] > max_bucket) max_bucket = buckets[b];
                        }
                        fast_path_success = true;
                    }
                }

                if (!fast_path_success) {
                    for (uint32_t b = 0; b < nbuckets; b++) {
                        uint32_t bucket_val;
                        if (!read_loop_offset(fd, &bucket_val, sizeof(bucket_val), buckets_off + (off_t)(b * 4))) break;
                        if (bucket_val > max_bucket) max_bucket = bucket_val;
                    }
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

    if (out->nsyms > 0) {
        out->symtab.resize(out->nsyms);
        if (!read_loop_offset(fd, out->symtab.data(), out->nsyms * sizeof(ElfW(Sym)), out->symtab_off)) {
            return false;
        }
    }
    return true;
}

static bool find_dynsym_value(const elf_dyn_info *info, const char *sym_name, ElfW(Addr) *out_value, uint8_t *out_type = nullptr) {
    for (size_t i = 0; i < info->nsyms; i++) {
        const ElfW(Sym)& sym = info->symtab[i];
        if (sym.st_name == 0 || sym.st_name >= info->strsz) continue;
        const char *name = &info->strtab[sym.st_name];
        if (strcmp(name, sym_name) != 0 || sym.st_shndx == SHN_UNDEF) continue;
        *out_value = sym.st_value;
        if (out_type) *out_type = ELF_ST_TYPE(sym.st_info);
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

static bool resolve_symbol_addr(const elf_dyn_info *info,
                                const std::vector<const char*>& needed_paths,
                                const std::vector<LoadedModule>& loaded_modules,
                                uintptr_t load_bias, size_t sym_idx, uintptr_t *out_addr) {

    if (sym_idx >= info->nsyms) return false;
    const ElfW(Sym)& sym = info->symtab[sym_idx];

    if (sym.st_shndx != SHN_UNDEF) { 
        uintptr_t addr = (uintptr_t)load_bias + (uintptr_t)sym.st_value;
        if (ELF_ST_TYPE(sym.st_info) == STT_GNU_IFUNC) {
            auto ifunc = reinterpret_cast<void* (*)()>(addr);
            addr = reinterpret_cast<uintptr_t>(ifunc());
        }
        *out_addr = addr; 
        return true; 
    }
    if (sym.st_name == 0 || sym.st_name >= info->strsz) return false;

    const char *name = &info->strtab[sym.st_name];
    if (!name || !*name) return false;

    ElfW(Addr) local_val = 0;
    uint8_t local_type = 0;
    if (find_dynsym_value(info, name, &local_val, &local_type) && local_val != 0) {
        uintptr_t addr = (uintptr_t)load_bias + local_val;
        if (local_type == STT_GNU_IFUNC) {
            auto ifunc = reinterpret_cast<void* (*)()>(addr);
            addr = reinterpret_cast<uintptr_t>(ifunc());
        }
        *out_addr = addr;
        return true;
    }

    for (const auto& mod_path : needed_paths) {
        if (!mod_path || !*mod_path) continue;
        // First try to resolve within our newly loaded modules
        for (const auto& mod : loaded_modules) {
            if (mod.path == mod_path) {
                ElfW(Addr) mod_val = 0;
                uint8_t mod_type = 0;
                if (find_dynsym_value(&mod.dinfo, name, &mod_val, &mod_type) && mod_val != 0) {
                    uintptr_t addr = (uintptr_t)mod.load_bias + mod_val;
                    if (mod_type == STT_GNU_IFUNC) {
                        auto ifunc = reinterpret_cast<void* (*)()>(addr);
                        addr = reinterpret_cast<uintptr_t>(ifunc());
                    }
                    *out_addr = addr;
                    return true;
                }
            }
        }
    }

    // Fallback to dlsym
    void* sym_ptr = dlsym(RTLD_DEFAULT, name);
    if (sym_ptr) {
        *out_addr = reinterpret_cast<uintptr_t>(sym_ptr);
        return true;
    }

    return false;
}

struct sleb128_decoder {
    const uint8_t *current;
    const uint8_t *end;
};

static void sleb128_decoder_init(sleb128_decoder *decoder, const uint8_t *buffer, size_t count) {
    decoder->current = buffer;
    decoder->end = buffer + count;
}

static int64_t sleb128_decode(sleb128_decoder *decoder) {
    int64_t value = 0;
    size_t shift = 0;
    uint8_t byte;
    const size_t size = sizeof(int64_t) * CHAR_BIT;

    do {
        if (decoder->current >= decoder->end) {
            LOGE("Failed to decode SLEB128: buffer overrun");
            return 0; // Better than aborting the whole daemon
        }

        byte = *decoder->current++;
        value |= ((int64_t)(byte & 0x7F)) << shift;
        shift += 7;
    } while (byte & 0x80);

    if (shift < size && (byte & 0x40)) {
        value |= -((int64_t)1 << shift);
    }

    return value;
}

static uint64_t read_uleb128(const uint8_t **p, const uint8_t *end) {
    const uint8_t *s = *p;
    uint64_t r = 0;
    unsigned shift = 0;

    while (s < end) {
        uint8_t b = *s++;
        r |= ((uint64_t)(b & 0x7f)) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
        if (shift >= 64) break;
    }
    *p = s;
    return r;
}

#define DW_EH_PE_omit     0xff
#define DW_EH_PE_ptr      0x00
#define DW_EH_PE_uleb128  0x01
#define DW_EH_PE_udata2   0x02
#define DW_EH_PE_udata4   0x03
#define DW_EH_PE_udata8   0x04
#define DW_EH_PE_sdata2   0x0a
#define DW_EH_PE_sdata4   0x0b
#define DW_EH_PE_sdata8   0x0c

#define DW_EH_PE_absptr   0x00
#define DW_EH_PE_pcrel    0x10
#define DW_EH_PE_datarel  0x30
#define DW_EH_PE_indirect 0x80

static int read_u16(const uint8_t **p, const uint8_t *end, uint16_t *out) {
    if ((size_t)(end - *p) < sizeof(uint16_t)) return -1;
    uint16_t v = 0;
    memcpy(&v, *p, sizeof(uint16_t));
    *p += sizeof(uint16_t);
    *out = v;
    return 0;
}

static int read_u32(const uint8_t **p, const uint8_t *end, uint32_t *out) {
    if ((size_t)(end - *p) < sizeof(uint32_t)) return -1;
    uint32_t v = 0;
    memcpy(&v, *p, sizeof(uint32_t));
    *p += sizeof(uint32_t);
    *out = v;
    return 0;
}

static int read_u64(const uint8_t **p, const uint8_t *end, uint64_t *out) {
    if ((size_t)(end - *p) < sizeof(uint64_t)) return -1;
    uint64_t v = 0;
    memcpy(&v, *p, sizeof(uint64_t));
    *p += sizeof(uint64_t);
    *out = v;
    return 0;
}

static uintptr_t decode_eh_value(uint8_t enc, const uint8_t **p, uintptr_t base, uintptr_t data_base, const uint8_t *end) {
    if (enc == DW_EH_PE_omit) return 0;
    uint8_t fmt = enc & 0x0f;
    uint8_t app = enc & 0x70;

    uintptr_t value = 0;
    switch (fmt) {
        case DW_EH_PE_ptr:
#ifdef __LP64__
            if (read_u64(p, end, (uint64_t *)&value) != 0) return 0;
#else
            if (read_u32(p, end, (uint32_t *)&value) != 0) return 0;
#endif
            break;
        case DW_EH_PE_uleb128:
            value = (uintptr_t)read_uleb128(p, end);
            break;
        case DW_EH_PE_udata2:
            if (read_u16(p, end, (uint16_t *)&value) != 0) return 0;
            break;
        case DW_EH_PE_udata4:
            if (read_u32(p, end, (uint32_t *)&value) != 0) return 0;
            break;
        case DW_EH_PE_udata8:
            if (read_u64(p, end, (uint64_t *)&value) != 0) return 0;
            break;
        case DW_EH_PE_sdata2:
            if (read_u16(p, end, (uint16_t *)&value) != 0) return 0;
            break;
        case DW_EH_PE_sdata4:
            if (read_u32(p, end, (uint32_t *)&value) != 0) return 0;
            break;
        case DW_EH_PE_sdata8:
            if (read_u64(p, end, (uint64_t *)&value) != 0) return 0;
            break;
        default: return 0;
    }

    switch (app) {
        case DW_EH_PE_absptr: break;
        case DW_EH_PE_pcrel: value += base; break;
        case DW_EH_PE_datarel: value += data_base; break;
        default: break;
    }

    return value;
}

static bool apply_rela_section(int fd, [[maybe_unused]] const elf_dyn_info *info,
                               [[maybe_unused]] const std::vector<const char*>& needed_paths,
                               [[maybe_unused]] const std::vector<LoadedModule>& loaded_modules,
                               uintptr_t load_bias, off_t rela_off, size_t rela_sz) {
    size_t count = rela_sz / sizeof(ElfW(Rela));
    std::vector<ElfW(Rela)> rels(count);
    if (!read_loop_offset(fd, rels.data(), rela_sz, rela_off)) return false;

    for (size_t i = 0; i < count; i++) {
        const ElfW(Rela)& r = rels[i];

        [[maybe_unused]] unsigned type = (unsigned)ELF_R_TYPE(r.r_info);
        [[maybe_unused]] unsigned sym = (unsigned)ELF_R_SYM(r.r_info);
        uintptr_t target = (uintptr_t)load_bias + (uintptr_t)r.r_offset;
        ElfW(Addr) value = 0;

#if defined(__aarch64__)
        if (type == R_AARCH64_RELATIVE) value = (ElfW(Addr))load_bias + (ElfW(Addr))r.r_addend;
        else if (type == R_AARCH64_GLOB_DAT || type == R_AARCH64_JUMP_SLOT || type == R_AARCH64_ABS64) {
            uintptr_t sym_addr = 0;
            if (!resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, sym, &sym_addr)) sym_addr = 0;
            value = sym_addr ? (ElfW(Addr))sym_addr + (ElfW(Addr))r.r_addend : 0;
        } else if (type == R_AARCH64_TLS_DTPMOD) {
            value = info->tls_mod_id;
        } else if (type == R_AARCH64_TLS_DTPREL) {
            const ElfW(Sym)& symb = info->symtab[sym];
            value = (ElfW(Addr))symb.st_value + r.r_addend;
        } else if (type == R_AARCH64_TLS_TPREL) {
            uintptr_t sym_addr = 0;
            if (sym == 0) {
                value = info->tls_segment_vaddr + r.r_addend;
            } else if (resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, sym, &sym_addr)) {
                value = sym_addr - load_bias + info->tls_segment_vaddr;
            }
        } else return false;
#elif defined(__x86_64__)
        if (type == R_X86_64_RELATIVE) value = (ElfW(Addr))load_bias + (ElfW(Addr))r.r_addend;
        else if (type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT || type == R_X86_64_64) {
            uintptr_t sym_addr = 0;
            if (!resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, sym, &sym_addr)) sym_addr = 0;
            value = sym_addr ? (ElfW(Addr))sym_addr + (ElfW(Addr))r.r_addend : 0;
        } else if (type == R_X86_64_DTPMOD64) {
            value = info->tls_mod_id;
        } else if (type == R_X86_64_DTPOFF64) {
            const ElfW(Sym)& symb = info->symtab[sym];
            value = (ElfW(Addr))symb.st_value + r.r_addend;
        } else if (type == R_X86_64_TPOFF64) {
            uintptr_t sym_addr = 0;
            if (sym == 0) {
                value = info->tls_segment_vaddr + r.r_addend;
            } else if (resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, sym, &sym_addr)) {
                value = sym_addr - load_bias + info->tls_segment_vaddr;
            }
        } else return false;
#else
        if (type == 0) value = (ElfW(Addr))load_bias + (ElfW(Addr))r.r_addend;
        else return false;
#endif
        *reinterpret_cast<ElfW(Addr)*>(target) = value;
    }
    return true;
}

static bool apply_rel_section(int fd, [[maybe_unused]] const elf_dyn_info *info,
                              [[maybe_unused]] const std::vector<const char*>& needed_paths,
                              [[maybe_unused]] const std::vector<LoadedModule>& loaded_modules,
                              uintptr_t load_bias, off_t rel_off, size_t rel_sz) {
    size_t count = rel_sz / sizeof(ElfW(Rel));
    std::vector<ElfW(Rel)> rels(count);
    if (!read_loop_offset(fd, rels.data(), rel_sz, rel_off)) return false;

    for (size_t i = 0; i < count; i++) {
        const ElfW(Rel)& r = rels[i];

        [[maybe_unused]] unsigned type = (unsigned)ELF_R_TYPE(r.r_info);
        [[maybe_unused]] unsigned sym = (unsigned)ELF_R_SYM(r.r_info);
        uintptr_t target = (uintptr_t)load_bias + (uintptr_t)r.r_offset;
        [[maybe_unused]] ElfW(Addr) addend = 0;
        ElfW(Addr) value = 0;

#if defined(__arm__)
        if (type == R_ARM_RELATIVE) {
            addend = *reinterpret_cast<ElfW(Addr)*>(target);
            value = (ElfW(Addr))load_bias + addend;
        } else if (type == R_ARM_GLOB_DAT || type == R_ARM_JUMP_SLOT || type == R_ARM_ABS32) {
            uintptr_t sym_addr = 0;
            if (!resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, sym, &sym_addr)) sym_addr = 0;
            if (sym_addr == 0) value = 0;
            else if (type == R_ARM_ABS32) {
                addend = *reinterpret_cast<ElfW(Addr)*>(target);
                value = (ElfW(Addr))sym_addr + addend;
            } else value = (ElfW(Addr))sym_addr;
        } else if (type == R_ARM_TLS_DTPMOD32) {
            value = info->tls_mod_id;
        } else if (type == R_ARM_TLS_DTPOFF32) {
            const ElfW(Sym)& symb = info->symtab[sym];
            value = (ElfW(Addr))symb.st_value; // REL section relies on addend read from mem if present but usually 0 for dtpoff unless added manually
        } else if (type == R_ARM_TLS_TPOFF32) {
            uintptr_t sym_addr = 0;
            if (sym == 0) {
                value = info->tls_segment_vaddr;
            } else if (resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, sym, &sym_addr)) {
                value = sym_addr - load_bias + info->tls_segment_vaddr;
            }
        } else return false;
#elif defined(__i386__)
        if (type == R_386_RELATIVE) {
            addend = *reinterpret_cast<ElfW(Addr)*>(target);
            value = (ElfW(Addr))load_bias + addend;
        } else if (type == R_386_GLOB_DAT || type == R_386_JMP_SLOT || type == R_386_32) {
            uintptr_t sym_addr = 0;
            if (!resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, sym, &sym_addr)) sym_addr = 0;
            if (sym_addr == 0) value = 0;
            else if (type == R_386_32) {
                addend = *reinterpret_cast<ElfW(Addr)*>(target);
                value = (ElfW(Addr))sym_addr + addend;
            } else value = (ElfW(Addr))sym_addr;
        } else if (type == R_386_TLS_DTPMOD32) {
            value = info->tls_mod_id;
        } else if (type == R_386_TLS_DTPOFF32) {
            const ElfW(Sym)& symb = info->symtab[sym];
            value = (ElfW(Addr))symb.st_value;
        } else if (type == R_386_TLS_TPOFF) {
            uintptr_t sym_addr = 0;
            if (sym == 0) {
                value = info->tls_segment_vaddr;
            } else if (resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, sym, &sym_addr)) {
                value = sym_addr - load_bias + info->tls_segment_vaddr;
            }
        } else return false;
#else
        return false;
#endif
        *reinterpret_cast<ElfW(Addr)*>(target) = value;
    }
    return true;
}

static bool apply_android_relocations(int fd, const elf_dyn_info *info,
                                      const std::vector<const char*>& needed_paths,
                                      const std::vector<LoadedModule>& loaded_modules,
                                      uintptr_t load_bias, off_t reloc_off, size_t reloc_sz, bool is_rela) {
    std::vector<uint8_t> reloc_data(reloc_sz);
    if (!read_loop_offset(fd, reloc_data.data(), reloc_sz, reloc_off)) return false;

    if (reloc_sz < 4 || memcmp(reloc_data.data(), "APS2", 4) != 0) {
        LOGE("Invalid Android REL/RELA magic");
        return false;
    }

    sleb128_decoder decoder;
    sleb128_decoder_init(&decoder, reloc_data.data() + 4, reloc_sz - 4);

    uint64_t num_relocs = sleb128_decode(&decoder);
    ElfW(Addr) current_offset = sleb128_decode(&decoder);

    unsigned current_sym_idx = 0;
    unsigned current_type = 0;
    ElfW(Addr) current_addend = 0;

    for (uint64_t i = 0; i < num_relocs; ) {
        uint64_t group_size = sleb128_decode(&decoder);
        uint64_t group_flags = sleb128_decode(&decoder);

        size_t group_r_offset_delta = 0;
        const size_t RELOCATION_GROUPED_BY_INFO_FLAG = 1;
        const size_t RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2;
        const size_t RELOCATION_GROUPED_BY_ADDEND_FLAG = 4;
        const size_t RELOCATION_GROUP_HAS_ADDEND_FLAG = 8;

        if (group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
            group_r_offset_delta = sleb128_decode(&decoder);
        }

        if (group_flags & RELOCATION_GROUPED_BY_INFO_FLAG) {
            ElfW(Addr) r_info = sleb128_decode(&decoder);
            current_sym_idx = ELF_R_SYM(r_info);
            current_type = ELF_R_TYPE(r_info);
        }

        size_t group_flags_reloc = 0;
        if (is_rela) {
            group_flags_reloc = group_flags & (RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG);
            if (group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG) {
                // Each relocation has an addend.
            } else if (group_flags_reloc == (RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG)) {
                current_addend += sleb128_decode(&decoder);
            } else {
                current_addend = 0;
            }
        } else {
            if (group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG) {
                LOGE("REL relocations should not have addends");
                return false;
            }
        }

        for (size_t j = 0; j < group_size; ++j) {
            if (group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
                current_offset += group_r_offset_delta;
            } else {
                current_offset += sleb128_decode(&decoder);
            }
            if ((group_flags & RELOCATION_GROUPED_BY_INFO_FLAG) == 0) {
                ElfW(Addr) r_info = sleb128_decode(&decoder);
                current_sym_idx = ELF_R_SYM(r_info);
                current_type = ELF_R_TYPE(r_info);
            }
            if (is_rela && group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG) {
                current_addend += sleb128_decode(&decoder);
            }

            uintptr_t target = (uintptr_t)load_bias + (uintptr_t)current_offset;
            ElfW(Addr) value = 0;

#if defined(__aarch64__)
            if (current_type == R_AARCH64_RELATIVE) value = (ElfW(Addr))load_bias + (ElfW(Addr))current_addend;
            else if (current_type == R_AARCH64_GLOB_DAT || current_type == R_AARCH64_JUMP_SLOT || current_type == R_AARCH64_ABS64) {
                uintptr_t sym_addr = 0;
                if (!resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, current_sym_idx, &sym_addr)) sym_addr = 0;
                value = sym_addr ? (ElfW(Addr))sym_addr + (ElfW(Addr))current_addend : 0;
            } else if (current_type == R_AARCH64_TLS_DTPMOD) {
                value = info->tls_mod_id;
            } else if (current_type == R_AARCH64_TLS_DTPREL) {
                const ElfW(Sym)& sym = info->symtab[current_sym_idx];
                value = (ElfW(Addr))sym.st_value + current_addend;
            } else if (current_type == R_AARCH64_TLS_TPREL) {
                uintptr_t sym_addr = 0;
                if (current_sym_idx == 0) {
                    value = info->tls_segment_vaddr + current_addend;
                } else if (resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                    value = sym_addr - load_bias + info->tls_segment_vaddr; // Rough TPREL emulation without tpidr thread-context
                }
            } else return false;
#elif defined(__x86_64__)
            if (current_type == R_X86_64_RELATIVE) value = (ElfW(Addr))load_bias + (ElfW(Addr))current_addend;
            else if (current_type == R_X86_64_GLOB_DAT || current_type == R_X86_64_JUMP_SLOT || current_type == R_X86_64_64) {
                uintptr_t sym_addr = 0;
                if (!resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, current_sym_idx, &sym_addr)) sym_addr = 0;
                value = sym_addr ? (ElfW(Addr))sym_addr + (ElfW(Addr))current_addend : 0;
            } else if (current_type == R_X86_64_DTPMOD64) {
                value = info->tls_mod_id;
            } else if (current_type == R_X86_64_DTPOFF64) {
                const ElfW(Sym)& sym = info->symtab[current_sym_idx];
                value = (ElfW(Addr))sym.st_value + current_addend;
            } else if (current_type == R_X86_64_TPOFF64) {
                uintptr_t sym_addr = 0;
                if (current_sym_idx == 0) {
                    value = info->tls_segment_vaddr + current_addend;
                } else if (resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                    value = sym_addr - load_bias + info->tls_segment_vaddr;
                }
            } else return false;
#elif defined(__arm__)
            if (current_type == R_ARM_RELATIVE) {
                ElfW(Addr) addend_rel = *reinterpret_cast<ElfW(Addr)*>(target);
                value = (ElfW(Addr))load_bias + addend_rel;
            } else if (current_type == R_ARM_GLOB_DAT || current_type == R_ARM_JUMP_SLOT || current_type == R_ARM_ABS32) {
                uintptr_t sym_addr = 0;
                if (!resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, current_sym_idx, &sym_addr)) sym_addr = 0;
                if (sym_addr == 0) value = 0;
                else if (current_type == R_ARM_ABS32) {
                    ElfW(Addr) addend_rel = *reinterpret_cast<ElfW(Addr)*>(target);
                    value = (ElfW(Addr))sym_addr + addend_rel;
                } else value = (ElfW(Addr))sym_addr;
            } else if (current_type == R_ARM_TLS_DTPMOD32) {
                value = info->tls_mod_id;
            } else if (current_type == R_ARM_TLS_DTPOFF32) {
                const ElfW(Sym)& sym = info->symtab[current_sym_idx];
                value = (ElfW(Addr))sym.st_value + current_addend;
            } else if (current_type == R_ARM_TLS_TPOFF32) {
                uintptr_t sym_addr = 0;
                if (current_sym_idx == 0) {
                    value = info->tls_segment_vaddr + current_addend;
                } else if (resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                    value = sym_addr - load_bias + info->tls_segment_vaddr;
                }
            } else return false;
#elif defined(__i386__)
            if (current_type == R_386_RELATIVE) {
                ElfW(Addr) addend_rel = *reinterpret_cast<ElfW(Addr)*>(target);
                value = (ElfW(Addr))load_bias + addend_rel;
            } else if (current_type == R_386_GLOB_DAT || current_type == R_386_JMP_SLOT || current_type == R_386_32) {
                uintptr_t sym_addr = 0;
                if (!resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, current_sym_idx, &sym_addr)) sym_addr = 0;
                if (sym_addr == 0) value = 0;
                else if (current_type == R_386_32) {
                    ElfW(Addr) addend_rel = *reinterpret_cast<ElfW(Addr)*>(target);
                    value = (ElfW(Addr))sym_addr + addend_rel;
                } else value = (ElfW(Addr))sym_addr;
            } else if (current_type == R_386_TLS_DTPMOD32) {
                value = info->tls_mod_id;
            } else if (current_type == R_386_TLS_DTPOFF32) {
                const ElfW(Sym)& sym = info->symtab[current_sym_idx];
                value = (ElfW(Addr))sym.st_value + current_addend;
            } else if (current_type == R_386_TLS_TPOFF) {
                uintptr_t sym_addr = 0;
                if (current_sym_idx == 0) {
                    value = info->tls_segment_vaddr + current_addend;
                } else if (resolve_symbol_addr(info, needed_paths, loaded_modules, load_bias, current_sym_idx, &sym_addr)) {
                    value = sym_addr - load_bias + info->tls_segment_vaddr;
                }
            } else return false;
#else
            return false;
#endif
            *reinterpret_cast<ElfW(Addr)*>(target) = value;
        }

        i += group_size;
    }
    return true;
}

static bool apply_relr_section(int fd, uintptr_t load_bias, off_t relr_off, size_t relr_sz) {
    size_t count = relr_sz / sizeof(ElfW(Addr));
    std::vector<ElfW(Addr)> relr(count);
    if (!read_loop_offset(fd, relr.data(), relr_sz, relr_off)) return false;

    const size_t bits_per_entry = sizeof(ElfW(Addr)) * 8;
    ElfW(Addr) base_offset = 0;

    for (size_t i = 0; i < count; i++) {
        ElfW(Addr) entry = relr[i];

        if ((entry & 1) == 0) {
            // Even entries encode an explicit address
            ElfW(Addr) reloc_offset = entry;
            uintptr_t target = (uintptr_t)load_bias + reloc_offset;
            ElfW(Addr) value = *reinterpret_cast<ElfW(Addr)*>(target);
            value += load_bias;
            *reinterpret_cast<ElfW(Addr)*>(target) = value;

            base_offset = reloc_offset + sizeof(ElfW(Addr));
            continue;
        }

        // Odd entries encode a bitmap of up to (bits_per_entry - 1) following words
        ElfW(Addr) bitmap = entry >> 1;

        for (size_t bit = 0; bitmap != 0 && bit < bits_per_entry - 1; bit++, bitmap >>= 1) {
            if ((bitmap & 1) == 0) continue;

            uintptr_t target = (uintptr_t)load_bias + base_offset + (bit * sizeof(ElfW(Addr)));
            ElfW(Addr) value = *reinterpret_cast<ElfW(Addr)*>(target);
            value += load_bias;
            *reinterpret_cast<ElfW(Addr)*>(target) = value;
        }

        base_offset += sizeof(ElfW(Addr)) * (bits_per_entry - 1);
    }

    return true;
}

static bool apply_module_relocations(int memfd, LoadedModule& mod, const std::vector<LoadedModule>& loaded_modules) {
    UniqueFd fd;

    if (mod.path == "main_module" && memfd >= 0) {
        fd = UniqueFd(dup(memfd));
    } else {
        fd = UniqueFd(open(mod.path.c_str(), O_RDONLY | O_CLOEXEC));
    }

    if (fd < 0) {
        LOGE("Failed to open module file for relocations: %s", mod.path.c_str());
        return false;
    }

    std::vector<const char*> needed_paths(mod.dinfo.needed_str_offsets.size(), nullptr);
    for (size_t i = 0; i < mod.dinfo.needed_str_offsets.size(); i++) {
        size_t off = mod.dinfo.needed_str_offsets[i];
        if (off < mod.dinfo.strsz) {
            const char *soname = &mod.dinfo.strtab[off];
            for (const auto& m : loaded_modules) {
                const char *m_name = strrchr(m.path.c_str(), '/');
                m_name = m_name ? m_name + 1 : m.path.c_str();
                if (strcmp(m_name, soname) == 0) {
                    needed_paths[i] = m.path.c_str();
                    break;
                }
            }
        }
    }

    if (mod.dinfo.rela_sz && mod.dinfo.rela_off) {
        if (!apply_rela_section(fd, &mod.dinfo, needed_paths, loaded_modules, mod.load_bias, mod.dinfo.rela_off, mod.dinfo.rela_sz)) return false;
    }
    if (mod.dinfo.rel_sz && mod.dinfo.rel_off) {
        if (!apply_rel_section(fd, &mod.dinfo, needed_paths, loaded_modules, mod.load_bias, mod.dinfo.rel_off, mod.dinfo.rel_sz)) return false;
    }
    if (mod.dinfo.jmprel_sz && mod.dinfo.jmprel_off) {
        if (mod.dinfo.pltrel_type == DT_RELA) {
            if (!apply_rela_section(fd, &mod.dinfo, needed_paths, loaded_modules, mod.load_bias, mod.dinfo.jmprel_off, mod.dinfo.jmprel_sz)) return false;
        } else {
            if (!apply_rel_section(fd, &mod.dinfo, needed_paths, loaded_modules, mod.load_bias, mod.dinfo.jmprel_off, mod.dinfo.jmprel_sz)) return false;
        }
    }

    if (mod.dinfo.android_rel_sz && mod.dinfo.android_rel_off) {
        if (!apply_android_relocations(fd, &mod.dinfo, needed_paths, loaded_modules, mod.load_bias, mod.dinfo.android_rel_off, mod.dinfo.android_rel_sz, mod.dinfo.android_is_rela)) return false;
    }
    if (mod.dinfo.relr_sz && mod.dinfo.relr_off) {
        if (!apply_relr_section(fd, mod.load_bias, mod.dinfo.relr_off, mod.dinfo.relr_sz)) return false;
    }

    return true;
}

extern "C" void __register_frame(void*) __attribute__((weak));
extern "C" void __deregister_frame(void*) __attribute__((weak));

static bool load_single_library(const char *lib_path, int memfd, LoadedModule* out_module) {
    long page_size_long = sysconf(_SC_PAGESIZE);
    size_t page_size = (size_t)page_size_long;

    UniqueFd fd;
    if (memfd >= 0) {
        fd = UniqueFd(dup(memfd));
    } else {
        fd = UniqueFd(open(lib_path, O_RDONLY | O_CLOEXEC));
    }
    if (fd < 0) return false;

    ElfW(Ehdr) eh;
    std::vector<ElfW(Phdr)> phdr;
    ElfW(Addr) min_vaddr = 0;
    size_t map_size = 0;

    if (!compute_load_layout(fd, page_size, &eh, phdr, &min_vaddr, &map_size)) { return false; }

    void* remote_base_ptr = mmap(nullptr, map_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (remote_base_ptr == MAP_FAILED) return false;
    uintptr_t remote_base = reinterpret_cast<uintptr_t>(remote_base_ptr);

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
            void* seg_map = mmap(reinterpret_cast<void*>(seg_page), file_page_end - seg_page, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, fd, file_page_offset);
            if (seg_map == MAP_FAILED) return false;

            if (is_writable && file_page_end > file_end) {
                memset(reinterpret_cast<void*>(file_end), 0, file_page_end - file_end);
            }
        }
        if (seg_page_end > file_page_end) {
            void* bss_map = mmap(reinterpret_cast<void*>(file_page_end), seg_page_end - file_page_end, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (bss_map == MAP_FAILED) return false;
        }
        int prot = 0;
        if (phdr[i].p_flags & PF_R) prot |= PROT_READ;
        if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC;
        segs.push_back({seg_page, seg_page_len, prot});
    }

    elf_dyn_info dinfo;
    if (!elf_load_dyn_info(fd, &eh, phdr, &dinfo)) return false;

    for (const auto& s : segs) {
        if (s.prot == (PROT_READ | PROT_WRITE)) continue;
        mprotect(reinterpret_cast<void*>(s.addr), s.len, s.prot);
    }

    if (dinfo.tls_segment_vaddr && dinfo.tls_segment_memsz) {
        CustomTlsInfo* tls_info = new CustomTlsInfo();
        tls_info->module_id = reinterpret_cast<size_t>(tls_info);
        pthread_key_create(&tls_info->key, free);
        dinfo.tls_mod_id = tls_info->module_id;
    }

    out_module->path = lib_path;
    out_module->load_bias = load_bias;
    out_module->base = remote_base;
    out_module->size = map_size;
    out_module->dinfo = std::move(dinfo);

    return true;
}

static bool _linker_find_library_path(const char *lib_name, char *full_path, size_t full_path_size) {
    const char *search_paths[] = {
#ifdef __LP64__
#ifdef __ANDROID__
        "/apex/com.android.runtime/lib64/bionic/",
        "/apex/com.android.runtime/lib64/",
        "/system/lib64/",
        "/vendor/lib64/",
#else
        "/lib64/",
        "/usr/lib64/",
        "/lib/x86_64-linux-gnu/",
        "/usr/lib/x86_64-linux-gnu/",
#endif
#else
#ifdef __ANDROID__
        "/apex/com.android.runtime/lib/bionic/",
        "/apex/com.android.runtime/lib/",
        "/system/lib/",
        "/vendor/lib/",
#else
        "/lib/",
        "/usr/lib/",
        "/lib/i386-linux-gnu/",
#endif
#endif
        "/usr/local/lib/",
        nullptr
    };

#ifdef __ANDROID__
    if (strstr(lib_name, "libc++")) {
        LOGD("Forced replacement for using /system/lib64 for libc++.so");
#ifdef __LP64__
        snprintf(full_path, full_path_size, "/system/lib64/%s", lib_name);
#else
        snprintf(full_path, full_path_size, "/system/lib/%s", lib_name);
#endif
        return true;
    }
#endif

    for (int i = 0; search_paths[i] != nullptr; ++i) {
        snprintf(full_path, full_path_size, "%s%s", search_paths[i], lib_name);
        if (access(full_path, F_OK) == 0) return true;
    }

    full_path[0] = '\0';
    return false;
}

static bool load_dependencies_recursive(const char *lib_path, int memfd, std::vector<LoadedModule>& loaded_modules) {
    const char *soname = strrchr(lib_path, '/');
    soname = soname ? soname + 1 : lib_path;

    for (const auto& m : loaded_modules) {
        const char *m_name = strrchr(m.path.c_str(), '/');
        m_name = m_name ? m_name + 1 : m.path.c_str();
        if (strcmp(m_name, soname) == 0) {
            return true; // Already loaded
        }
    }

    // Allows the system linker (Bionic) to load the library if it is system.
    // We remove RTLD_NOLOAD so that Bionic can safely load it if it is missing, 
    // avoiding mapping duplicate manual copies of the OS.
    void* existing_handle = dlopen(soname, RTLD_NOW);
    if (existing_handle != nullptr) {
        // We INTENTIONALLY do not do dlclose(). We want the system to maintain
        // the library lives in memory so that our module can use it.
        return true;
    }

    LoadedModule mod;
    if (!load_single_library(lib_path, memfd, &mod)) {
        LOGE("Failed to load dependency: %s", lib_path);
        return false;
    }

    loaded_modules.push_back(std::move(mod));
    size_t current_idx = loaded_modules.size() - 1;

    std::vector<size_t> needed_offsets = loaded_modules[current_idx].dinfo.needed_str_offsets;

    for (size_t off : needed_offsets) {
        if (off >= loaded_modules[current_idx].dinfo.strsz) continue;

        const char *dep_soname = &loaded_modules[current_idx].dinfo.strtab[off];

        char full_path[1024];
        if (_linker_find_library_path(dep_soname, full_path, sizeof(full_path))) {
            if (!load_dependencies_recursive(full_path, -1, loaded_modules)) {
                LOGW("Failed to recursively load dependency %s for %s", full_path, lib_path);
            }
        } else {
            LOGW("Could not find library path for %s needed by %s", dep_soname, lib_path);
        }
    }
    return true;
}

static inline void cleanup_failed_load(const std::vector<LoadedModule>& loaded_modules) {
    for (auto it = loaded_modules.rbegin(); it != loaded_modules.rend(); ++it) {
        const auto& mod = *it;
        if (mod.eh_registered && __deregister_frame) {
            __deregister_frame(reinterpret_cast<void*>(mod.eh_frame_ptr));
        }
        if (mod.dinfo.tls_mod_id) {
            CustomTlsInfo* tls_info = reinterpret_cast<CustomTlsInfo*>(mod.dinfo.tls_mod_id);
            pthread_key_delete(tls_info->key);
            delete tls_info;
        }
        if (mod.base != 0 && mod.size != 0) {
            munmap(reinterpret_cast<void*>(mod.base), mod.size);
        }
    }
}

struct tls_index {
    size_t module_id;
    size_t offset;
};

extern "C" void* custom_tls_get_addr(tls_index* ti) {
    CustomTlsInfo* tls_info = reinterpret_cast<CustomTlsInfo*>(ti->module_id);
    if (tls_info && tls_info->module_id == ti->module_id) {
        void* ptr = pthread_getspecific(tls_info->key);
        if (!ptr) {
            size_t size = 4096;
            posix_memalign(&ptr, 16, size);
            memset(ptr, 0, size);
            pthread_setspecific(tls_info->key, ptr);
        }
        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(ptr) + ti->offset);
    }
    auto original_tls = reinterpret_cast<void*(*)(tls_index*)>(dlsym(RTLD_DEFAULT, "__tls_get_addr"));
    return original_tls ? original_tls(ti) : nullptr;
}

// ---------------- MAIN ----------------
extern "C" bool custom_linker_load(int memfd, uintptr_t *out_base, size_t *out_total_size, uintptr_t *out_entry, uintptr_t *out_init_array, size_t *out_init_count) {
    std::vector<LoadedModule> loaded_modules;

    // Give a dummy name for the main module
    if (!load_dependencies_recursive("main_module", memfd, loaded_modules)) {
        LOGE("Failed to recursively load main module and its dependencies");
        cleanup_failed_load(loaded_modules);
        return false;
    }

    if (loaded_modules.empty()) return false;

    // Step 1: Hook TLS for all modules first
    for (auto& mod : loaded_modules) {
        for (size_t i = 0; i < mod.dinfo.nsyms; i++) {
            ElfW(Sym)& sym = mod.dinfo.symtab[i];
            if (sym.st_name != 0 && sym.st_name < mod.dinfo.strsz) {
                const char *name = &mod.dinfo.strtab[sym.st_name];
                if (strcmp(name, "__tls_get_addr") == 0) {
                    sym.st_value = reinterpret_cast<uintptr_t>(&custom_tls_get_addr) - mod.load_bias;
                    sym.st_shndx = 1;
                }
            }
        }
    }

    // Step 2: Relocate and Initialize in REVERSE order (dependencies first)
    for (auto it = loaded_modules.rbegin(); it != loaded_modules.rend(); ++it) {
        auto& mod = *it;

        if (!apply_module_relocations(memfd, mod, loaded_modules)) {
            LOGE("Failed to apply relocations for module %s", mod.path.c_str());
            cleanup_failed_load(loaded_modules);
            return false;
        }

        // Register DWARF immediately after relocation
        if (__register_frame && mod.dinfo.eh_frame_hdr_sz && mod.dinfo.eh_frame_hdr_vaddr) {
            uintptr_t hdr_addr = mod.load_bias + mod.dinfo.eh_frame_hdr_vaddr;
            const uint8_t *p = reinterpret_cast<const uint8_t*>(hdr_addr);
            const uint8_t *end = p + mod.dinfo.eh_frame_hdr_sz;

            if (mod.dinfo.eh_frame_hdr_sz >= 4) {
                uint8_t version = *p++;
                uint8_t eh_frame_ptr_enc = *p++;
                [[maybe_unused]] uint8_t fde_count_enc = *p++;
                [[maybe_unused]] uint8_t table_enc = *p++;

                if (version == 1) {
                    uintptr_t base = hdr_addr + (p - reinterpret_cast<const uint8_t*>(hdr_addr));
                    uintptr_t eh_frame_ptr = decode_eh_value(eh_frame_ptr_enc, &p, base, hdr_addr, end);
                    if (eh_frame_ptr) {
                        __register_frame(reinterpret_cast<void*>(eh_frame_ptr));
                        mod.eh_registered = true;
                        mod.eh_frame_ptr = eh_frame_ptr;
                    }
                }
            }
        }

        // Execute Constructors immediately after DWARF registration
        if (mod.dinfo.init_vaddr) {
            auto func = reinterpret_cast<void (*)()>(mod.load_bias + mod.dinfo.init_vaddr);
            func();
        }

        if (mod.dinfo.init_array_vaddr && mod.dinfo.init_arraysz) {
            size_t count = mod.dinfo.init_arraysz / sizeof(ElfW(Addr));
            ElfW(Addr)* array_addr = reinterpret_cast<ElfW(Addr)*>(mod.load_bias + mod.dinfo.init_array_vaddr);
            for (size_t i = 0; i < count; ++i) {
                if (array_addr[i]) {
                    auto func = reinterpret_cast<void (*)()>(array_addr[i]);
                    func();
                }
            }
        }
    }

    LoadedModule& main_mod = loaded_modules[0];

    ElfW(Addr) entry_value = 0;
    if (!find_dynsym_value(&main_mod.dinfo, "zygisk_module_entry", &entry_value)) {
        LOGE("Module %s does not export 'zygisk_module_entry'. Invalid Zygisk module.", main_mod.path.c_str());
        cleanup_failed_load(loaded_modules);
        return false;
    }

    *out_base = main_mod.base;
    *out_total_size = main_mod.size;
    *out_entry = (uintptr_t)main_mod.load_bias + (uintptr_t)entry_value;
    *out_init_array = main_mod.dinfo.init_array_vaddr ? ((uintptr_t)main_mod.load_bias + main_mod.dinfo.init_array_vaddr) : 0;
    *out_init_count = main_mod.dinfo.init_arraysz ? (main_mod.dinfo.init_arraysz / sizeof(ElfW(Addr))) : 0;

    {
        std::lock_guard<std::mutex> lock(g_custom_regions_lock);
        CustomRegion region;
        region.base = main_mod.base;
        region.size = main_mod.size;

        // We collect all destroyers in reverse order of loading
        for (auto it = loaded_modules.rbegin(); it != loaded_modules.rend(); ++it) {
            const auto& mod = *it;

            // 1. FINI_ARRAY is executed in reverse order (from the end of the array to the beginning)
            if (mod.dinfo.fini_array_vaddr && mod.dinfo.fini_arraysz) {
                size_t count = mod.dinfo.fini_arraysz / sizeof(ElfW(Addr));
                ElfW(Addr)* array_addr = reinterpret_cast<ElfW(Addr)*>(mod.load_bias + mod.dinfo.fini_array_vaddr);
                for (size_t i = 0; i < count; ++i) {
                    if (array_addr[count - 1 - i]) {
                        auto func = reinterpret_cast<void (*)()>(array_addr[count - 1 - i]);
                        region.destructors.push_back(func);
                    }
                }
            }

            // 2. DT_FINI is executed after FINI_ARRAY
            if (mod.dinfo.fini_vaddr) {
                auto func = reinterpret_cast<void (*)()>(mod.load_bias + mod.dinfo.fini_vaddr);
                region.destructors.push_back(func);
            }

            // 3. It's also the perfect time to clean up TLS and DWARF
            if (mod.dinfo.tls_mod_id) {
                size_t mod_id = mod.dinfo.tls_mod_id;
                region.destructors.push_back([mod_id]() {
                    CustomTlsInfo* tls_info = reinterpret_cast<CustomTlsInfo*>(mod_id);
                    pthread_key_delete(tls_info->key);
                    delete tls_info;
                });
            }

            if (mod.eh_registered && __deregister_frame) {
                uintptr_t frame_ptr = mod.eh_frame_ptr;
                region.destructors.push_back([frame_ptr]() {
                    __deregister_frame(reinterpret_cast<void*>(frame_ptr));
                });
            }
        }

        g_custom_regions.push_back(std::move(region));
    }
    return true;
}
