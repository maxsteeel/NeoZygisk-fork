#include "elf_utils.hpp"
#include <unistd.h>
#include <string.h>
#include <errno.h>

bool read_loop_offset(int fd, void *buf, size_t count, off_t offset) {
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

bool compute_load_layout(int fd, size_t page_size, ElfW(Ehdr) *eh,
                         std::unique_ptr<ElfW(Phdr)[]>& out_phdr, ElfW(Addr) *out_min_vaddr,
                         size_t *out_map_size) {
    if (!read_loop_offset(fd, eh, sizeof(*eh), 0)) return false;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return false;

    size_t phdr_sz = (size_t)eh->e_phnum * sizeof(ElfW(Phdr));
    out_phdr = std::make_unique<ElfW(Phdr)[]>(eh->e_phnum);
    if (!read_loop_offset(fd, out_phdr.get(), phdr_sz, eh->e_phoff)) return false;

    ElfW(Addr) lo = (ElfW(Addr))UINTPTR_MAX;
    ElfW(Addr) hi = 0;

    for (int i = 0; i < eh->e_phnum; i++) {
        if (out_phdr[i].p_type != PT_LOAD) continue;
        if (out_phdr[i].p_vaddr < lo) lo = out_phdr[i].p_vaddr;
        ElfW(Addr) end;
        if (__builtin_add_overflow(out_phdr[i].p_vaddr, out_phdr[i].p_memsz, &end)) return false;
        if (end > hi) hi = end;
    }

    if (hi <= lo) return false;
    *out_min_vaddr = (ElfW(Addr))page_start((uintptr_t)lo, page_size);
    *out_map_size = (size_t)(page_end((uintptr_t)hi, page_size) - *out_min_vaddr);
    return true;
}

bool vaddr_to_offset(const std::unique_ptr<ElfW(Phdr)[]>& phdr, size_t phnum, ElfW(Addr) vaddr, off_t *out_off) {
    for (size_t i = 0; i < phnum; i++) {
        const auto& p = phdr[i];
        if (p.p_type != PT_LOAD) continue;
        ElfW(Addr) seg_start = p.p_vaddr;
        ElfW(Addr) seg_end = p.p_vaddr + p.p_filesz;
        if (vaddr < seg_start || vaddr >= seg_end) continue;
        *out_off = (off_t)p.p_offset + (off_t)(vaddr - seg_start);
        return true;
    }
    return false;
}

bool elf_load_dyn_info(void* memory_map, bool is_raw_file, const ElfW(Ehdr) *eh, const std::unique_ptr<ElfW(Phdr)[]>& phdr, elf_dyn_info *out) {
    // Helper to calculate exact memory pointers without reading from disk
    auto get_ptr = [&](ElfW(Addr) vaddr) -> void* {
        if (is_raw_file) {
            off_t offset;
            if (vaddr_to_offset(phdr, eh->e_phnum, vaddr, &offset)) {
                return reinterpret_cast<uint8_t*>(memory_map) + offset;
            }
            return nullptr;
        }
        return reinterpret_cast<uint8_t*>(memory_map) + vaddr;
    };

    const ElfW(Phdr) *dyn_phdr = nullptr;
    for (size_t i = 0; i < eh->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) dyn_phdr = &phdr[i];
        else if (phdr[i].p_type == PT_GNU_EH_FRAME) {
            out->eh_frame_hdr_vaddr = phdr[i].p_vaddr;
            out->eh_frame_hdr_sz = phdr[i].p_memsz;
        } else if (phdr[i].p_type == PT_GNU_RELRO) {
            out->relro_vaddr = phdr[i].p_vaddr;
            out->relro_sz = phdr[i].p_memsz;
        } else if (phdr[i].p_type == PT_TLS) {
            out->tls_segment_vaddr = phdr[i].p_vaddr;
            out->tls_segment_memsz = phdr[i].p_memsz;
        }
    }

    if (!dyn_phdr || dyn_phdr->p_filesz == 0) return false;

    ElfW(Dyn)* dyn = reinterpret_cast<ElfW(Dyn)*>(get_ptr(dyn_phdr->p_vaddr));
    if (!dyn) return false;

    size_t dyn_count = dyn_phdr->p_filesz / sizeof(ElfW(Dyn));
    ElfW(Addr) symtab_vaddr = 0, strtab_vaddr = 0, gnu_hash_vaddr = 0;

    for (size_t i = 0; i < dyn_count; i++) {
        const auto& d = dyn[i]; 
        switch (d.d_tag) {
            case DT_SYMTAB: symtab_vaddr = (ElfW(Addr))d.d_un.d_ptr; break;
            case DT_STRTAB: strtab_vaddr = (ElfW(Addr))d.d_un.d_ptr; break;
            case DT_STRSZ: out->strsz = (size_t)d.d_un.d_val; break;
            case DT_SYMENT: out->syment = (size_t)d.d_un.d_val; break;
            case DT_REL: out->rel_vaddr = (ElfW(Addr))d.d_un.d_ptr; break;
            case DT_RELSZ: out->rel_sz = (size_t)d.d_un.d_val; break;
            case DT_RELA: out->rela_vaddr = (ElfW(Addr))d.d_un.d_ptr; break;
            case DT_RELASZ: out->rela_sz = (size_t)d.d_un.d_val; break;
            case DT_JMPREL: out->jmprel_vaddr = (ElfW(Addr))d.d_un.d_ptr; break;
            case DT_PLTRELSZ: out->jmprel_sz = (size_t)d.d_un.d_val; break;
            case DT_PLTREL: out->pltrel_type = (int)d.d_un.d_val; break;
            case DT_GNU_HASH: gnu_hash_vaddr = (ElfW(Addr))d.d_un.d_ptr; break;
            case DT_NEEDED: if (out->needed_count < 128) out->needed_str_offsets[out->needed_count++] = d.d_un.d_val; break;
            case DT_INIT_ARRAY: out->init_array_vaddr = (ElfW(Addr))d.d_un.d_ptr; break;
            case DT_INIT_ARRAYSZ: out->init_arraysz = (size_t)d.d_un.d_val; break;
            case DT_INIT: out->init_vaddr = (ElfW(Addr))d.d_un.d_ptr; break;
            case DT_FINI: out->fini_vaddr = (ElfW(Addr))d.d_un.d_ptr; break;
            case DT_FINI_ARRAY: out->fini_array_vaddr = (ElfW(Addr))d.d_un.d_ptr; break;
            case DT_FINI_ARRAYSZ: out->fini_arraysz = (size_t)d.d_un.d_val; break;
#ifdef __ANDROID__
            case DT_ANDROID_RELA: out->android_rel_vaddr = (ElfW(Addr))d.d_un.d_ptr; out->android_is_rela = true; break;
            case DT_ANDROID_RELASZ: out->android_rel_sz = (size_t)d.d_un.d_val; break;
            case DT_ANDROID_REL: out->android_rel_vaddr = (ElfW(Addr))d.d_un.d_ptr; out->android_is_rela = false; break;
            case DT_ANDROID_RELSZ: out->android_rel_sz = (size_t)d.d_un.d_val; break;
            case DT_ANDROID_RELR:
            case DT_RELR: out->relr_vaddr = (ElfW(Addr))d.d_un.d_ptr; break;
            case DT_ANDROID_RELRSZ:
            case DT_RELRSZ: out->relr_sz = (size_t)d.d_un.d_val; break;
#endif
            case DT_NULL: i = dyn_count; break;
        }
    }

    if (!out->syment) out->syment = sizeof(ElfW(Sym));
    if (!symtab_vaddr || !strtab_vaddr || !out->strsz) return false;

    out->symtab = reinterpret_cast<ElfW(Sym)*>(get_ptr(symtab_vaddr));
    out->strtab = reinterpret_cast<const char*>(get_ptr(strtab_vaddr));
    if (!out->symtab || !out->strtab) return false;

    if (gnu_hash_vaddr) {
        uint32_t* gnu_hash = reinterpret_cast<uint32_t*>(get_ptr(gnu_hash_vaddr));
        if (gnu_hash) {
            uint32_t nbuckets = gnu_hash[0];
            out->gnu_symndx = gnu_hash[1];
            uint32_t bloom_size = gnu_hash[2];
            out->gnu_shift2 = gnu_hash[3];

            out->gnu_bloom_filter = reinterpret_cast<const ElfW(Addr)*>(&gnu_hash[4]);
            out->gnu_bloom_filter_size = bloom_size;
            out->gnu_buckets = reinterpret_cast<const uint32_t*>(&out->gnu_bloom_filter[bloom_size]);
            out->gnu_buckets_size = nbuckets;
            out->gnu_chains = &out->gnu_buckets[nbuckets];

            // Fast loop to calculate total symbols
            uint32_t max_bucket = 0;
            for (uint32_t b = 0; b < nbuckets; b++) {
                if (out->gnu_buckets[b] > max_bucket) max_bucket = out->gnu_buckets[b];
            }
            if (max_bucket >= out->gnu_symndx) {
                uint32_t chain_idx = max_bucket - out->gnu_symndx;
                while (true) {
                    if (out->gnu_chains[chain_idx] & 1) { out->nsyms = max_bucket + 1; break; }
                    max_bucket++; chain_idx++;
                }
            } else {
                out->nsyms = out->gnu_symndx;
            }
        }
    }
    return true;
}

static uint32_t calc_gnu_hash(const char *name) {
    uint32_t h = 5381;
    for (unsigned char c = *name; c != '\0'; c = *++name) {
        h = (h << 5) + h + c;
    }
    return h;
}

bool find_dynsym_value(const elf_dyn_info *info, const char *sym_name, ElfW(Addr) *out_value, uint8_t *out_type) {
    if (info->gnu_buckets != nullptr && info->gnu_bloom_filter != nullptr) {
        uint32_t hash = calc_gnu_hash(sym_name);
        uint32_t h2 = hash >> info->gnu_shift2;
        uint32_t word_num = (hash / (sizeof(ElfW(Addr)) * 8)) & (info->gnu_bloom_filter_size - 1);

        ElfW(Addr) mask = (((ElfW(Addr))1) << (hash % (sizeof(ElfW(Addr)) * 8))) |
                          (((ElfW(Addr))1) << (h2 % (sizeof(ElfW(Addr)) * 8)));

        if ((info->gnu_bloom_filter[word_num] & mask) == mask) {
            uint32_t sym_idx = info->gnu_buckets[hash % info->gnu_buckets_size];
            if (sym_idx >= info->gnu_symndx) {
                uint32_t chain_idx = sym_idx - info->gnu_symndx;

                while (sym_idx < info->nsyms) {
                    uint32_t chain_val = info->gnu_chains[chain_idx];
                    if ((chain_val | 1) == (hash | 1)) {
                        const ElfW(Sym)& sym = info->symtab[sym_idx];
                        const char *name = &info->strtab[sym.st_name];
                        if (strcmp(name, sym_name) == 0 && sym.st_shndx != SHN_UNDEF) {
                            *out_value = sym.st_value;
                            if (out_type) *out_type = ELF_ST_TYPE(sym.st_info);
                            return true;
                        }
                    }
                    if (chain_val & 1) break;
                    chain_idx++;
                    sym_idx++;
                }
            }
        }
        return false;
    }

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

struct SymData {
    const char* lib_name;
    const char* sym_name;
    void* result;
};

static int sym_cb(struct dl_phdr_info* info, [[maybe_unused]] size_t size, void* data) {
    auto* search = reinterpret_cast<SymData*>(data);

    // Check if this is the library we are looking for
    if (!info->dlpi_name || !strstr(info->dlpi_name, search->lib_name)) {
        return 0; // Continue searching
    }

    ElfW(Addr) base = info->dlpi_addr;
    ElfW(Dyn)* dyn = nullptr;

    // Find the PT_DYNAMIC section
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<ElfW(Dyn)*>(base + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }

    if (!dyn) return 0;

    ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    uint32_t* gnu_hash = nullptr;

    // Extract tables
    for (ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_SYMTAB) symtab = reinterpret_cast<ElfW(Sym)*>(base + d->d_un.d_ptr);
        if (d->d_tag == DT_STRTAB) strtab = reinterpret_cast<const char*>(base + d->d_un.d_ptr);
        if (d->d_tag == DT_GNU_HASH) gnu_hash = reinterpret_cast<uint32_t*>(base + d->d_un.d_ptr);
    }

    // Android libraries rely on GNU_HASH
    if (symtab && strtab && gnu_hash) {
        uint32_t nbuckets = gnu_hash[0];
        uint32_t symoffset = gnu_hash[1];
        uint32_t bloom_size = gnu_hash[2];

        const ElfW(Addr)* bloom_filter = reinterpret_cast<const ElfW(Addr)*>(&gnu_hash[4]);
        const uint32_t* buckets = reinterpret_cast<const uint32_t*>(&bloom_filter[bloom_size]);
        const uint32_t* chains = &buckets[nbuckets];

        uint32_t hash = calc_gnu_hash(search->sym_name);
        uint32_t bucket = hash % nbuckets;
        uint32_t sym_idx = buckets[bucket];

        // Walk the hash chain
        if (sym_idx >= symoffset) {
            do {
                const ElfW(Sym)& sym = symtab[sym_idx];
                if (((chains[sym_idx - symoffset] ^ hash) >> 1) == 0 && sym.st_shndx != SHN_UNDEF) {
                    if (strcmp(strtab + sym.st_name, search->sym_name) == 0) {
                        // Symbol found! Apply PAC stripping if necessary depending on your environment, 
                        // though for JNI calls it's usually safe as-is.
                        search->result = reinterpret_cast<void*>(base + sym.st_value);
                        return 1; // Stop iterating
                    }
                }
                sym_idx++;
            } while ((chains[sym_idx - 1 - symoffset] & 1) == 0);
        }
    }
    return 0; // Continue just in case
}

// Drops dlopen/dlclose and extracts the symbol purely from mapped memory
void* resolve_symbol(const char* lib_name, const char* sym_name) {
    SymData search = {lib_name, sym_name, nullptr};
    dl_iterate_phdr(sym_cb, &search);
    return search.result;
}
