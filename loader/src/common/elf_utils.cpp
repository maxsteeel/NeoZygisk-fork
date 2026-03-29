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
        ElfW(Addr) end;
        if (__builtin_add_overflow(out_phdr[i].p_vaddr, out_phdr[i].p_memsz, &end)) return false;
        if (end > hi) hi = end;
    }

    if (hi <= lo) return false;
    *out_min_vaddr = (ElfW(Addr))page_start((uintptr_t)lo, page_size);
    *out_map_size = (size_t)(page_end((uintptr_t)hi, page_size) - *out_min_vaddr);
    return true;
}

bool vaddr_to_offset(const std::vector<ElfW(Phdr)>& phdr, ElfW(Addr) vaddr, off_t *out_off) {
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

bool elf_load_dyn_info(int fd, [[maybe_unused]] const ElfW(Ehdr) *eh, const std::vector<ElfW(Phdr)>& phdr, elf_dyn_info *out) {
    const ElfW(Phdr) *dyn_phdr = nullptr;
    for (const auto& p : phdr) { if (p.p_type == PT_DYNAMIC) { dyn_phdr = &p; break; } }
    if (!dyn_phdr || dyn_phdr->p_filesz == 0) return false;

    out->dyn_off = (off_t)dyn_phdr->p_offset;

    for (const auto& p : phdr) {
        if (p.p_type == PT_GNU_EH_FRAME) {
            out->eh_frame_hdr_vaddr = p.p_vaddr;
            out->eh_frame_hdr_sz = p.p_memsz;
        } else if (p.p_type == PT_GNU_RELRO) {
            out->relro_vaddr = p.p_vaddr;
            out->relro_sz = p.p_memsz;
        } else if (p.p_type == PT_TLS) {
            out->tls_segment_vaddr = p.p_vaddr;
            out->tls_segment_memsz = p.p_memsz;
            out->tls_segment_filesz = p.p_filesz;
            out->tls_segment_align = p.p_align;
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
                out->gnu_symndx = header[1];
                uint32_t bloom_size = header[2];
                out->gnu_shift2 = header[3];

                off_t bloom_off = gnu_hash_off + 16;
                off_t buckets_off = bloom_off + (off_t)(bloom_size * sizeof(ElfW(Addr)));
                off_t chains_off = buckets_off + (off_t)(nbuckets * 4);

                uint32_t max_bucket = 0;
                bool max_bucket_found = false;

                // Safety check for large nbuckets
                if (nbuckets <= 1024 * 1024) {
                    out->gnu_buckets.resize(nbuckets);
                    if (read_loop_offset(fd, out->gnu_buckets.data(), nbuckets * sizeof(uint32_t), buckets_off)) {
                        for (uint32_t b = 0; b < nbuckets; b++) {
                            if (out->gnu_buckets[b] > max_bucket) max_bucket = out->gnu_buckets[b];
                        }
                        max_bucket_found = true;
                    }
                } else {
                    for (uint32_t b = 0; b < nbuckets; b++) {
                        uint32_t val;
                        if (!read_loop_offset(fd, &val, sizeof(val), buckets_off + (off_t)(b * 4))) break;
                        if (val > max_bucket) max_bucket = val;
                    }
                    max_bucket_found = true;
                }

                if (max_bucket_found) {
                    if (max_bucket >= out->gnu_symndx) {
                        uint32_t chain_idx = max_bucket - out->gnu_symndx;
                        uint32_t chain_val;
                        while (read_loop_offset(fd, &chain_val, sizeof(chain_val), chains_off + (off_t)(chain_idx * 4))) {
                            if (chain_val & 1) { out->nsyms = max_bucket + 1; break; }
                            max_bucket++; chain_idx++;
                        }
                        if (!out->nsyms) out->nsyms = max_bucket + 1;
                    } else {
                        out->nsyms = out->gnu_symndx;
                    }

                    out->gnu_bloom_filter.resize(bloom_size);
                    read_loop_offset(fd, out->gnu_bloom_filter.data(), bloom_size * sizeof(ElfW(Addr)), bloom_off);

                    if (out->nsyms > out->gnu_symndx) {
                        uint32_t num_chains = out->nsyms - out->gnu_symndx;
                        out->gnu_chains.resize(num_chains);
                        read_loop_offset(fd, out->gnu_chains.data(), num_chains * sizeof(uint32_t), chains_off);
                    }
                }
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

static uint32_t calc_gnu_hash(const char *name) {
    uint32_t h = 5381;
    for (unsigned char c = *name; c != '\0'; c = *++name) {
        h = (h << 5) + h + c;
    }
    return h;
}

bool find_dynsym_value(const elf_dyn_info *info, const char *sym_name, ElfW(Addr) *out_value, uint8_t *out_type) {
    if (!info->gnu_buckets.empty() && !info->gnu_bloom_filter.empty()) {
        uint32_t hash = calc_gnu_hash(sym_name);
        uint32_t h2 = hash >> info->gnu_shift2;
        uint32_t word_num = (hash / (sizeof(ElfW(Addr)) * 8)) & (info->gnu_bloom_filter.size() - 1);

        ElfW(Addr) mask = (((ElfW(Addr))1) << (hash % (sizeof(ElfW(Addr)) * 8))) |
                          (((ElfW(Addr))1) << (h2 % (sizeof(ElfW(Addr)) * 8)));

        if ((info->gnu_bloom_filter[word_num] & mask) == mask) {
            uint32_t sym_idx = info->gnu_buckets[hash % info->gnu_buckets.size()];
            if (sym_idx >= info->gnu_symndx) {
                uint32_t chain_idx = sym_idx - info->gnu_symndx;

                while (chain_idx < info->gnu_chains.size()) {
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
