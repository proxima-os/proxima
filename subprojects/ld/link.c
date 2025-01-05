#include "link.h"
#include "proxima/compiler.h"
#include "proxima/elf.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

HIDDEN const void *vdso_image;
static const void *vdso_strtab;
static const elf_sym_t *vdso_symtab;
static const uint32_t *vdso_buckets;
static const uint32_t *vdso_chains;
static uint32_t vdso_nbuckets;
static uint32_t vdso_nchains;

extern elf_dynamic_t _DYNAMIC[];

HIDDEN void setup_vdso(void) {
    const elf_header_t *header = vdso_image;
    const elf_dynamic_t *vdso_dynamic = NULL;

    for (int i = 0; i < header->phnum; i++) {
        const elf_segment_t *segment = vdso_image + header->phoff + (uint64_t)i * header->phentsize;

        if (segment->kind == PT_DYNAMIC) {
            vdso_dynamic = vdso_image + segment->offset;
            break;
        }
    }

    const uint32_t *vdso_hash = NULL;

    for (const elf_dynamic_t *cur = vdso_dynamic; cur->tag != DT_NULL; cur++) {
        switch (cur->tag) {
        case DT_STRTAB: vdso_strtab = vdso_image + cur->val; break;
        case DT_SYMTAB: vdso_symtab = vdso_image + cur->val; break;
        case DT_HASH: vdso_hash = vdso_image + cur->val; break;
        }
    }

    vdso_nbuckets = vdso_hash[0];
    vdso_nchains = vdso_hash[1];
    vdso_buckets = &vdso_hash[2];
    vdso_chains = &vdso_hash[2 + vdso_nbuckets];
}

static uint32_t elf_hash(const unsigned char *name) {
    uint32_t hash = 0;

    while (*name) {
        hash = (hash << 4) + *name++;

        uint32_t top = hash & 0xf0000000;
        if (top) hash ^= top >> 24;
        hash &= ~top;
    }

    return hash;
}

static const elf_sym_t *get_vdso_symbol(const void *name) {
    uint32_t hash = elf_hash(name);
    uint32_t index = vdso_buckets[hash % vdso_nbuckets];

    while (index != STN_UNDEF) {
        const elf_sym_t *sym = &vdso_symtab[index];

        if (strcmp(vdso_strtab + sym->name, name) == 0) {
            return sym;
        }

        index = vdso_chains[index];
    }

    return NULL;
}

typedef struct {
    uintptr_t base;
    const void *strtab;
    const elf_sym_t *symtab;
} relocation_ctx_t;

static void process_relocations(relocation_ctx_t *ctx, const void *table, size_t entsize, size_t size, uintptr_t base) {
    for (size_t i = 0; i < size; i += entsize) {
        const elf_rela_t *cur = table + i;

        unsigned sym_idx = ELF_R_SYM(cur->info);
        unsigned type = ELF_R_TYPE(cur->info);

        uintptr_t addend = cur->addend;
        uintptr_t addr = (uintptr_t)cur->offset + base;
        uintptr_t symbol;

        if (sym_idx != STN_UNDEF) {
            symbol = (uintptr_t)vdso_image + (uintptr_t)get_vdso_symbol(ctx->strtab + ctx->symtab[sym_idx].name)->value;
        } else {
            symbol = 0;
        }

        switch (type) {
        case R_X86_64_NONE:
        case R_X86_64_COPY: break;
        case R_X86_64_64: *(uint64_t *)addr = symbol + addend; break;
        case R_X86_64_GLOB_DAT: *(uint64_t *)addr = symbol; break;
        case R_X86_64_JUMP_SLOT: *(uint64_t *)addr = symbol; break;
        case R_X86_64_RELATIVE: *(uint64_t *)addr = base + addend; break;
        default: __builtin_trap();
        }
    }
}

HIDDEN void link_self(uintptr_t base) {
    relocation_ctx_t ctx = {.base = base};

    const void *rela = NULL;
    size_t relasz = 0;
    size_t relaent = 0;
    size_t pltrelsz;
    const void *jmprel = NULL;

    for (elf_dynamic_t *cur = _DYNAMIC; cur->tag != DT_NULL; cur++) {
        switch (cur->tag) {
        case DT_RELA: rela = cur->ptr + base; break;
        case DT_RELASZ: relasz = cur->val; break;
        case DT_RELAENT: relasz = cur->val; break;
        case DT_STRTAB: ctx.strtab = cur->ptr + base; break;
        case DT_SYMTAB: ctx.symtab = cur->ptr + base; break;
        case DT_PLTRELSZ: pltrelsz = cur->val; break;
        case DT_JMPREL: jmprel = cur->ptr + base; break;
        }
    }

    if (rela) process_relocations(&ctx, rela, relaent, relasz, base);
    if (jmprel) process_relocations(&ctx, jmprel, sizeof(elf_rela_t), pltrelsz, base);
}
