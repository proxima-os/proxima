#ifndef PROXIMA_ELF_H
#define PROXIMA_ELF_H

#include <stdint.h>

typedef struct {
    uint8_t ident[16];
    uint16_t image_type;
    uint16_t machine;
    uint32_t version;
    uintptr_t entry;
    uintptr_t phoff;
    uintptr_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
} __attribute__((packed)) elf_header_t;

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define ELFCLASS64 2
#define ELFDATA2LSB 1

#define ET_EXEC 2
#define ET_DYN 3

#define EM_NATIVE 62
#define EV_CURRENT 1

typedef struct {
    uint32_t kind;
    uint32_t flags;
    uintptr_t offset;
    uintptr_t vaddr;
    uintptr_t paddr;
    uintptr_t filesz;
    uintptr_t memsz;
    uintptr_t align;
} __attribute__((packed)) elf_segment_t;

#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_PHDR 6

#define PF_X 1
#define PF_W 2
#define PF_R 4

typedef struct {
    int a_type;
    union {
        long a_val;
        void *a_ptr;
        void (*a_fnc)();
    };
} __attribute__((aligned(1))) elf_auxv_t;

#define AT_NULL 0
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_BASE 7
#define AT_ENTRY 9
#define AT_SYSINFO_EHDR 33

typedef struct {
    long tag;
    union {
        unsigned long val;
        void *ptr;
    };
} __attribute__((packed)) elf_dynamic_t;

#define DT_NULL 0
#define DT_PLTRELSZ 2
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_RELA 7
#define DT_RELASZ 8
#define DT_RELAENT 9
#define DT_JMPREL 23

#define DT_X86_64_PLT 0x70000000
#define DT_X86_64_PLTSZ 0x70000001
#define DT_X86_64_PLTENT 0x70000003

typedef struct {
    void *offset;
    unsigned long info;
    long addend;
} __attribute__((packed)) elf_rela_t;

#define ELF_R_SYM(i) ((i) >> 32)
#define ELF_R_TYPE(i) ((i) & 0xffffffffL)

#define R_X86_64_NONE 0
#define R_X86_64_64 1
#define R_X86_64_COPY 5
#define R_X86_64_GLOB_DAT 6
#define R_X86_64_JUMP_SLOT 7
#define R_X86_64_RELATIVE 8
#define R_X86_64_IRELATIVE 37

typedef struct {
    uint32_t name;
    unsigned char info;
    unsigned char other;
    uint16_t shndx;
    void *value;
    uint64_t size;
} __attribute__((packed)) elf_sym_t;

#define STN_UNDEF 0

#endif // PROXIMA_ELF_H
