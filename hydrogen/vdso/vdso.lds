ENTRY(_start)

PHDRS {
    text    PT_LOAD FILEHDR PHDRS FLAGS(5);
    dynamic PT_DYNAMIC FLAGS(4);
}

SECTIONS {
    /*. = 0;
    .text   : { *(.text .text.*) } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .dynsym : { *(.dynsym) } :rodata
    .dynstr : { *(.dynstr) } :rodata
    .hash : { *(.hash) } :rodata
    .gnu.hash : { *(.gnu.hash) } :rodata
    .rela : { *(.rela .rela.*) } :rodata
    .rodata : { *(.rodata .rodata.*) } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .data    : { *(.data .data.*) } :data
    .dynamic : { *(.dynamic) } :data :dynamic
    .bss : {
        *(.bss .bss.*)
        . = ALIGN(CONSTANT(MAXPAGESIZE));
    } :data

    vdso_info = .;*/
    vdso_info = . - CONSTANT(MAXPAGESIZE);

    . = SIZEOF_HEADERS;
    .hash          : { *(.hash) } :text
    .gnu.hash      : { *(.gnu.hash) }
    .dynsym        : { *(.dynsym) }
    .dynstr        : { *(.dynstr) }
    .gnu.version   : { *(.gnu.version) }
    .gnu.version_d : { *(.gnu.version_d) }
    .gnu.version_r : { *(.gnu.version_r) }
    .dynamic       : { *(.dynamic) } :text :dynamic
    .rodata        : { *(.rodata .rodata.*) } :text
    .rela          : { *(.rela .rela.*) }
    .text          : { *(.text .text.*) }
    .data          : { *(.bss .bss.* .data .data.* .got .got.*) }

    ASSERT(SIZEOF(.data) == 0, "vdso contains writable data section")
    ASSERT(SIZEOF(.rela) == 0, "vdso contains relocations")

    /DISCARD/ : { *(.eh_frame* .note*) }
}
