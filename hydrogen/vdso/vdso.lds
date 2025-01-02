ENTRY(_start)

PHDRS {
    text    PT_LOAD    FLAGS(5);
    rodata  PT_LOAD    FLAGS(4);
    data    PT_LOAD    FLAGS(6);
    dynamic PT_DYNAMIC FLAGS(6);
}

SECTIONS {
    . = 0;
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

    vdso_info = .;

    /DISCARD/ : { *(.eh_frame* .note*) }
}
