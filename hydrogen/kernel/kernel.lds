ENTRY(_entry)
OUTPUT_ARCH(i386:x86-64)
OUTPUT_FORMAT(elf64-x86-64)

PHDRS {
    rodata PT_LOAD FLAGS(4);
    text   PT_LOAD FLAGS(5);
    data   PT_LOAD FLAGS(6);
}

SECTIONS {
    . = 0xffffffff80000000;
    _start = .;

    .rodata : {
        KEEP(*(SORT_BY_NAME(.requests*)))
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .vdso : {
        __vdso_start = .;
        KEEP(*(.vdso))
        . = ALIGN(CONSTANT(MAXPAGESIZE));
        __vdso_end = .;
    }

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    _erodata = .;
    .text : { *(.text .text.*) } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    _etext = .;
    .data : { *(.data .data.*) } :data
    .bss : {
        *(.bss .bss.*)
        . = ALIGN(CONSTANT(MAXPAGESIZE));
        vdso_info = .;
        . += CONSTANT(MAXPAGESIZE);
    } :data

    _end = .;

    /DISCARD/ : { *(.eh_frame* .note*) }
}
