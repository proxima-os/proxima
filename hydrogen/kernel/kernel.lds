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

    . = ALIGN(4K);
    _erodata = .;
    .text : { *(.text .text.*) } :text

    . = ALIGN(4K);
    _etext = .;
    .data : { *(.data .data.*) } :data
    .bss : { *(.bss .bss.*) } :data

    . = ALIGN(4K);
    _end = .;

    /DISCARD/ : { *(.eh_frame* .note*) }
}
