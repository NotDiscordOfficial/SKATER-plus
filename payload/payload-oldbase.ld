ENTRY(payload_ecdh)

SECTIONS {
    /* Original link address used before rebasing into expanded oss.cro text. */
    . = 0x16efd8;
    .text : {
        KEEP(*(.text.ecdhe_get_hook))
        KEEP(*(.text.ecdhe_send_hook))
        *(.text.payload_ecdh)
        *(.text*)
    }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : {
        *(.bss*)
        *(COMMON)
    }
    /DISCARD/ : {
        *(.comment*)
        *(.ARM.attributes*)
        *(.note*)
    }
}
