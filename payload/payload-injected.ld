ENTRY(payload_ecdh)

SECTIONS {
    /* Unused rodata cave at file 0x16F158, expressed relative to seg0. */
    . = 0x145950;
    .text : {
        KEEP(*(.text.ecdhe_get_hook))
        KEEP(*(.text.ecdhe_send_hook))
        *(.text.payload_ecdh)
        *(.text*)
    }
    .rodata : {
        *(.rodata*)
    }
    .data : {
        *(.data*)
    }
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
