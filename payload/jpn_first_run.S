.syntax unified
.cpu arm1176jzf-s
.thumb

/*
 * SKATER revision 10178 Japanese first-run response compatibility.
 *
 * The official endpoint now sends a chunked response. Its HTTPC content-size
 * output is zero, while the download-size output contains the received byte
 * count. Use the existing bounded 4096-byte path and accept success only when
 * the official response contains "regist_ok".
 */
.section .zero_length, "ax", %progbits
.thumb_func
.global zero_length
zero_length:
    movs    r6, #1
    lsls    r6, r6, #12
    b       0x00166d3c
    nop
    nop

.section .hook_response, "ax", %progbits
.thumb_func
.global hook_response
hook_response:
    b       response_token_check
    nop

.section .response_payload, "ax", %progbits
.align 2
.thumb_func
.global response_token_check
response_token_check:
    add     r0, sp, #0x18
    add     r1, sp, #0x14
    add     r2, sp, #0x10
    blx     0x00306480
    cmp     r0, #0
    blt     2f
    ldr     r1, [sp, #0x38]
    ldr     r2, [sp, #0x14]
    cmp     r1, #0
    beq     2f
    cmp     r2, #9
    blo     2f
    movs    r3, #1
    lsls    r3, r3, #12
    cmp     r2, r3
    bhi     2f
    subs    r2, #8
    adds    r2, r2, r1
1:
    ldr     r3, [r1]
    ldr     r0, =0x69676572
    cmp     r3, r0
    bne     3f
    ldr     r3, [r1, #4]
    ldr     r0, =0x6f5f7473
    cmp     r3, r0
    bne     3f
    ldrb    r3, [r1, #8]
    cmp     r3, #'k'
    beq     4f
3:
    adds    r1, #1
    cmp     r1, r2
    blo     1b
2:
    movs    r0, #0
    b       0x00166e0a
4:
    movs    r0, #1
    b       0x00166e0a

.ltorg
