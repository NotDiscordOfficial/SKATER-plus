    .syntax unified
    .thumb
    .thumb_func
    .global p384_hook_thumb
    .type p384_hook_thumb, %function
p384_hook_thumb:
    /* Called instead of the stock X509_get_pubkey BL in the actual
       certificate-signature loop at CRO relative 0x1e4b8. r4->cert is
       the subject, r5->cert is its issuer. */
    push {r4, r5, r6, lr}
    mov r6, r0
    ldr r0, [r4]
    ldr r1, [r5]
    ldr r3, =p384_verify_pair
    blx r3
    cmp r0, #0
    beq 1f
    pop {r4, r5, r6}
    add sp, #4
    ldr r3, =stock_signature_verified_thumb
    bx r3
1:
    mov r0, r6
    ldr r3, =stock_X509_get_pubkey_thumb
    blx r3
    pop {r4, r5, r6, pc}
    .size p384_hook_thumb, . - p384_hook_thumb

    .align 2
    .thumb_func
    .global browser_crypto_malloc
    .type browser_crypto_malloc, %function
browser_crypto_malloc:
    ldr r3, =stock_crypto_malloc_thumb
    bx r3
    .size browser_crypto_malloc, . - browser_crypto_malloc

    .align 2
    .thumb_func
    .global browser_crypto_free
    .type browser_crypto_free, %function
browser_crypto_free:
    ldr r3, =stock_crypto_free_thumb
    bx r3
    .size browser_crypto_free, . - browser_crypto_free

    .align 2
    .thumb_func
    .global ec_cert_type_hook
    .type ec_cert_type_hook, %function
ec_cert_type_hook:
    /* Replace CMP/BEQ at ssl_cert_type+0x18, preserving GOST and all
       other existing branches. EC (NID 408) maps to SSL_PKEY_ECC (5). */
    ldr r3, =408
    cmp r0, r3
    bne 1f
    movs r4, #5
    ldr r3, =stock_cert_type_done_thumb
    bx r3
1:
    cmp r0, r1
    bne 2f
    ldr r3, =stock_cert_type_gost94_thumb
    bx r3
2:
    bx lr
    .size ec_cert_type_hook, . - ec_cert_type_hook

