.syntax unified
.cpu mpcore
.thumb

/* Segment-relative Thumb entry points in the original oss.cro. */
.thumb_set orig_get_rsa,       0x000BBD79
.thumb_set orig_get_next,      0x000BBDDB
.thumb_set orig_get_bad,       0x000BBCCD
.thumb_set orig_get_signature, 0x000BC04D
.thumb_set orig_send_rsa,      0x000BDC55
.thumb_set orig_send_next,     0x000BDD15
.thumb_set orig_send_finish,   0x000BE109
.thumb_set orig_send_fail,     0x000BE0DB

.thumb_set fn_DH_new,          0x000ABD5D
.thumb_set fn_DH_free,         0x000ABCC9
.thumb_set fn_BN_bin2bn,       0x000BA0AB
.thumb_set fn_BN_num_bits,     0x000BA15B
.thumb_set fn_BN_bn2bin,       0x000BA071
.thumb_set fn_X509_get_pubkey, 0x000B9B69
.thumb_set fn_RAND_bytes,      0x000B8CDD

.extern payload_ecdh

/*
 * Hooked at file 0xBBEF6 (segment offset 0xBBD76), after the stock function
 * has cleaned old temporary keys and populated these locals:
 *   sp+0x14 p, sp+0x24 algorithm_mkey, sp+0x48 param,
 *   sp+0x4c algorithm_auth; r4=n, r5=SSL*, r6=&s->session.
 */
.section .text.ecdhe_get_hook, "ax", %progbits
.align 2
.global ecdhe_get_hook
.type ecdhe_get_hook, %function
.thumb_func
ecdhe_get_hook:
    ldr     r0, [sp, #0x24]
    cmp     r0, #0x80
    beq     1f

    /* Reproduce the overwritten SSL_kRSA test. */
    lsls    r2, r0, #23
    bmi     90f
    bl      orig_get_next
90:
    bl      orig_get_rsa

1:  /* Only named secp256r1 with an uncompressed 65-byte point. */
    cmp     r4, #69
    blo     89f
    ldr     r0, [sp, #0x14]
    ldrb    r1, [r0, #0]
    cmp     r1, #3
    bne     89f
    ldrb    r1, [r0, #1]
    cmp     r1, #0
    bne     89f
    ldrb    r1, [r0, #2]
    cmp     r1, #0x17
    bne     89f
    ldrb    r1, [r0, #3]
    cmp     r1, #65
    bne     89f
    ldrb    r1, [r0, #4]
    cmp     r1, #4
    bne     89f

    /* A real DH object gives us lifecycle-safe storage in peer_dh_tmp. */
    bl      fn_DH_new
    cmp     r0, #0
    beq     89f
    mov     r7, r0

    ldr     r0, [sp, #0x14]
    adds    r0, #5
    movs    r1, #64
    movs    r2, #0
    bl      fn_BN_bin2bn
    cmp     r0, #0
    beq     88f
    str     r0, [r7, #0x14]       /* DH.pub_key */

    ldr     r1, [r6]              /* session */
    adds    r1, #0x80
    ldr     r1, [r1, #0x18]       /* sess_cert */
    str     r7, [r1, #0x70]       /* peer_dh_tmp */
    ldr     r0, [r1, #0x0c]       /* RSA certificate */
    bl      fn_X509_get_pubkey
    cmp     r0, #0
    beq     87f
    str     r0, [sp, #8]          /* pkey for stock signature verifier */

    movs    r0, #69
    str     r0, [sp, #0x20]       /* param_len */
    ldr     r1, [sp, #0x14]
    adds    r1, #69
    str     r1, [sp, #0x14]       /* p now points at signature algorithm */
    subs    r4, #69               /* n excludes ECDHE parameters */
    bl      orig_get_signature

87: /* Detach and release our valid DH object on setup failure. */
    ldr     r1, [r6]
    adds    r1, #0x80
    ldr     r1, [r1, #0x18]
    movs    r0, #0
    str     r0, [r1, #0x70]
88:
    mov     r0, r7
    bl      fn_DH_free
89:
    bl      orig_get_bad
.size ecdhe_get_hook, . - ecdhe_get_hook


/*
 * Hooked at file 0xBDDCE (segment offset 0xBDC4E). The stock function has
 * already prepared its 0x2b4-byte frame and output pointers. r0=alg_k,
 * r5=SSL*, r6=&s->session.
 */
.section .text.ecdhe_send_hook, "ax", %progbits
.align 2
.global ecdhe_send_hook
.type ecdhe_send_hook, %function
.thumb_func
ecdhe_send_hook:
    cmp     r0, #0x80
    beq     1f

    /* Reproduce the overwritten SSL_kRSA test. */
    lsls    r1, r0, #31
    cmp     r1, #0
    bne     90f
    bl      orig_send_next
90:
    bl      orig_send_rsa

1:  /* Fetch the server point saved as peer_dh_tmp->pub_key. */
    ldr     r0, [r6]
    adds    r0, #0x80
    ldr     r0, [r0, #0x18]       /* sess_cert */
    ldr     r4, [r0, #0x70]       /* peer_dh_tmp */
    cmp     r4, #0
    beq     89f
    ldr     r7, [r4, #0x14]       /* pub_key BIGNUM */
    cmp     r7, #0
    beq     89f

    /* sp+0x180: zero-padded 64-byte server X||Y. */
    mov     r3, sp
    adds    r3, #0xff
    adds    r3, #0x81
    movs    r0, #0
    movs    r1, #16
2:
    str     r0, [r3]
    adds    r3, #4
    subs    r1, #1
    bne     2b
    mov     r0, r7
    bl      fn_BN_num_bits
    adds    r0, #7
    lsrs    r0, r0, #3
    cmp     r0, #64
    bhi     89f
    movs    r1, #64
    subs    r1, r1, r0
    mov     r0, r7
    mov     r2, sp
    adds    r2, #0xff
    adds    r2, #0x81
    adds    r1, r2, r1
    bl      fn_BN_bn2bin

    /* Generate a valid scalar and calculate public point/shared secret. */
3:
    mov     r0, sp
    adds    r0, #0xff
    adds    r0, #1                /* private key: sp+0x100 */
    movs    r1, #32
    bl      fn_RAND_bytes
    cmp     r0, #0
    ble     89f
    mov     r0, sp
    adds    r0, #0xff
    adds    r0, #1
    mov     r1, sp
    adds    r1, #0xff
    adds    r1, #0x81             /* server public: sp+0x180 */
    mov     r2, sp
    adds    r2, #0xff
    adds    r2, #0x21             /* client public: sp+0x120 */
    mov     r3, sp
    adds    r3, #0xff
    adds    r3, #0x61             /* shared secret: sp+0x160 */
    bl      payload_ecdh
    cmp     r0, #0
    beq     3b

    /* Existing method callback derives/stores the TLS master secret. */
    ldr     r0, [r5, #8]
    ldr     r1, [r6]              /* session */
    ldr     r0, [r0, #0x64]
    adds    r1, #0x14
    mov     r2, sp
    adds    r2, #0xff
    adds    r2, #0x61
    movs    r3, #32
    ldr     r7, [r0, #0x0c]
    mov     r0, r5
    blx     r7
    ldr     r1, [r6]
    str     r0, [r1, #0x10]
    cmp     r0, #0
    ble     89f

    /* ClientKeyExchange body: length byte, uncompressed marker, X||Y. */
    mov     r0, sp
    adds    r0, #0xff
    adds    r0, #0xff
    adds    r0, #0x92
    ldr     r0, [r0]
    movs    r1, #65
    strb    r1, [r0, #0]
    movs    r1, #4
    strb    r1, [r0, #1]
    adds    r0, #2
    mov     r1, sp
    adds    r1, #0xff
    adds    r1, #0x21
    movs    r2, #16
4:
    ldr     r3, [r1]
    str     r3, [r0]
    adds    r1, #4
    adds    r0, #4
    subs    r2, #1
    bne     4b

    /* Detach before DH_free so later cleanup cannot see a stale pointer. */
    ldr     r0, [r6]
    adds    r0, #0x80
    ldr     r0, [r0, #0x18]
    movs    r1, #0
    str     r1, [r0, #0x70]
    mov     r0, r4
    bl      fn_DH_free

    movs    r4, #66
    bl      orig_send_finish

89:
    movs    r0, #0
    mvns    r0, r0               /* return -1 through stock epilogue */
    bl      orig_send_fail
.size ecdhe_send_hook, . - ecdhe_send_hook


