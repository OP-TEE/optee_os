/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
    .syntax unified
    .thumb
    .section .text
    .align   2

    .global __mpa_full_adder
    .global __mpa_full_sub
    .global __mpa_full_adder_ackum
    .global __mpa_div_dword
    .global __mpa_mul_add_word
    .global __mpa_mul_add_word_cum
    .global __mpa_montgomery_mul_add
    .global __mpa_montgomery_sub_ack

@  --------------------------------------------------------------------
@  Function:   __mpa_full_adder
@
@  A word_t sized full adder. Incoming carry is in *carry.
@  The sum will be put in *sum and the
@  outgoing carry will be returned in *carry
@
@  void  __mpa_full_adder( mpa_word_t  a,
@                          mpa_word_t  b,
@                          mpa_word_t* sum,
@                          mpa_word_t* carry)
@
    .thumb_func
    .type __mpa_full_adder, %function
__mpa_full_adder:
    push        {r9}
    ldr         r9, [r3]        @ r9 holds incoming carry
    adds        r1, r1, r0      @ r1 holds b + a
    mov         r12, #0         @
    adc         r0, r12, #0     @ r0 holds carry of a + b
    adds        r1, r1, r9      @ r1 holds a + b + incoming carry
    str         r1, [r2]        @ *sum <- r1
    adc         r0, r0, #0      @ r0 holds acc carry
    str         r0, [r3]        @ *carry <- r0
    pop         {r9}
    bx          lr

@  --------------------------------------------------------------------
@  Function:   __mpa_full_sub
@
@   A word_t sized full subtraction function. Incoming carry is in *carry
@   The difference will be put in *diff and the outgoing carry will be returned
@   in *carry
@
@   void __mpa_full_sub(mpa_word_t  a,
@                       mpa_word_t  b,
@                       mpa_word_t* diff,
@                       mpa_word_t* carry);
@
    .thumb_func
    .type __mpa_full_sub, %function
__mpa_full_sub:
    push        {r9}
    ldr         r9, [r3]        @ r9 holds incomming carry
    subs        r1, r0, r1      @ r1 holds a - b
    mov         r12, #0
    sbc         r0, r12, #0     @ r0 holds carry
    subs        r1, r1, r9      @ r1 holds a - b - carry
    str         r1, [r2]        @ *diff <- r1
    sbc         r0, r0, #0      @ r0 <- r0 - carry
    rsbs        r0, r0, #0      @ r0 <- 0 - r0 outgoing carry
    str         r0, [r3]        @ *carry <- r0
    pop         {r9}
    bx          lr

@  --------------------------------------------------------------------
@  Function:   __mpa_full_adder_ackum
@
@  A word_t sized full adder with ackumulate. *d  = *d + e + *carry
@  Outgoing carry is in *carry
@
@ void __mpa_full_adder_ackum(  mpa_word_t*    d,
@                               mpa_word_t     e,
@                               mpa_word_t*    carry)
@
    .thumb_func
    .type __mpa_full_adder_ackum, %function
__mpa_full_adder_ackum:
    push        {r9}
    ldr         r12, [r0]       @ r12 <- *d
    mov         r9, #0          @
    ldr         r3, [r2]        @ r3 holds incoming carry
    adds        r1, r1, r12     @ r1 <- e + *d
    adc         r9, r9, #0      @ r9 <- carry
    adds        r1, r1, r3      @ r1 <- r1 + *carry
    str         r1, [r0]        @ *d <- sum
    adc         r0, r9, #0      @ r0 <- outgoing carry
    str         r0, [r2]        @ *carry <- carry
    pop         {r9}
    bx          lr


@  --------------------------------------------------------------------
@  Function:   __mpa_div_dword
@
@   Wrapper for the soft div. Calculates quotient and remainder of
@   ((x1 << WORD_SIZE) + x0 ) / y
@
@   mpa_word_t __mpa_div_dword(mpa_word_t x0,
@                              mpa_word_t x1,
@                              mpa_word_t y,
@                              mpa_word_t* rem)
@
@   returns the quotient in r0 and the remainder in *rem
@
@   At entrace
@   r0  low32  of num
@   r1  high32 of num
@   r2  y (becomes high32 of den)
@   r3  addr of rem
    .thumb_func
    .type __mpa_div_dword, %function
__mpa_div_dword:
    push    {r4, r5, r6, r7, r8, r9, lr}@

    mov     r12, #0                 @ r12 holds low32 of den
                                    @ r2 holds high32 of den
    mov     lr, #1                  @ lr holds high32 of qbit
    movs    r4, #0                  @ r4 holds low32 of qbit
    cmp     r2, #-1                 @ if den >= 0
    bgt     normalize               @ branch to normalize
    mov     r9, #0                  @ r9 holds low of quot
    mov     r8, #0                  @ r8 holds high of quot

soft_div_main:
    cmp     r12, r0                 @ cmp low(den) low(num)
    mov     r6, #0                  @
    it      hi                      @
    movhi   r6, #1                  @ r6 is 1 if low(den) > low(num)
    cmp     r2, r1                  @ cmp high(den) high(num)
    mov     r5, #0                  @
    it      hi                      @
    movhi   r5, #1                  @ r5 if 1 if high(den) > high(num)
    it      eq                      @
    moveq   r5, r6                  @ if high is equal let low decide
    cbnz    r5, shift_right         @ if r5 == 1 branch

    adds    r9, r9, r4              @ quot += qbit
    adc     r8, r8, lr              @
    subs    r0, r0, r12             @ num -= den
    sbcs    r1, r2                  @

shift_right:
@
@ These right shifts should be done as
@
@ lsrs  r2, r2, #1              @ right shift den >>= 1
@ rrx   r12, r12
@ lsrs  lr, lr, #1              @ right shift qbit >>= 1
@ rrx   r4, r4
@
@ but due to a compiler error in the STE toolchain (2012-05-03)
@ we must implement this as:

    and     r7, r2, #1
    mov     r2, r2, lsr #1
    mov     r7, r7, lsl #31
    mov     r12, r12, lsr #1
    orr     r12, r12, r7

    and     r7, lr, #1
    mov     lr, lr, lsr #1
    mov     r7, r7, lsl #31
    mov     r4, r4, lsr #1
    orr     r4, r4, r7

@
@ end of compiler bug fix
@
    orrs    r5, r4, lr              @ while qbit != 0
    bne     soft_div_main           @ do mainloop

store_and_exit:
    cmp     r3, #0                  @ if (r != NULL)
    it      ne                      @
    strne   r0, [r3]                @ store remainder into *r
    mov     r0, r9                  @
    pop     {r4, r5, r6, r7, r8, r9, pc}@ clean up and exit

normalize:
    adds    r4, r4, r4              @ qbit <<= 1
    adc     lr, lr, lr              @
    adds    r12, r12, r12           @ den <<= 1
    adcs    r2, r2                  @
    cmp     r2, #-1                 @ while den >= 0
    bgt     normalize               @ do normalize

    mov     r9, #0                  @
    orrs    r6, r4, lr              @ if qbit == 0
    beq     store_and_exit          @ done, branch to store r and exit

    mov     r8, r9                  @ set quot = 0 (r9 = 0 r8 = 0)
    b       soft_div_main           @ and branch to main loop


@  --------------------------------------------------------------------
@  Function:   __mpa_mul_add_word
@
@  Multiplies a and b and adds the incoming carry tp produce the product.
@  Outgoing carry is stored in *carry
@
@   void __mpa_mul_add_word(mpa_word_t a,
@                           mpa_word_t b,
@                           mpa_word_t* p,
@                           mpa_word_t* carry)
@
@
    .thumb_func
    .type __mpa_mul_add_word, %function
__mpa_mul_add_word:
    push    {r9}
    umull   r1, r9, r1, r0      @ r1, r9 <- a * b
    ldr     r0, [r3]            @ r0 <- incoming carry
    adds    r1, r1, r0          @ add incoming carry to product
    str     r1, [r2]            @ store low32 of product
    adc     r0, r9, #0          @ add carry to high32
    str     r0, [r3]            @ store outgoing carry
    pop     {r9}
    bx      lr

@  --------------------------------------------------------------------
@  Function:   __mpa_mul_add_word_cum
@
@  Multiplies a and b and adds the incoming carry and the cumulative
@  product.
@  Outgoing carry is stored in *carry
@
@   void __mpa_mul_add_word_cum(mpa_word_t a,
@                               mpa_word_t b,
@                               mpa_word_t* p,
@                               mpa_word_t* carry)
@
@
    .thumb_func
    .type __mpa_mul_add_word_cum, %function
__mpa_mul_add_word_cum:
    push    {r9}
    umull    r12, r9, r1, r0     @ r9, r12 <- a * b
    ldr     r0, [r2]            @ r0 holds incoming product
    ldr     r1, [r3]            @ r1 holds incoming carry
    adds    r0, r0, r12         @ r0 holds incoming product + new low32
    adc     r9, r9, #0          @ add carry to high32
    adds    r0, r0, r1          @ add incoming carry
    str     r0, [r2]            @ store outgoing product
    adc     r0, r9, #0          @ store outgoing carry in r0
    str     r0, [r3]            @ and write to [r3]
    pop    {r9}
    bx      lr


@  --------------------------------------------------------------------
@  Function:  __mpa_montgomery_mul_add
@
@  Calculates dest = dest + src * w
@  Dest must be big enough to hold the result
@
@   void __mpa_montgomery_mul_add(mpanum     dest,
@                                 mpanum     src,
@                                 mpa_word_t w)
@
    .thumb_func
    .type __mpa_montgomery_mul_add, %function
__mpa_montgomery_mul_add:
    push    {r4, r5, r6, r7, lr}
    add     r7, sp, #12
    push    {r8, r9, r10, r11}
    cbz     r2, mm_mul_add_exit     @ if w == 0 return
    ldr     r3, [r1, #4]            @ r3 holds src->size
    add     r9, r0, #8              @ r9 holds &dest->d (dest_begin)
    cmp     r3, #1                  @
    mov     r3, r9                  @ r3 holds &dest->d (ddig)
    blt     mm_mul_add_check_size   @ if src->size == NULL jump
    add     r12, r1, #8             @ r12 holds &src->d
    mov     lr, #0                  @
    movs    r3, #0                  @
    movs    r4, #0                  @ r4 holds carry
    movs    r5, #0                  @ r5 holds inx

mm_main_loop:
    ldr     r6, [r12, r5, lsl #2]   @ r6 holds src->d[idx]
    adds    r3, #4
    ldr     r11, [r9, r5, lsl #2]   @ r11 holds dest->d[idx]
    umull    r10, r8, r6, r2         @ r8, r10 holds src->d[idx] * w
    mla     r8, r6, lr, r8          @ r8 <- r6*0 + r8 ??
    adds    r6, r11, r4             @ r6 <- dest->d[idx] + carry
    adc     r4, lr, #0              @ r4 holds C
    adds    r6, r6, r10             @ r6 holds low32 of result
    str     r6, [r9, r5, lsl #2]    @ store into dest->d[idx]
    add     r5, r5, #1              @ idx++
    ldr     r6, [r1, #4]            @ r6 holds src->size
    adc     r4, r4, r8              @ r4 holds high32 of result
    cmp     r5, r6                  @ while (idx < src->size)
    blt     mm_main_loop            @ do jump

    adds    r1, r0, r3              @
    cmp     r4, #0                  @ check carry
    add     r3, r1, #8              @ r3 holds &dest->d[idx]
    beq     mm_mul_add_check_size   @ jump if no carry
    movs    r1, #0

mm_carry_loop:
    ldr     r2, [r3]                @ r2 holds dest->d[idx]
    adds    r2, r2, r4              @ r2 <- r2 + carry
    str     r2, [r3], #4            @ store at dest->d[idx++]
    adcs    r4, r1, #0              @ r4 holds new C
    bne     mm_carry_loop           @ if r4 != 0 jump

mm_mul_add_check_size:
    sub     r1, r3, r9              @ r1 holds ddig - dest_begin
    ldr     r2, [r0, #4]            @ r2 holds dest->size
    asrs    r1, r1, #2              @ mult by 2 to go from byte addr to word
    cmp     r1, r2                  @
    it      gt                      @
    strgt    r1, [r0, #4]            @ store new size if idx > dest->size

mm_mul_add_exit:
    pop     {r8, r9, r10, r11}
    pop     {r4, r5, r6, r7, pc}


@  --------------------------------------------------------------------
@ Function:  __mpa_montgomery_sub_ack
@  Calculates dest = dest - src
@  Assumption: dest >= src and both non-negative
@  and dest > src.
@
@
@   void __mpa_montgomery_sub_ack(mpanum dest,
@                                 mpanum src)
@
    .thumb_func
    .type __mpa_montgomery_sub_ack, %function
__mpa_montgomery_sub_ack:
    push    {r4, r5, r7, r9, lr}
    ldr     r2, [r1, #4]
    add     r9, r0, #8
    mov     lr, #0
    add     r7, sp, #8
    cmp     r2, #0
    bgt     LBB1_10
    movs    r2, #0
    b       LBB1_6
LBB1_2:
    cbz    r4, LBB1_6
    movs    r1, #0
    LBB1_4:
    add     r5, r0, r2, lsl #2
    adds    r3, #4
    adds    r2, #1
    ldr     r4, [r5, #8]
    subs    r4, r4, r12
    str     r4, [r5, #8]
    sbcs    r5, r1, #0
    rsb     r12, r5, #0
    bne     LBB1_4
    add     r9, r0, r3
LBB1_6:
    ldr     r3, [r0, #4]
    cmp     r2, r3
    blt     LBB1_12
    sub     r1, r9, #4
    subs    r2, r3, #1
LBB1_8:
    adds    r3, r2, #1
    cmp     r3, #1
    blt     LBB1_12
    ldr     r3, [r1]
    cmp     r3, #0
    it      ne
    popne    {r4, r5, r7, r9, pc}
    str     r2, [r0, #4]
    subs    r2, #1
    subs    r1, #4
    b       LBB1_8
LBB1_10:
    movs    r3, #8
    movs    r2, #0
    mov     r12, #0
LBB1_11:
    add     r5, r1, r2, lsl #2
    ldr     r4, [r9]
    adds    r3, #4
    adds    r2, #1
    ldr     r5, [r5, #8]
    subs    r5, r4, r5
    sbc     r4, lr, #0
    subs    r5, r5, r12
    str     r5, [r9], #4
    sbc     r4, r4, #0
    ldr     r5, [r1, #4]
    rsb     r12, r4, #0
    cmp     r2, r5
    blt     LBB1_11
    b       LBB1_2
LBB1_12:
    pop    {r4, r5, r7, r9, pc}


