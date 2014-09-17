/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include "tee_syscall_numbers.h"
#include "tee_trace_levels.h"

.global tee_svc_enter_user_mode
.global tee_svc_sys_return
.global tee_svc_syscall

.set SPSR_T_BIT,        (1 << 5)
.set SPSR_IT_MASK,      0x0600FC00
.set SPSR_IT_MASK1,     0x06000000
.set SPSR_IT_MASK2,     0x0000FC00

.section .text
.balign 4
.code 32

/*
 * Function called from the vector table when a svc exception is received.
 * This function handles entry and exit from a system call.
 */
.func tee_svc_syscall
tee_svc_syscall:
    push    {r4 - r12, lr}
    mov     r8, sp

    /* Restore IRQ which are disabled on exception entry */
    push    {r0-r3}
    blx     thread_restore_irq
    pop     {r0-r3}

    /*
     * Copy eventual arguments passed on the user stack.
     *
     * r5 holds the address of the first word
     * r6 holds the number of words
     *
     * TODO figure out how to avoid stack overflow because of too much data
     * passed on the stack.
     */
    sub     sp, sp, r6, lsl #2
    cmp     r6, #0
    beq     .Lno_args
    push    {r0}
    push    {r1-r3}
    mov     r0, #0
    mov     r2, r5
    add     r1, sp, #(4 * 4)
    mov     r3, r6, lsl #2
    ldr     lr, =tee_svc_copy_from_user
    blx     lr

    /* If copy failed return the error */
    cmp     r0, #0
    pop     {r1-r3}
    addne   sp, sp, #4
    popeq   {r0}
    bne     .Lret
.Lno_args:

    /*
     * Find the system call and call the function.
     *
     * System call number is passed in r7.
     */
#if (CFG_TEE_CORE_LOG_LEVEL == TRACE_FLOW)
    push    {r0-r3}
    mov     r0, r7
    blx     _trace_syscall
    pop     {r0-r3}
#endif
    ldr     r12, =tee_svc_syscall_table
    cmp     r7, #TEE_SCN_MAX
    /* Either syscall function should return to cleanup (.Lret) */
    ldr     lr, =.Lret         
    ldrls   pc, [r12, r7, lsl #2]       /* if valid syscall number */
    ldr     pc, =tee_svc_sys_nocall     /* if invalid syscall number */
.Lret:
    mov     sp, r8
    pop     {r4 - r12, lr}
    movs    pc, lr
.endfunc



@ TEE_Result tee_svc_enter_user_mode(
@              uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
@              tee_uaddr_t sp, tee_uaddr_t user_func,
@              uint32_t *panicked, uint32_t *panic_code);
.func tee_svc_enter_user_mode
tee_svc_enter_user_mode:
    /*
     * Save all registers to allow tee_svc_sys_return() to
     * resume execution as if this function would have returned.
     * This is also used in tee_svc_sys_panic().
     *
     * If stack usage of this function is changed tee_svc_sys_return()
     * and tee_svc_sys_panic() has to be updated.
     */
    push    {r4-r12,lr} 

    ldr     r4, [sp, #(10 * 0x4)]   /* user stack pointer */
    ldr     r5, [sp, #(11 * 0x4)]   /* user function */

    /* Save user sp */
    stmfd   sp, {sp}^       /* store r13 user mode */
    nop
    sub     sp, sp, #4    /* update stack pointer */

    /* Switch from Supervisor mode to System mode */
    mrs     r6, cpsr
    mrs     r7, cpsr
    orr     r6, #0xF
    msr     cpsr, r6

    /* Setup user stack */
    mov     sp, r4

    /* Switch back to Supervisor mode to have a spsr to modify */
    msr     cpsr, r7

    /*
     * Set the saved Processors Status Register to user mode to allow entry
     * of user mode through movs below. Also update thumbstate since movs
     * doesn't do that automatically.
     */
    bic     r6, #0xF
    tst     r5, #1              /* If it's odd we should switch to thumb mode */
    orrne   r6, #SPSR_T_BIT     /* Enable thumb mode */
    biceq   r6, #SPSR_T_BIT     /* Disable thumb mode */
    bicne   r6, #SPSR_IT_MASK1  /* Clear IT state for thumb mode */
    bicne   r6, #SPSR_IT_MASK2  /* Clear IT state for thumb mode */
    msr     spsr_cxsf, r6

    /*
     * Don't allow return from this function, return is done through
     * tee_svc_sys_return() below.
     */
    mov     lr, #0
    /* Call the user function with its arguments */
    movs    pc, r5
.endfunc

@ tee_svc_sys_return(uint32_t ret, uint32_t param_types, void *params);
.func tee_svc_sys_return
tee_svc_sys_return:
    mov     sp, r8          /* Restore sp in case extra parameters was passed */
    pop     {r4-r12,lr}     /* Match the push in tee_svc_syscall() */

    /* Restore user sp */
    ldmfd   sp, {sp}^       /* store r13 user mode */
    nop
    add     sp, sp, #4    /* update stack pointer */

    pop     {r4-r12,pc}     /* Match the push in tee_svc_enter_user_mode() */
.endfunc

@ void tee_svc_sys_panic(uint32_t code);
.func tee_svc_sys_panic
tee_svc_sys_panic:
    mov     sp, r8          /* Restore sp in case extra parameters was passed */
    pop     {r4-r12,lr}     /* Match the push in tee_svc_syscall() */

.global tee_svc_user_ta_panic_from_pager
tee_svc_user_ta_panic_from_pager:
    ldr     r1, [sp, #(13 * 0x4)]   /* &session->panicked */
    mov     r2, #1                  /* true */
    str     r2, [r1]                /* update session->panicked */

    ldr     r1, [sp, #(14 * 0x4)]   /* &session->panic_code */
    str     r0, [r1]                /* update session->panic_code */

    /* Restore user sp */
    ldmfd   sp, {sp}^       /* store r13 user mode */
    nop
    add     sp, sp, #4    /* update stack pointer */

    pop     {r4-r12,pc}     /* Match the push in tee_svc_enter_user_mode() */
.endfunc


        .section .rodata
.balign 4
tee_svc_syscall_table:
.word tee_svc_sys_return
.word tee_svc_sys_log
.word tee_svc_sys_panic
.word tee_svc_sys_dummy
.word tee_svc_sys_dummy_7args
.word tee_svc_sys_get_property
.word tee_svc_open_ta_session
.word tee_svc_close_ta_session
.word tee_svc_invoke_ta_command
.word tee_svc_check_access_rights
.word tee_svc_get_cancellation_flag
.word tee_svc_unmask_cancellation
.word tee_svc_mask_cancellation
.word tee_svc_wait
.word tee_svc_get_time
.word tee_svc_set_ta_time
.word tee_svc_cryp_state_alloc
.word tee_svc_cryp_state_copy
.word tee_svc_cryp_state_free
.word tee_svc_hash_init
.word tee_svc_hash_update
.word tee_svc_hash_final
.word tee_svc_cipher_init
.word tee_svc_cipher_update
.word tee_svc_cipher_final
.word tee_svc_cryp_obj_get_info
.word tee_svc_cryp_obj_restrict_usage
.word tee_svc_cryp_obj_get_attr
.word tee_svc_cryp_obj_alloc
.word tee_svc_cryp_obj_close
.word tee_svc_cryp_obj_reset
.word tee_svc_cryp_obj_populate
.word tee_svc_cryp_obj_copy
.word tee_svc_cryp_derive_key
.word tee_svc_cryp_random_number_generate
.word tee_svc_authenc_init
.word tee_svc_authenc_update_aad
.word tee_svc_authenc_update_payload
.word tee_svc_authenc_enc_final
.word tee_svc_authenc_dec_final
.word tee_svc_asymm_operate
.word tee_svc_asymm_verify
.word tee_svc_storage_obj_open
.word tee_svc_storage_obj_create
.word tee_svc_storage_obj_del
.word tee_svc_storage_obj_rename
.word tee_svc_storage_alloc_enum
.word tee_svc_storage_free_enum
.word tee_svc_storage_reset_enum
.word tee_svc_storage_start_enum
.word tee_svc_storage_next_enum
.word tee_svc_storage_obj_read
.word tee_svc_storage_obj_write
.word tee_svc_storage_obj_trunc
.word tee_svc_storage_obj_seek
.word tee_svc_obj_generate_key
