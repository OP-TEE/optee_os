/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Limited
 */

#include <kernel/thread.h>
#include <kernel/riscv_fp.h>
#include <kernel/riscv_vector.h>
#include <assert.h>

void __asm_save_fp_state(struct riscv_fp_state *ctx);
void __asm_restore_fp_state(struct riscv_fp_state *ctx);

#define STATE_TOKEN_FP     SHIFT_U32(1, 0)
#define STATE_TOKEN_VEC    SHIFT_U32(1, 1)

struct thread_riscv_ext_state {
	struct riscv_fp_state fp_ctx;
	struct riscv_vector_state v_ctx;
	bool fp_saved;
	bool vec_saved;
};

static struct thread_riscv_ext_state cpu_ctx_states[CFG_NUM_THREADS];

static inline unsigned long read_sstatus(void)
{
	unsigned long val;
	asm volatile("csrr %0, sstatus" : "=r"(val));
	return val;
}

static inline void write_sstatus(unsigned long val)
{
	asm volatile("csrw sstatus, %0" :: "r"(val));
}

uint32_t thread_kernel_enable_vfp(void)
{
	unsigned long sstatus = read_sstatus();
	uint32_t active_token = 0;

	if ((sstatus & SSTATUS_FS_MASK) != SSTATUS_FS_CLEAN) {
		sstatus &= ~SSTATUS_FS_MASK;
		sstatus |= SSTATUS_FS_CLEAN;
		active_token |= STATE_TOKEN_FP;
	}

	if ((sstatus & SSTATUS_VS_MASK) != SSTATUS_VS_CLEAN) {
		sstatus &= ~SSTATUS_VS_MASK;
		sstatus |= SSTATUS_VS_CLEAN;
		active_token |= STATE_TOKEN_VEC;
	}

	write_sstatus(sstatus);
	return active_token;
}

void thread_kernel_disable_vfp(uint32_t state_value)
{
	unsigned long sstatus = read_sstatus();

	if (state_value & STATE_TOKEN_FP) {
		sstatus &= ~SSTATUS_FS_MASK;
		sstatus |= SSTATUS_FS_OFF;
	}
	if (state_value & STATE_TOKEN_VEC) {
		sstatus &= ~SSTATUS_VS_MASK;
		sstatus |= SSTATUS_VS_OFF;
	}
	write_sstatus(sstatus);
}

void thread_kernel_save_vfp(void)
{
	unsigned long sstatus = read_sstatus();
	uint32_t tid = thread_get_id();
	struct thread_riscv_ext_state *state = &cpu_ctx_states[tid];

	if ((sstatus & SSTATUS_FS_MASK) == SSTATUS_FS_DIRTY) {
		__asm_save_fp_state(&state->fp_ctx);
		state->fp_saved = true;
		sstatus = (sstatus & ~SSTATUS_FS_MASK) | SSTATUS_FS_CLEAN;
	}

	if ((sstatus & SSTATUS_VS_MASK) == SSTATUS_VS_DIRTY) {
		assert(state->v_ctx.vregs != NULL);
		riscv_vector_save_internal(&state->v_ctx);
		state->vec_saved = true;
		sstatus = (sstatus & ~SSTATUS_VS_MASK) | SSTATUS_VS_CLEAN;
	}
	write_sstatus(sstatus);
}

void thread_kernel_restore_vfp(void)
{
	unsigned long sstatus = read_sstatus();
	uint32_t tid = thread_get_id();
	struct thread_riscv_ext_state *state = &cpu_ctx_states[tid];

	if (state->fp_saved) {
		sstatus = (sstatus & ~SSTATUS_FS_MASK) | SSTATUS_FS_CLEAN;
		write_sstatus(sstatus);
		__asm_restore_fp_state(&state->fp_ctx);
		state->fp_saved = false;
	}

	if (state->vec_saved) {
		sstatus = (sstatus & ~SSTATUS_VS_MASK) | SSTATUS_VS_CLEAN;
		write_sstatus(sstatus);
		riscv_vector_restore_internal(&state->v_ctx);
		state->vec_saved = false;
	}
}

void thread_user_enable_vfp(struct thread_user_vfp_state *uvfp __unused)
{
	unsigned long sstatus = read_sstatus();
	sstatus = (sstatus & ~SSTATUS_FS_MASK) | SSTATUS_FS_INITIAL;
	sstatus = (sstatus & ~SSTATUS_VS_MASK) | SSTATUS_VS_INITIAL;
	write_sstatus(sstatus);
}

void thread_user_save_vfp(struct thread_user_vfp_state *uvfp __unused)
{
	thread_kernel_save_vfp();
}

void thread_user_clear_vfp(struct thread_user_vfp_state *uvfp __unused)
{
	unsigned long sstatus = read_sstatus();
	uint32_t tid = thread_get_id();
	struct thread_riscv_ext_state *state = &cpu_ctx_states[tid];

	state->fp_saved = false;
	state->vec_saved = false;

	sstatus &= ~(SSTATUS_FS_MASK | SSTATUS_VS_MASK);
	sstatus |= (SSTATUS_FS_OFF | SSTATUS_VS_OFF);
	write_sstatus(sstatus);
}

