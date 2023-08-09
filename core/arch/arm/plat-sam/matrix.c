// SPDX-License-Identifier: BSD-Source-Code
/*
 * Copyright (c) 2013, Atmel Corporation
 * Copyright (c) 2017, Timesys Corporation
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the disclaimer below.
 *
 * Atmel's name may not be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * DISCLAIMER: THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <arm32.h>
#include <initcall.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/pm.h>
#include <kernel/panic.h>
#include <matrix.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <tz_matrix.h>
#include <trace.h>

#define WORLD_NON_SECURE	0
#define WORLD_SECURE		1

static void matrix_write(unsigned int base,
			 unsigned int offset,
			 const unsigned int value)
{
	io_write32(offset + base, value);
}

static unsigned int matrix_read(int base, unsigned int offset)
{
	return io_read32(offset + base);
}

vaddr_t matrix_base(unsigned int matrix)
{
	unsigned int i = 0;
	struct matrix *pmatrix = NULL;

	do {
		pmatrix = matrix_get(i++);
		if (!pmatrix)
			panic("Invalid matrix");
	} while (pmatrix->matrix != matrix);

	return io_pa_or_va_secure(&pmatrix->p, CORE_MMU_PGDIR_SIZE);
}

void matrix_write_protect_enable(unsigned int matrix_base)
{
	matrix_write(matrix_base, MATRIX_WPMR,
		     MATRIX_WPMR_WPKEY_PASSWD | MATRIX_WPMR_WPEN_ENABLE);
}

void matrix_write_protect_disable(unsigned int matrix_base)
{
	matrix_write(matrix_base, MATRIX_WPMR, MATRIX_WPMR_WPKEY_PASSWD);
}

void matrix_configure_slave_security(unsigned int matrix_base,
				     unsigned int slave,
				     unsigned int srtop_setting,
				     unsigned int srsplit_setting,
				     unsigned int ssr_setting)
{
	matrix_write(matrix_base, MATRIX_SSR(slave), ssr_setting);
	matrix_write(matrix_base, MATRIX_SRTSR(slave), srtop_setting);
	matrix_write(matrix_base, MATRIX_SASSR(slave), srsplit_setting);
}

static const struct peri_security *get_peri_security(unsigned int peri_id)
{
	unsigned int i = 0;
	struct peri_security *p = NULL;

	do {
		p = peri_security_get(i++);
		if (p && peri_id == p->peri_id)
			break;
	} while (p);

	return p;
}

static int matrix_set_periph_world(unsigned int matrix, unsigned int peri_id,
				   unsigned int world)
{
	unsigned int spselr = 0;
	unsigned int idx = peri_id / 32;
	unsigned int bit = 0x01 << (peri_id % 32);
	unsigned int base = matrix_base(matrix);

	if (idx > 3)
		return -1;

	spselr = matrix_read(base, MATRIX_SPSELR(idx));
	if (world == WORLD_SECURE)
		spselr &= ~bit;
	else
		spselr |= bit;
	matrix_write(base, MATRIX_SPSELR(idx), spselr);

	return 0;
}

TEE_Result matrix_dt_get_id(const void *fdt, int node, unsigned int *id)
{
	unsigned int i = 0;
	paddr_t pbase = 0;
	struct peri_security *p = NULL;

	pbase = fdt_reg_base_address(fdt, node);
	if (pbase == DT_INFO_INVALID_REG)
		return TEE_ERROR_BAD_PARAMETERS;

	do {
		p = peri_security_get(i++);
		if (p && p->addr == pbase) {
			*id = p->peri_id;
			return TEE_SUCCESS;
		}
	} while (p);

	return TEE_ERROR_ITEM_NOT_FOUND;
}

int matrix_configure_periph_secure(unsigned int peri_id)
{
	const struct peri_security *psec = NULL;

	psec = get_peri_security(peri_id);
	if (!psec)
		return -1;

	return matrix_set_periph_world(psec->matrix, peri_id, WORLD_SECURE);
}

int matrix_configure_periph_non_secure(unsigned int *peri_id_array,
				       unsigned int size)
{
	unsigned int i = 0;
	unsigned int *peri_id_p = peri_id_array;
	unsigned int matrix = 0;
	unsigned int peri_id = 0;
	const struct peri_security *peripheral_sec = NULL;
	int ret = 0;

	if (!peri_id_array || !size)
		return -1;

	for (i = 0; i < size; i++) {
		peripheral_sec = get_peri_security(*peri_id_p);
		if (!peripheral_sec)
			return -1;

		if (peripheral_sec->security_type != SECURITY_TYPE_PS)
			return -1;

		matrix = peripheral_sec->matrix;
		peri_id = *peri_id_p;
		ret = matrix_set_periph_world(matrix, peri_id,
					      WORLD_NON_SECURE);
		if (ret)
			return -1;

		peri_id_p++;
	}

	return 0;
}

#ifdef CFG_PM_ARM32

static void matrix_save_regs(vaddr_t base, struct matrix_state *state)
{
	int idx = 0;

	for (idx = 0; idx < MATRIX_SPSELR_COUNT; idx++)
		state->spselr[idx] = matrix_read(base, MATRIX_SPSELR(idx));

	for (idx = 0; idx < MATRIX_SLAVE_COUNT; idx++) {
		state->ssr[idx] = matrix_read(base, MATRIX_SSR(idx));
		state->srtsr[idx] = matrix_read(base, MATRIX_SRTSR(idx));
		state->sassr[idx] = matrix_read(base, MATRIX_SASSR(idx));
	}

	state->meier = matrix_read(base, MATRIX_MEIER);
	state->meimr = matrix_read(base, MATRIX_MEIMR);
}

static void matrix_suspend(void)
{
	unsigned int i = 0;
	struct matrix *pmatrix = NULL;

	for (pmatrix = matrix_get(i++); pmatrix; pmatrix = matrix_get(i++))
		matrix_save_regs(matrix_base(pmatrix->matrix), &pmatrix->state);
}

static void matrix_restore_regs(vaddr_t base, struct matrix_state *state)
{
	int idx = 0;

	matrix_write_protect_disable(base);

	for (idx = 0; idx < MATRIX_SPSELR_COUNT; idx++)
		matrix_write(base, MATRIX_SPSELR(idx), state->spselr[idx]);

	for (idx = 0; idx < MATRIX_SLAVE_COUNT; idx++) {
		matrix_write(base, MATRIX_SSR(idx), state->ssr[idx]);
		matrix_write(base, MATRIX_SRTSR(idx), state->srtsr[idx]);
		matrix_write(base, MATRIX_SASSR(idx), state->sassr[idx]);
	}

	matrix_write(base, MATRIX_MEIER, state->meier);
	matrix_write(base, MATRIX_MEIMR, state->meimr);
}

static void matrix_resume(void)
{
	unsigned int i = 0;
	struct matrix *pmatrix = NULL;

	for (pmatrix = matrix_get(i++); pmatrix; pmatrix = matrix_get(i++))
		matrix_restore_regs(matrix_base(pmatrix->matrix),
				    &pmatrix->state);
}

static TEE_Result matrix_pm(enum pm_op op, uint32_t pm_hint __unused,
			    const struct pm_callback_handle *hdl __unused)
{
	switch (op) {
	case PM_OP_RESUME:
		matrix_resume();
		break;
	case PM_OP_SUSPEND:
		matrix_suspend();
		break;
	default:
		panic("Invalid PM operation");
	}

	return TEE_SUCCESS;
}

static TEE_Result matrix_pm_init(void)
{
	/*
	 * We can't call matrix_register_pm in matrix_init since allocator is
	 * not ready yet so we just call it later in this driver init callback.
	 */
	register_pm_driver_cb(matrix_pm, NULL, "sam-matrix");

	return TEE_SUCCESS;
}
driver_init(matrix_pm_init);

#endif
