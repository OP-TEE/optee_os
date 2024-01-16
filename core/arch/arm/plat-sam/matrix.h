/* SPDX-License-Identifier: BSD-Source-Code */
/* ----------------------------------------------------------------------------
 *         ATMEL Microcontroller Software Support
 * ----------------------------------------------------------------------------
 * Copyright (c) 2013, Atmel Corporation
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
#ifndef MATRIX_H
#define MATRIX_H

#include <mm/core_memprot.h>
#include <stdint.h>
#include <tee_api_types.h>

#define SECURITY_TYPE_AS	1
#define SECURITY_TYPE_NS	2
#define SECURITY_TYPE_PS	3

#define MATRIX_SPSELR_COUNT	3
#define MATRIX_SLAVE_COUNT	15

#ifdef CFG_PM_ARM32
struct matrix_state {
	uint32_t spselr[MATRIX_SPSELR_COUNT];
	uint32_t ssr[MATRIX_SLAVE_COUNT];
	uint32_t srtsr[MATRIX_SLAVE_COUNT];
	uint32_t sassr[MATRIX_SLAVE_COUNT];
	uint32_t meier;
	uint32_t meimr;
};
#endif

struct matrix {
	unsigned int matrix;
	struct io_pa_va p;
#ifdef CFG_PM_ARM32
	struct matrix_state state;
#endif
};

struct peri_security {
	unsigned int peri_id;
	unsigned int matrix;
	unsigned int security_type;
	paddr_t addr;
};

struct peri_security *peri_security_get(unsigned int idx);
struct matrix *matrix_get(unsigned int idx);
vaddr_t matrix_base(unsigned int matrix);

void matrix_write_protect_enable(unsigned int matrix_base);
void matrix_write_protect_disable(unsigned int matrix_base);
void matrix_configure_slave_security(unsigned int matrix_base,
				     unsigned int slave,
				     unsigned int srtop_setting,
				     unsigned int srsplit_setting,
				     unsigned int ssr_setting);

int matrix_configure_periph_non_secure(unsigned int *peri_id_array,
				       unsigned int size);
int matrix_configure_periph_secure(unsigned int peri_id);
TEE_Result matrix_dt_get_id(const void *fdt, int node, unsigned int *id);

#endif /* #ifndef MATRIX_H */
