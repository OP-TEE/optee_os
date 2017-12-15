// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
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

#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

#if defined(PLATFORM_FLAVOR_rk322x)

#define SGRF_SOC_CON(n)		((n) * 4)
#define DDR_SGRF_DDR_CON(n)	((n) * 4)
#define DDR_RGN0_NS		BIT32(30)
#define SLAVE_ALL_NS		0xffff0000

static TEE_Result platform_init(void)
{
	vaddr_t sgrf_base = (vaddr_t)phys_to_virt_io(SGRF_BASE);
	vaddr_t ddrsgrf_base = (vaddr_t)phys_to_virt_io(DDRSGRF_BASE);

	/* Set rgn0 non-secure */
	write32(DDR_RGN0_NS, ddrsgrf_base + DDR_SGRF_DDR_CON(0));

	/* Initialize all slave non-secure */
	write32(SLAVE_ALL_NS, sgrf_base + SGRF_SOC_CON(7));
	write32(SLAVE_ALL_NS, sgrf_base + SGRF_SOC_CON(8));
	write32(SLAVE_ALL_NS, sgrf_base + SGRF_SOC_CON(9));
	write32(SLAVE_ALL_NS, sgrf_base + SGRF_SOC_CON(10));

	return TEE_SUCCESS;
}

#endif

service_init(platform_init);
