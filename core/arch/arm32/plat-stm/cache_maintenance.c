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
#include <compiler.h>
#include <arm32.h>
#include <mm/core_mmu.h>
#include <kernel/tz_ssvce_pl310.h>

unsigned int cache_maintenance_l2(int op __unused,
				   paddr_t pa __unused, size_t len __unused)
{
	unsigned int ret = TEE_SUCCESS;

	core_l2cc_mutex_lock();

	switch (op) {
	case L2CACHE_INVALIDATE:
		arm_cl2_invbyway();
		break;
	case L2CACHE_AREA_INVALIDATE:
		arm_cl2_invbyway();
		break;
	case L2CACHE_CLEAN:
		arm_cl2_cleanbyway();
		break;
	case L2CACHE_AREA_CLEAN:
		arm_cl2_cleanbyway();
		break;
	case L2CACHE_CLEAN_INV:
		arm_cl2_cleaninvbyway();
		break;
	case L2CACHE_AREA_CLEAN_INV:
		arm_cl2_cleaninvbyway();
		break;
	default:
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	core_l2cc_mutex_unlock();
	return ret;
}
