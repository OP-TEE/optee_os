/*
 * Copyright (c) 2014, Allwinner Technology Co., Ltd.
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
#include <platform_config.h>

#include <sm/sm.h>
#include <sm/sm_defs.h>
#include <sm/tee_mon.h>
#include <sm/optee_smc.h>
#include <optee_msg.h>

#include <arm.h>
#include <kernel/thread.h>
#include <kernel/time_source.h>
#include <kernel/panic.h>
#include <kernel/misc.h>
#include <mm/tee_pager.h>
#include <mm/core_mmu.h>

#include <drivers/gic.h>
#include <drivers/sunxi_uart.h>

#include <trace.h>
#include <io.h>
#include <assert.h>
#include <util.h>
#include <platform.h>

void sunxi_secondary_entry(void);

uint32_t sunxi_secondary_ns_entry;

struct gic_data gic_data;

static int platform_smp_init(void)
{
	write32((uint32_t)sunxi_secondary_entry, (PRCM_BASE + PRCM_CPU_SOFT_ENTRY_REG));
	
	return 0;
}

void platform_init(void)
{
	/*
	 * GIC configuration is initialized in Secure bootloader,
	 * Initialize GIC base address here for debugging.
	 */
	gic_init_base_addr(&gic_data, GIC_BASE + GICC_OFFSET,
			   GIC_BASE + GICD_OFFSET);
	itr_init(&gic_data.chip);

	/* platform smp initialize */
	platform_smp_init();
	
	/* enable non-secure access cci-400 registers */
	write32(0x1, CCI400_BASE + CCI400_SECURE_ACCESS_REG);

	/* Initialize uart with physical address */
	sunxi_uart_init(UART0_BASE);

	return ;
}

/**
 * handle platform special smc commands.
 */
uint32_t platform_smc_handle(struct thread_smc_args *smc_args)
{
	uint32_t ret = TEE_SUCCESS;
	switch (smc_args->a1) {
	case OPTEE_SMC_SIP_SUNXI_SET_SMP_BOOTENTRY:
		sunxi_secondary_ns_entry = smc_args->a2;
		
		/* in order to sync with secondary up cpu */
		cache_maintenance_l1(DCACHE_AREA_CLEAN, 
		                       (void *)(&sunxi_secondary_ns_entry), 
		                       sizeof(uint32_t));
		break;
	default:
		ret = OPTEE_SMC_RETURN_EBADCMD;
		break;
	}
	smc_args->a0 = ret;
	return ret;
}

