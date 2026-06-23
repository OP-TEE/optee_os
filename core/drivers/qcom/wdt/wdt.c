// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * QCOM Secure Watchdog Driver
 *
 */

#include <arm.h>
#include <initcall.h>
#include <io.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <trace.h>
#include <util.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, WDT_TMR_BASE,
			CORE_MMU_PGDIR_SIZE);

#define WDT_CTL_OFFSET				0x08
#define WDT_BARK_TIME_OFFSET			0x10
#define WDT_BITE_TIME_OFFSET			0x14

#define WDT_CTL_INT_ENABLE_SHFT			0
#define WDT_CTL_UNMASKED_INT_ENABLE_SHFT	1

#define WDT_BARK_TIME_RMSK			0xFFFFFU
#define WDT_BITE_TIME_RMSK			0xFFFFFU

#define WDT_CLK_HZ				32000U

#define WDT_BARK_TIME_MS			6000U
#define WDT_BITE_TIME_MS			22000U

static vaddr_t wdt_base;

static uint32_t ms_to_ticks_wdt(uint32_t ms)
{
	return (uint32_t)(((uint64_t)ms * WDT_CLK_HZ) / 1000U);
}

static void wdt_enable(bool enable)
{
	io_write32(wdt_base + WDT_CTL_OFFSET,
		   UINT32_C(1) << WDT_CTL_UNMASKED_INT_ENABLE_SHFT
		   | (enable ? UINT32_C(1) : UINT32_C(0))
		     << WDT_CTL_INT_ENABLE_SHFT);
}

static void wdt_reset(void)
{
	io_write32(wdt_base + WDT_RESET_REG_OFFSET, 1);
}

static void wdt_start(uint32_t bark_timeout, uint32_t bite_timeout)
{
	/* Zero timeouts are not allowed, ensure timeouts are > 0. */
	bark_timeout = MAX(bark_timeout, 0x1U);
	bite_timeout = MAX(bite_timeout, 0x1U);

	bark_timeout = ms_to_ticks_wdt(bark_timeout);
	bite_timeout = ms_to_ticks_wdt(bite_timeout);

	/* Timeouts have a ceiling value */
	bark_timeout = MIN(bark_timeout, (uint32_t)(WDT_BARK_TIME_RMSK));
	bite_timeout = MIN(bite_timeout, (uint32_t)(WDT_BITE_TIME_RMSK));

	wdt_enable(false);

	io_write32(wdt_base + WDT_BARK_TIME_OFFSET, bark_timeout);
	io_write32(wdt_base + WDT_BITE_TIME_OFFSET, bite_timeout);

	wdt_enable(true);

	wdt_reset();
}

static enum itr_return
wdt_bark_handler(struct itr_handler *h __unused)
{
	io_write32(wdt_base + WDT_RESET_REG_OFFSET, 1);

	return ITRR_HANDLED;
}

static TEE_Result wdt_init(void)
{
	TEE_Result res = TEE_SUCCESS;
	struct itr_handler *handler = NULL;

	wdt_base = (vaddr_t)phys_to_virt(WDT_TMR_BASE,
					 MEM_AREA_IO_SEC, 1);
	if (!wdt_base) {
		EMSG("wdt: Failed to map watchdog registers");
		return TEE_ERROR_GENERIC;
	}

	wdt_start(WDT_BARK_TIME_MS, WDT_BITE_TIME_MS);

	res = interrupt_create_handler(interrupt_get_main_chip(),
				       WDT_BARK_INT_ID,
				       wdt_bark_handler,
				       0u, 0u, &handler);
	if (res != TEE_SUCCESS) {
		EMSG("wdt: Failed to register bark handler (err=0x%x)",
		     res);
		return res;
	}

	return TEE_SUCCESS;
}

driver_init(wdt_init);

