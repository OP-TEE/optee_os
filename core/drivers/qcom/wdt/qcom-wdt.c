// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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

#define QCOM_WDT_CTL_OFFSET			0x08
#define QCOM_WDT_BARK_TIME_OFFSET		0x10
#define QCOM_WDT_BITE_TIME_OFFSET		0x14
#define QCOM_WDT_RESET_REG_OFFSET		0x4

#define QCOM_WDT_CTL_INT_ENABLE		BIT32(0)
#define QCOM_WDT_CTL_UNMASKED_INT_ENABLE	BIT32(1)

#define QCOM_WDT_RESET_REG_RESET		UINT32_C(1)

#define QCOM_WDT_BARK_TIME_RMSK		0xFFFFFU
#define QCOM_WDT_BITE_TIME_RMSK		0xFFFFFU

#define QCOM_WDT_CLK_HZ				32000U

#define QCOM_WDT_MS_TO_TICKS(ms) \
	((uint32_t)(((uint64_t)(ms) * QCOM_WDT_CLK_HZ) / 1000U))

#define QCOM_WDT_BARK_TIME_MS			6000U
#define QCOM_WDT_BITE_TIME_MS			22000U

register_phys_mem_pgdir(MEM_AREA_IO_SEC, QCOM_WDT_TMR_BASE,
			CORE_MMU_PGDIR_SIZE);

static vaddr_t qcom_wdt_base;

static void qcom_wdt_enable(bool enable)
{
	uint32_t val = QCOM_WDT_CTL_UNMASKED_INT_ENABLE;

	if (enable)
		val |= QCOM_WDT_CTL_INT_ENABLE;

	io_write32(qcom_wdt_base + QCOM_WDT_CTL_OFFSET, val);
}

static void qcom_wdt_reset(void)
{
	io_write32(qcom_wdt_base + QCOM_WDT_RESET_REG_OFFSET,
		   QCOM_WDT_RESET_REG_RESET);
}

static void qcom_wdt_start(void)
{
	uint32_t bark_timeout = QCOM_WDT_MS_TO_TICKS(QCOM_WDT_BARK_TIME_MS);
	uint32_t bite_timeout = QCOM_WDT_MS_TO_TICKS(QCOM_WDT_BITE_TIME_MS);

	/* Timeouts have a ceiling value */
	bark_timeout = MIN(bark_timeout, (uint32_t)(QCOM_WDT_BARK_TIME_RMSK));
	bite_timeout = MIN(bite_timeout, (uint32_t)(QCOM_WDT_BITE_TIME_RMSK));

	io_write32(qcom_wdt_base + QCOM_WDT_BARK_TIME_OFFSET, bark_timeout);
	io_write32(qcom_wdt_base + QCOM_WDT_BITE_TIME_OFFSET, bite_timeout);

	qcom_wdt_enable(true);

	qcom_wdt_reset();
}

static enum itr_return
qcom_wdt_bark_handler(struct itr_handler *h __unused)
{
	io_write32(qcom_wdt_base + QCOM_WDT_RESET_REG_OFFSET,
		   QCOM_WDT_RESET_REG_RESET);

	return ITRR_HANDLED;
}

static TEE_Result qcom_wdt_init(void)
{
	TEE_Result res = TEE_SUCCESS;
	struct itr_handler *handler = NULL;

	qcom_wdt_base = (vaddr_t)phys_to_virt(QCOM_WDT_TMR_BASE,
					      MEM_AREA_IO_SEC,
					      CORE_MMU_PGDIR_SIZE);
	if (!qcom_wdt_base) {
		EMSG("wdt: Failed to map watchdog registers");
		return TEE_ERROR_GENERIC;
	}

	qcom_wdt_enable(false);

	res = interrupt_create_handler(interrupt_get_main_chip(),
				       QCOM_WDT_BARK_INT_ID,
				       qcom_wdt_bark_handler,
				       0u, 0u, &handler);
	if (res != TEE_SUCCESS) {
		EMSG("wdt: Failed to register bark handler (err=0x%x)",
		     res);
		return res;
	}

	qcom_wdt_start();

	return TEE_SUCCESS;
}

driver_init(qcom_wdt_init);

