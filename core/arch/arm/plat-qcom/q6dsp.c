// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Limited
 */

#include <console.h>
#include <drivers/geni_uart.h>
#include <drivers/clk_qcom.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <io.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <tee/entry_fast.h>
#include <drivers/gic.h>
#include <sm/optee_smc.h>
#include <kernel/delay.h>

#include "q6dsp.h"

#define WPSS_MEM_PHYS 0x84800000

/*QDSP6SS register offsets*/
#define RST_EVB_REG			0x10
#define CORE_START_REG			0x400
#define BOOT_CMD_REG			0x404
#define BOOT_STATUS_REG			0x408
#define RET_CFG_REG			0x1C

#define QDSP6SS_XO_CBCR		0x38
#define QDSP6SS_CORE_CBCR	0x20
#define QDSP6SS_SLEEP_CBCR	0x3c
#define LPASS_BOOT_CORE_START	BIT(0)
#define LPASS_BOOT_CMD_START	BIT(0)

#define BOOT_FSM_TIMEOUT		10000

#if defined(PLATFORM_FLAVOR_sc7280)
#define PAS_ID_WPSS 0x06
static struct qcom_q6dsp_data wpss_dsp_data = {
	.pas_id = PAS_ID_WPSS,
	.base.pa = WPSS_BASE,
};
#endif

static void kodiak_wpss_start(struct thread_smc_args *args)
{
	uint32_t val;
	uint64_t timer;
	vaddr_t base = io_pa_or_va(&wpss_dsp_data.base, 0x500);
	/* Enable the XO clock */
	io_write32(base + QDSP6SS_XO_CBCR, 1);

	/* Enable the QDSP6SS sleep clock */
	io_write32(base + QDSP6SS_SLEEP_CBCR, 1);

	/* Enable the QDSP6 core clock */
	io_write32(base + QDSP6SS_CORE_CBCR, 1);

	/* Program boot address */
	io_write32(base + RST_EVB_REG, wpss_dsp_data.firmware_base >> 4);

	/* Flush configuration */
	dsb();

	/* De-assert QDSP6 stop core. QDSP6 will execute after out of reset */
	io_write32(base + CORE_START_REG, LPASS_BOOT_CORE_START);

	/* Trigger boot FSM to start QDSP6 */
	io_write32(base + BOOT_CMD_REG, LPASS_BOOT_CMD_START);

	/* Wait for core to come out of reset */
	timer = timeout_init_us(BOOT_FSM_TIMEOUT);
	do {
		val = io_read32(base + BOOT_STATUS_REG);
		if ((val & BIT(0)) != 0)
			break;
		if (timeout_elapsed(timer))
			break;
		udelay(10);
	} while (0);

	if ((val & BIT(0)) != 0) {
		EMSG("Timed out waiting for WPSS to boot :(");
		args->a0 = -4;
		return;
	}

	args->a0 = OPTEE_SMC_RETURN_OK;
	args->a2 = 0;
	args->a3 = 0;
	args->a4 = 0;
	args->a5 = 0;
}

#define QCOM_SCM_PIL_PAS_INIT_IMAGE	0x0201
#define QCOM_SCM_PIL_PAS_MEM_SETUP	0x0202
#define QCOM_SCM_PIL_PAS_AUTH_AND_RESET	0x0205
#define QCOM_SCM_PIL_PAS_SHUTDOWN	0x0206
#define QCOM_SCM_PIL_PAS_IS_SUPPORTED	0x0207
#define QCOM_SCM_PIL_PAS_MSS_RESET	0x020a

static inline const char *smc_decode_pil_cmd(uint32_t cmd)
{
	switch (cmd) {
	case QCOM_SCM_PIL_PAS_INIT_IMAGE: return "init_image";
	case QCOM_SCM_PIL_PAS_MEM_SETUP: return "mem_setup";
	case QCOM_SCM_PIL_PAS_AUTH_AND_RESET: return "auth_and_reset";
	case QCOM_SCM_PIL_PAS_SHUTDOWN: return "shutdown";
	case QCOM_SCM_PIL_PAS_IS_SUPPORTED: return "is_supported";
	case QCOM_SCM_PIL_PAS_MSS_RESET: return "mss_reset";
	default:  return "???";
	}
}

static inline const char *pas_id_name(uint32_t pas_id)
{
	switch (pas_id) {
	case PAS_ID_WPSS: return "wpss";
	default: return "???";
	}
}

void qcom_handle_pil_smc(struct thread_smc_args *args)
{
	uint32_t sv_cmd = args->a0 & 0xffff;

	DMSG("Handling %s cmd for %s", smc_decode_pil_cmd(sv_cmd),
	     pas_id_name(args->a2));

	if (args->a2 != PAS_ID_WPSS) {
		EMSG("Ignoring request for unsupported DSP 0x%lx", args->a2);
		args->a0 = OPTEE_SMC_RETURN_EBADCMD;
		return;
	}

	switch (sv_cmd) {
	case QCOM_SCM_PIL_PAS_INIT_IMAGE:
		/* FIXME: handle MBN parsing stuff here */
		break;
	case QCOM_SCM_PIL_PAS_MEM_SETUP:
		/* Save base address of firmware */
		wpss_dsp_data.firmware_base = args->a3;
		break;
	case QCOM_SCM_PIL_PAS_AUTH_AND_RESET:
		qcom_clock_enable(QCOM_CLKS_WPSS);
		kodiak_wpss_start(args);
		break;
	case QCOM_SCM_PIL_PAS_SHUTDOWN:
	case QCOM_SCM_PIL_PAS_IS_SUPPORTED:
	case QCOM_SCM_PIL_PAS_MSS_RESET:
		break;
	default:
		EMSG("Unsupported command 0x%x", sv_cmd);
		args->a0 = OPTEE_SMC_RETURN_EBADCMD;
		break;
	}

	args->a0 = OPTEE_SMC_RETURN_OK;
	args->a1 = 0;
	args->a2 = 0;
	args->a3 = 0;
	args->a4 = 0;
}
