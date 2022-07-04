// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <arm.h>
#include <drivers/versal_mbox.h>
#include <drivers/versal_pm.h>
#include <kernel/cache_helpers.h>
#include <kernel/delay.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>
#include <tee_api_types.h>
#include <utee_defines.h>

#define PAYLOAD_ARG_CNT		6
#define PM_SIP_SVC		0xc2000000

/* PM API ids */
#define PM_GET_API_VERSION		1
#define PM_GET_DEVICE_STATUS		3
#define PM_GET_OP_CHARACTERISTIC	4
#define PM_REGISTER_NOTIFIER		5
#define PM_REQ_SUSPEND			6
#define PM_SELF_SUSPEND			7
#define PM_FORCE_POWERDOWN		8
#define PM_ABORT_SUSPEND		9
#define PM_REQ_WAKEUP			10
#define PM_SET_WAKEUP_SOURCE		11
#define PM_SYSTEM_SHUTDOWN		12
#define PM_REQUEST_DEVICE		13
#define PM_RELEASE_DEVICE		14
#define PM_SET_REQUIREMENT		15
#define PM_SET_MAX_LATENCY		16
#define PM_RESET_ASSERT			17
#define PM_RESET_GET_STATUS		18
#define PM_INIT_FINALIZE		21
#define PM_GET_CHIPID			24
#define	PM_PINCTRL_REQUEST		28
#define	PM_PINCTRL_RELEASE		29
#define	PM_PINCTRL_GET_FUNCTION		30
#define	PM_PINCTRL_SET_FUNCTION		31
#define	PM_PINCTRL_CONFIG_PARAM_GET	32
#define	PM_PINCTRL_CONFIG_PARAM_SET	33
#define PM_IOCTL			34
#define PM_QUERY_DATA			35
#define PM_CLOCK_ENABLE			36
#define PM_CLOCK_DISABLE		37
#define PM_CLOCK_GETSTATE		38
#define PM_CLOCK_SETDIVIDER		39
#define PM_CLOCK_GETDIVIDER		40
#define PM_CLOCK_SETRATE		41
#define PM_CLOCK_GETRATE		42
#define PM_CLOCK_SETPARENT		43
#define PM_CLOCK_GETPARENT		44
#define PM_PLL_SET_PARAMETER		48
#define PM_PLL_GET_PARAMETER		49
#define PM_PLL_SET_MODE			50
#define PM_PLL_GET_MODE			51
#define PM_FEATURE_CHECK		63
#define PM_LOAD_PDI			0x701

/* PDI sources */
#define PDI_SRC_JTAG		0x0
#define PDI_SRC_QSPI24		0x1
#define PDI_SRC_QSPI32		0x2
#define PDI_SRC_SD0		0x3
#define PDI_SRC_EMMC0		0x4
#define PDI_SRC_SD1		0x5
#define PDI_SRC_EMMC1		0x6
#define PDI_SRC_USB		0x7
#define PDI_SRC_OSPI		0x8
#define PDI_SRC_SBI		0x9
#define PDI_SRC_SMAP		0xA
#define PDI_SRC_PCIE		0xB
#define PDI_SRC_SD1_LS		0xE
#define PDI_SRC_DDR		0xF

struct versal_sip_payload {
	uint32_t data[PAYLOAD_ARG_CNT];
};

static uint32_t versal_sip_call(uint32_t pm_api_id, uint32_t arg0,
				uint32_t arg1, uint32_t arg2, uint32_t arg3,
				struct versal_sip_payload *payload)
{
	struct thread_smc_args args = {
		.a0 = PM_SIP_SVC | pm_api_id,
		.a1 = reg_pair_to_64(arg1, arg0),
		.a2 = reg_pair_to_64(arg3, arg2),
	};

	thread_smccc(&args);

	if (payload) {
		reg_pair_from_64(args.a0, &payload->data[1], &payload->data[0]);
		reg_pair_from_64(args.a1, &payload->data[3], &payload->data[2]);
		reg_pair_from_64(args.a2, &payload->data[5], &payload->data[4]);
	}

	/* allow the PLM to output its debug information */
	if (IS_ENABLED(CFG_VERSAL_TRACE_PLM))
		mdelay(500);

	return args.a0;
}

TEE_Result versal_write_fpga(paddr_t pa)
{
	struct ipi_cmd cmd = { };

	if (IS_ENABLED(CFG_VERSAL_FPGA_PM_DRIVER))
		return versal_sip_call(PM_LOAD_PDI, PDI_SRC_DDR, pa, pa >> 32,
				       0, NULL);

	cmd.data[0] = PM_LOAD_PDI;
	cmd.data[1] = PDI_SRC_DDR;
	cmd.data[2] = pa >> 32;
	cmd.data[3] = pa;
	if (versal_mbox_notify(&cmd, NULL, NULL))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

TEE_Result versal_soc_version(uint8_t *version)
{
	struct versal_sip_payload payload = { };
	const uint32_t version_shift = 12;
	uint32_t res = 0;

	if (!version)
		return TEE_ERROR_BAD_PARAMETERS;

	res = versal_sip_call(PM_GET_CHIPID, 0, 0, 0, 0, &payload);
	if (res) {
		EMSG("Failed to retrieve version");
		return TEE_ERROR_GENERIC;
	}

	*version = payload.data[2] >> version_shift;

	return TEE_SUCCESS;
}
