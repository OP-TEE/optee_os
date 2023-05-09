// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2022 NXP
 */
#include <drivers/imx_mu.h>
#include <drivers/imx_sc_api.h>
#include <imx-regs.h>
#include <initcall.h>
#include <kernel/mutex.h>
#include <mm/core_memprot.h>
#include <tee_api_types.h>
#include <trace.h>

#define RNG_INIT_RETRY 100

#define SC_RPC_VERSION 1
#define SC_RPC_MAX_MSG 8

/* Defines for struct sc_rpc_msg svc field */
#define SC_RPC_SVC_PM	2
#define SC_RPC_SVC_RM	3
#define SC_RPC_SVC_SECO 9

/* Define for PM function calls */
enum sc_pm_func {
	SC_PM_FUNC_SET_RESOURCE_POWER_MODE = 3
};

/* Defines for RM function calls */
enum sc_rm_func {
	SC_RM_FUNC_GET_PARTITION = 5,
	SC_RM_FUNC_ASSIGN_RESOURCE = 8
};

/* Define for SECO function calls */
enum sc_seco_func {
	SC_SECO_FUNC_START_RNG = 22
};

/* Internal SCFW API error codes */
enum sc_error {
	SC_ERR_NONE = 0,	/* Success */
	SC_ERR_VERSION,		/* Incompatible API version */
	SC_ERR_CONFIG,		/* Configuration error */
	SC_ERR_PARM,		/* Bad parameter */
	SC_ERR_NOACCESS,	/* Permission error (no access) */
	SC_ERR_LOCKED,		/* Permission error (locked) */
	SC_ERR_UNAVAILABLE,	/* Unavailable (out of resources) */
	SC_ERR_NOTFOUND,	/* Not found */
	SC_ERR_NOPOWER,		/* No power */
	SC_ERR_IPC,		/* Generic IPC error */
	SC_ERR_BUSY,		/* Resource is currently busy/active */
	SC_ERR_FAIL,		/* General I/O failure */
	SC_ERR_LAST
};

/* RNG SECO states */
enum sc_seco_rng_status {
	SC_SECO_RNG_STAT_UNAVAILABLE = 0,
	SC_SECO_RNG_STAT_INPROGRESS,
	SC_SECO_RNG_STAT_READY
};

/* Resources IDs */
enum sc_resource {
	SC_RES_CAAM_JR1 = 500,
	SC_RES_CAAM_JR2,
	SC_RES_CAAM_JR3,
	SC_RES_CAAM_JR1_OUT = 514,
	SC_RES_CAAM_JR2_OUT,
	SC_RES_CAAM_JR3_OUT,
	SC_RES_CAAM_JR0 = 519,
	SC_RES_CAAM_JR0_OUT,
	SC_RES_LAST = 546
};

/* Power modes */
enum sc_power_mode {
	SC_PM_PW_MODE_OFF = 0,
	SC_PM_PW_MODE_STBY,
	SC_PM_PW_MODE_LP,
	SC_PM_PW_MODE_ON
};

static vaddr_t secure_ipc_addr;

register_phys_mem(MEM_AREA_IO_SEC, SC_IPC_BASE_SECURE, SC_IPC_SIZE);

/*
 * Get the partition ID of secure world
 *
 * @partition Partition ID
 */
static TEE_Result sc_rm_get_partition(uint8_t *partition)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	enum sc_error err = SC_ERR_LAST;
	struct imx_mu_msg msg = {
		.header.version = SC_RPC_VERSION,
		.header.size = 1,
		.header.tag = SC_RPC_SVC_RM,
		.header.command = SC_RM_FUNC_GET_PARTITION,
	};

	res = imx_mu_call(secure_ipc_addr, &msg, true);
	if (res != TEE_SUCCESS) {
		EMSG("Communication error");
		return res;
	}

	err = msg.header.command;
	if (err != SC_ERR_NONE) {
		EMSG("Unable to get partition ID, sc_error: %d", err);
		return TEE_ERROR_GENERIC;
	}

	*partition = IMX_MU_DATA_U8(&msg, 0);

	return TEE_SUCCESS;
}

/*
 * Set the given power mode of a resource
 *
 * @resource	ID of the resource
 * @mode	Power mode to apply
 */
static TEE_Result sc_pm_set_resource_power_mode(enum sc_resource resource,
						enum sc_power_mode mode)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	enum sc_error scu_error = SC_ERR_LAST;
	struct imx_mu_msg msg = {
		.header.version = SC_RPC_VERSION,
		.header.size = 2,
		.header.tag = SC_RPC_SVC_PM,
		.header.command = SC_PM_FUNC_SET_RESOURCE_POWER_MODE,
	};

	IMX_MU_DATA_U16(&msg, 0) = (uint16_t)resource;
	IMX_MU_DATA_U8(&msg, 2) = (uint8_t)mode;

	res = imx_mu_call(secure_ipc_addr, &msg, true);
	if (res != TEE_SUCCESS) {
		EMSG("Communication error");
		return res;
	}

	scu_error = msg.header.command;
	if (scu_error != SC_ERR_NONE) {
		EMSG("Unable to set resource power mode sc_error: %d",
		     scu_error);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

/*
 * Assign ownership of a resource to the secure partition
 *
 * @resource Resource to assign
 */
static TEE_Result sc_rm_assign_resource(enum sc_resource resource)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	enum sc_error err = SC_ERR_LAST;
	uint8_t secure_partition = 0;
	struct imx_mu_msg msg = {
		.header.version = SC_RPC_VERSION,
		.header.size = 2,
		.header.tag = SC_RPC_SVC_RM,
		.header.command = SC_RM_FUNC_ASSIGN_RESOURCE,
	};

	res = sc_rm_get_partition(&secure_partition);
	if (res != TEE_SUCCESS) {
		EMSG("Cannot get secure partition ID");
		return res;
	}

	IMX_MU_DATA_U16(&msg, 0) = (uint16_t)resource;
	IMX_MU_DATA_U8(&msg, 2) = secure_partition;

	res = imx_mu_call(secure_ipc_addr, &msg, true);
	if (res != TEE_SUCCESS) {
		EMSG("Communication error");
		return res;
	}

	err = msg.header.command;
	if (err != SC_ERR_NONE) {
		EMSG("Unable to assign resource, sc_error: %d", err);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result imx_sc_rm_enable_jr(unsigned int jr_index)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	enum sc_resource jr_res = SC_RES_LAST;
	enum sc_resource jr_out_res = SC_RES_LAST;

	switch (jr_index) {
	case 0:
		jr_res = SC_RES_CAAM_JR0;
		jr_out_res = SC_RES_CAAM_JR0_OUT;
		break;

	case 1:
		jr_res = SC_RES_CAAM_JR1;
		jr_out_res = SC_RES_CAAM_JR1_OUT;
		break;

	case 2:
		jr_res = SC_RES_CAAM_JR2;
		jr_out_res = SC_RES_CAAM_JR2_OUT;
		break;

	case 3:
		jr_res = SC_RES_CAAM_JR3;
		jr_out_res = SC_RES_CAAM_JR3_OUT;
		break;

	default:
		EMSG("Wrong JR Index, should be 0, 1, 2 or 3");
		return TEE_ERROR_GENERIC;
	}

	/* Assign JR resources to secure world */
	res = sc_rm_assign_resource(jr_res);
	if (res != TEE_SUCCESS) {
		EMSG("Assign SC_R_CAAM_JR%u resource failed", jr_index);
		return res;
	}

	res = sc_rm_assign_resource(jr_out_res);
	if (res != TEE_SUCCESS) {
		EMSG("Assign SC_R_CAAM_JR%u_OUT resource failed", jr_index);
		return res;
	}

	/* Power ON JR resources */
	res = sc_pm_set_resource_power_mode(jr_res, SC_PM_PW_MODE_ON);
	if (res != TEE_SUCCESS) {
		EMSG("POWER ON SC_R_CAAM_JR%u resource failed", jr_index);
		return res;
	}

	res = sc_pm_set_resource_power_mode(jr_out_res, SC_PM_PW_MODE_ON);
	if (res != TEE_SUCCESS) {
		EMSG("POWER ON SC_R_CAAM_JR%u_OUT resource failed", jr_index);
		return res;
	}

	return TEE_SUCCESS;
}

TEE_Result imx_sc_seco_start_rng(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	enum sc_error err = SC_ERR_LAST;
	enum sc_seco_rng_status status = SC_SECO_RNG_STAT_UNAVAILABLE;
	unsigned int retry = 0;
	struct imx_mu_msg msg = {
		.header.version = SC_RPC_VERSION,
		.header.size = 1,
		.header.tag = SC_RPC_SVC_SECO,
		.header.command = SC_SECO_FUNC_START_RNG,
	};

	for (retry = RNG_INIT_RETRY; retry; retry--) {
		res = imx_mu_call(secure_ipc_addr, &msg, true);
		if (res != TEE_SUCCESS) {
			EMSG("Configuration error");
			return res;
		}

		err = msg.header.command;
		if (err != SC_ERR_NONE) {
			EMSG("RNG status: %d", err);
			return TEE_ERROR_GENERIC;
		}

		status = IMX_MU_DATA_U32(&msg, 0);

		if (status == SC_SECO_RNG_STAT_READY)
			return TEE_SUCCESS;
	}

	return TEE_ERROR_GENERIC;
}

TEE_Result imx_sc_driver_init(void)
{
	vaddr_t va = 0;

	va = core_mmu_get_va(SC_IPC_BASE_SECURE, MEM_AREA_IO_SEC, SC_IPC_SIZE);
	if (!va)
		return TEE_ERROR_GENERIC;

	imx_mu_init(va);
	secure_ipc_addr = va;

	return TEE_SUCCESS;
}
