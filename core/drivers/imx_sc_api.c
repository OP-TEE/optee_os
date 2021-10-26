// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2021 NXP
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

/* Macros to fill struct sc_rpc_msg data field */
#define RPC_U32(mesg, idx) ((mesg)->data.u32[(idx)])
#define RPC_U16(mesg, idx) ((mesg)->data.u16[(idx)])
#define RPC_U8(mesg, idx)  ((mesg)->data.u8[(idx)])

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

/* RPC message header */
struct sc_rpc_msg_header {
	uint8_t version;	/* SC RPC version */
	uint8_t size;		/* Size of the message */
	uint8_t svc;		/* Type of service: one of SC_RPC_SVC_* */
	uint8_t func;		/* Function ID or Error code */
};

/* RPC message format */
struct sc_rpc_msg {
	struct sc_rpc_msg_header header;
	union {
		uint32_t u32[SC_RPC_MAX_MSG - 1];
		uint16_t u16[(SC_RPC_MAX_MSG - 1) * 2];
		uint8_t u8[(SC_RPC_MAX_MSG - 1) * 4];
	} data;
};

static struct mutex scu_mu_mutex = MUTEX_INITIALIZER;
static vaddr_t secure_ipc_addr;

register_phys_mem(MEM_AREA_IO_SEC, SC_IPC_BASE_SECURE, SC_IPC_SIZE);

/*
 * Read a message from an IPC channel
 *
 * @ipc	IPC channel
 * @msg	Received message
 */
static TEE_Result sc_ipc_read(vaddr_t ipc, struct sc_rpc_msg *msg)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int count = 0;

	if (!msg) {
		EMSG("msg is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	assert(ipc);

	res = mu_receive_msg(ipc, 0, (uint32_t *)msg);
	if (res)
		return res;

	/* Check the size of the message to receive */
	if (msg->header.size > SC_RPC_MAX_MSG) {
		EMSG("Size of the message is > than SC_RPC_MAX_MSG");
		return TEE_ERROR_BAD_FORMAT;
	}

	for (count = 1; count < msg->header.size; count++) {
		res = mu_receive_msg(ipc, count % MU_NB_RR,
				     &msg->data.u32[count - 1]);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

/*
 * Write a message to an IPC channel
 *
 * @ipc	IPC channel
 * @msg	Send message pointer
 */
static TEE_Result sc_ipc_write(vaddr_t ipc, struct sc_rpc_msg *msg)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int count = 0;

	if (!msg) {
		EMSG("msg is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (msg->header.size > SC_RPC_MAX_MSG) {
		EMSG("msg->size is > than SC_RPC_MAX_MSG");
		return TEE_ERROR_BAD_FORMAT;
	}

	assert(ipc);

	res = mu_send_msg(ipc, 0, *(uint32_t *)msg);
	if (res)
		return res;

	for (count = 1; count < msg->header.size; count++) {
		res = mu_send_msg(ipc, count % MU_NB_TR,
				  msg->data.u32[count - 1]);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

/*
 * Send an RPC message over the secure world IPC channel
 *
 * @msg		Message to send. This pointer will also return the answer
 *		message if expected.
 * @wait_resp	Set to true if an answer is expected.
 */
static TEE_Result sc_call_rpc(struct sc_rpc_msg *msg, bool wait_resp)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	mutex_lock(&scu_mu_mutex);

	res = sc_ipc_write(secure_ipc_addr, msg);

	if (res == TEE_SUCCESS && wait_resp)
		res = sc_ipc_read(secure_ipc_addr, msg);

	mutex_unlock(&scu_mu_mutex);

	return res;
}

/*
 * Get the partition ID of secure world
 *
 * @partition Partition ID
 */
static TEE_Result sc_rm_get_partition(uint8_t *partition)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	enum sc_error err = SC_ERR_LAST;
	struct sc_rpc_msg msg = {
		.header.version = SC_RPC_VERSION,
		.header.size = 1,
		.header.svc = SC_RPC_SVC_RM,
		.header.func = SC_RM_FUNC_GET_PARTITION,
	};

	res = sc_call_rpc(&msg, true);
	if (res != TEE_SUCCESS) {
		EMSG("Communication error");
		return res;
	}

	err = msg.header.func;
	if (err != SC_ERR_NONE) {
		EMSG("Unable to get partition ID, sc_error: %d", err);
		return TEE_ERROR_GENERIC;
	}

	*partition = RPC_U8(&msg, 0);

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
	struct sc_rpc_msg msg = {
		.header.version = SC_RPC_VERSION,
		.header.size = 2,
		.header.svc = SC_RPC_SVC_PM,
		.header.func = SC_PM_FUNC_SET_RESOURCE_POWER_MODE,
	};

	RPC_U16(&msg, 0) = (uint16_t)resource;
	RPC_U8(&msg, 2) = (uint8_t)mode;

	res = sc_call_rpc(&msg, true);
	if (res != TEE_SUCCESS) {
		EMSG("Communication error");
		return res;
	}

	scu_error = msg.header.func;
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
	struct sc_rpc_msg msg = {
		.header.version = SC_RPC_VERSION,
		.header.size = 2,
		.header.svc = SC_RPC_SVC_RM,
		.header.func = SC_RM_FUNC_ASSIGN_RESOURCE,
	};

	res = sc_rm_get_partition(&secure_partition);
	if (res != TEE_SUCCESS) {
		EMSG("Cannot get secure partition ID");
		return res;
	}

	RPC_U16(&msg, 0) = (uint16_t)resource;
	RPC_U8(&msg, 2) = secure_partition;

	res = sc_call_rpc(&msg, true);
	if (res != TEE_SUCCESS) {
		EMSG("Communication error");
		return res;
	}

	err = msg.header.func;
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
	struct sc_rpc_msg msg = {
		.header.version = SC_RPC_VERSION,
		.header.size = 1,
		.header.svc = SC_RPC_SVC_SECO,
		.header.func = SC_SECO_FUNC_START_RNG,
	};

	for (retry = RNG_INIT_RETRY; retry; retry--) {
		res = sc_call_rpc(&msg, true);
		if (res != TEE_SUCCESS) {
			EMSG("Configuration error");
			return res;
		}

		err = msg.header.func;
		if (err != SC_ERR_NONE) {
			EMSG("RNG status: %d", err);
			return TEE_ERROR_GENERIC;
		}

		status = RPC_U32(&msg, 0);

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

	mutex_lock(&scu_mu_mutex);
	mu_init(va);
	secure_ipc_addr = va;
	mutex_unlock(&scu_mu_mutex);

	return TEE_SUCCESS;
}
