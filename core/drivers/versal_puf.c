// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <arm.h>
#include <drivers/versal_nvm.h>
#include <drivers/versal_mbox.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#include "drivers/versal_puf.h"

/* Protocol API with the remote processor */
#define PUF_MODULE_SHIFT	8
#define PUF_MODULE		12
#define PUF_API_ID(_id) ((PUF_MODULE << PUF_MODULE_SHIFT) | (_id))

#define __STR(X) #X
#define STR(X) __STR(X)

enum versal_puf_error {
	/* registration */
	ERROR_INVALID_PARAM = 0x02,
	ERROR_INVALID_SYNDROME_MODE = 0x03,
	ERROR_SYNDROME_WORD_WAIT_TIMEOUT = 0x04,
	ERROR_PUF_DONE_WAIT_TIMEOUT = 0x07,
	ERROR_REGISTRATION_INVALID = 0x08,
	SHUTTER_GVF_MISMATCH = 0x09,
	ERROR_SYN_DATA_ERROR = 0x0A,
	IRO_FREQ_WRITE_MISMATCH = 0x0B,
	/* regeneration */
	ERROR_CHASH_NOT_PROGRAMMED = 0x10,
	ERROR_PUF_STATUS_DONE_TIMEOUT = 0x11,
	ERROR_INVALID_REGENERATION_TYPE = 0x12,
	ERROR_INVALID_PUF_OPERATION = 0x13,
	ERROR_REGENERATION_INVALID = 0x14,
	ERROR_REGEN_PUF_HD_INVALID = 0x15,
	ERROR_INVALID_READ_HD_INPUT = 0x16,
	ERROR_PUF_DONE_KEY_NT_RDY = 0x17,
	ERROR_PUF_DONE_ID_NT_RDY = 0x18,
	ERROR_PUF_ID_ZERO_TIMEOUT = 0x19,
};

static const char *versal_puf_error(uint8_t err)
{
	struct {
		enum versal_puf_error error;
		const char *name;
	} elist[] = {
		/* registration */
		{ ERROR_INVALID_PARAM, STR(ERROR_INVALID_PARAM), },
		{ ERROR_INVALID_SYNDROME_MODE,
			STR(ERROR_INVALID_SYNDROME_MODE), },
		{ ERROR_SYNDROME_WORD_WAIT_TIMEOUT,
			STR(ERROR_SYNDROME_WORD_WAIT_TIMEOUT), },
		{ ERROR_PUF_DONE_WAIT_TIMEOUT,
			STR(ERROR_PUF_DONE_WAIT_TIMEOUT), },
		{ ERROR_REGISTRATION_INVALID,
			STR(ERROR_REGISTRATION_INVALID), },
		{ SHUTTER_GVF_MISMATCH, STR(SHUTTER_GVF_MISMATCH), },
		{ ERROR_SYN_DATA_ERROR, STR(ERROR_SYN_DATA_ERROR), },
		{ IRO_FREQ_WRITE_MISMATCH, STR(IRO_FREQ_WRITE_MISMATCH), },

		/* regeneration */
		{ ERROR_CHASH_NOT_PROGRAMMED,
			STR(ERROR_CHASH_NOT_PROGRAMMED), },
		{ ERROR_PUF_STATUS_DONE_TIMEOUT,
			STR(ERROR_PUF_STATUS_DONE_TIMEOUT), },
		{ ERROR_INVALID_REGENERATION_TYPE,
			STR(ERROR_INVALID_REGENERATION_TYPE), },
		{ ERROR_INVALID_PUF_OPERATION,
			STR(ERROR_INVALID_PUF_OPERATION), },
		{ ERROR_REGENERATION_INVALID,
			STR(ERROR_REGENERATION_INVALID), },
		{ ERROR_REGEN_PUF_HD_INVALID,
			STR(ERROR_REGEN_PUF_HD_INVALID), },
		{ ERROR_INVALID_READ_HD_INPUT,
			STR(ERROR_INVALID_READ_HD_INPUT) },
		{ ERROR_PUF_DONE_KEY_NT_RDY, STR(ERROR_PUF_DONE_KEY_NT_RDY), },
		{ ERROR_PUF_DONE_ID_NT_RDY, STR(ERROR_PUF_DONE_ID_NT_RDY), },
		{ ERROR_PUF_ID_ZERO_TIMEOUT, STR(ERROR_PUF_ID_ZERO_TIMEOUT), },
	};

	if (err <= ERROR_PUF_ID_ZERO_TIMEOUT && err >= ERROR_INVALID_PARAM) {
		if (elist[err - ERROR_INVALID_PARAM].name)
			return elist[err - ERROR_INVALID_PARAM].name;

		return "Invalid";
	}

	return "Unknown";
}

TEE_Result versal_puf_register(struct versal_puf_data *buf,
			       struct versal_puf_cfg *cfg)
{
	struct versal_puf_data_req req __aligned_puf  = { };
	struct versal_mbox_mem request = {
		.alloc_len = sizeof(req),
		.len = sizeof(req),
		.buf = &req,
	};
	struct versal_mbox_mem efuse_syn_data_addr = { };
	struct versal_mbox_mem syndrome_data_addr = { };
	struct versal_mbox_mem puf_id_addr = { };
	struct versal_mbox_mem hash_addr = { };
	struct versal_mbox_mem aux_addr = { };
	TEE_Result ret = TEE_SUCCESS;
	struct ipi_cmd arg = { };
	uint32_t err;

	versal_mbox_alloc(sizeof(buf->puf_id), buf->puf_id, &puf_id_addr);
	versal_mbox_alloc(sizeof(buf->chash), &buf->chash, &hash_addr);
	versal_mbox_alloc(sizeof(buf->aux), &buf->aux, &aux_addr);
	versal_mbox_alloc(sizeof(buf->efuse_syn_data), buf->efuse_syn_data,
			  &efuse_syn_data_addr);
	versal_mbox_alloc(sizeof(buf->syndrome_data), buf->syndrome_data,
			  &syndrome_data_addr);

	arg.ibuf[0].mem = request;
	arg.ibuf[1].mem = syndrome_data_addr;
	arg.ibuf[2].mem = hash_addr;
	arg.ibuf[3].mem = aux_addr;
	arg.ibuf[4].mem = puf_id_addr;
	arg.ibuf[5].mem = efuse_syn_data_addr;

	req.efuse_syn_data_addr = virt_to_phys(efuse_syn_data_addr.buf);
	req.syndrome_data_addr = virt_to_phys(syndrome_data_addr.buf);
	req.puf_id_addr = virt_to_phys(puf_id_addr.buf);
	req.hash_addr = virt_to_phys(hash_addr.buf);
	req.aux_addr = virt_to_phys(aux_addr.buf);

	req.global_var_filter = cfg->global_var_filter;
	req.shutter_value = cfg->shutter_value;
	req.puf_operation = cfg->puf_operation;
	req.read_option = cfg->read_option;
	req.reg_mode = cfg->reg_mode;

	arg.data[0] = PUF_API_ID(PUF_REGISTRATION);
	arg.data[1] = virt_to_phys(arg.ibuf[0].mem.buf);
	arg.data[2] = virt_to_phys(arg.ibuf[0].mem.buf) >> 32;

	if (versal_mbox_notify(&arg, NULL, &err)) {
		EMSG("Failed to register the PUF [%s]", versal_puf_error(err));
		ret = TEE_ERROR_GENERIC;
	}

	/* return the generated data */
	memcpy(buf->puf_id, puf_id_addr.buf, sizeof(buf->puf_id));
	memcpy(&buf->chash, hash_addr.buf, sizeof(buf->chash));
	memcpy(&buf->aux, aux_addr.buf, sizeof(buf->aux));
	memcpy(buf->efuse_syn_data, efuse_syn_data_addr.buf,
	       sizeof(buf->efuse_syn_data));
	memcpy(buf->syndrome_data, syndrome_data_addr.buf,
	       sizeof(buf->syndrome_data));

	free(syndrome_data_addr.buf);
	free(hash_addr.buf);
	free(aux_addr.buf);
	free(puf_id_addr.buf);
	free(efuse_syn_data_addr.buf);

	return ret;
}

TEE_Result versal_puf_regenerate(struct versal_puf_data *buf,
				 struct versal_puf_cfg *cfg)
{
	struct versal_puf_data_req req __aligned_puf  = { };
	struct versal_mbox_mem request = {
		.alloc_len = sizeof(req),
		.len = sizeof(req),
		.buf = &req,
	};
	struct versal_mbox_mem efuse_syn_data_addr = { };
	struct versal_mbox_mem syndrome_data_addr = { };
	struct versal_mbox_mem puf_id_addr = { };
	struct versal_mbox_mem hash_addr = { };
	struct versal_mbox_mem aux_addr = { };
	TEE_Result ret = TEE_SUCCESS;
	struct ipi_cmd arg = { };
	uint32_t err = 0;

	versal_mbox_alloc(sizeof(buf->puf_id), buf->puf_id, &puf_id_addr);
	versal_mbox_alloc(sizeof(buf->chash), &buf->chash, &hash_addr);
	versal_mbox_alloc(sizeof(buf->aux), &buf->aux, &aux_addr);
	versal_mbox_alloc(sizeof(buf->efuse_syn_data), buf->efuse_syn_data,
			  &efuse_syn_data_addr);
	versal_mbox_alloc(sizeof(buf->syndrome_data), buf->syndrome_data,
			  &syndrome_data_addr);

	arg.ibuf[0].mem = request;
	arg.ibuf[1].mem = syndrome_data_addr;
	arg.ibuf[2].mem = hash_addr;
	arg.ibuf[3].mem = aux_addr;
	arg.ibuf[4].mem = puf_id_addr;
	arg.ibuf[5].mem = efuse_syn_data_addr;

	req.efuse_syn_data_addr = virt_to_phys(efuse_syn_data_addr.buf);
	req.syndrome_addr = virt_to_phys(syndrome_data_addr.buf);
	req.puf_id_addr = virt_to_phys(puf_id_addr.buf);
	req.hash_addr = virt_to_phys(hash_addr.buf);
	req.aux_addr = virt_to_phys(aux_addr.buf);

	req.global_var_filter = cfg->global_var_filter;
	req.shutter_value = cfg->shutter_value;
	req.puf_operation = cfg->puf_operation;
	req.read_option = cfg->read_option;
	req.reg_mode = cfg->reg_mode;

	arg.data[0] = PUF_API_ID(PUF_REGENERATION);
	arg.data[1] = virt_to_phys(arg.ibuf[0].mem.buf);
	arg.data[2] = virt_to_phys(arg.ibuf[0].mem.buf) >> 32;

	if (versal_mbox_notify(&arg, NULL, &err)) {
		EMSG("Failed to regenerate [%s]", versal_puf_error(err));
		ret = TEE_ERROR_GENERIC;
	}

	/* return the updated puf id */
	memcpy(buf->puf_id, puf_id_addr.buf, sizeof(buf->puf_id));

	free(syndrome_data_addr.buf);
	free(hash_addr.buf);
	free(aux_addr.buf);
	free(puf_id_addr.buf);
	free(efuse_syn_data_addr.buf);

	return ret;
}

TEE_Result versal_puf_clear_id(void)
{
	struct ipi_cmd arg = { };

	arg.data[0] = PUF_API_ID(PUF_CLEAR_PUF_ID);

	if (versal_mbox_notify(&arg, NULL, NULL)) {
		EMSG("Failed to clear the PUFID");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result versal_puf_check_api(enum versal_puf_api id)
{
	struct ipi_cmd arg = { };

	arg.data[0] = PUF_API_ID(PUF_API_FEATURES);
	arg.data[1] = id;

	if (versal_mbox_notify(&arg, NULL, NULL))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
