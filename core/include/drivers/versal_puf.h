/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#ifndef __DRIVERS_VERSAL_PUF_H
#define __DRIVERS_VERSAL_PUF_H

#include <platform_config.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#define VERSAL_PUF_REGISTRATION			0x0
#define VERSAL_PUF_REGEN_ON_DEMAND		0x1
#define VERSAL_PUF_REGEN_ID_ONLY		0x2
#define VERSAL_PUF_SHUTTER_VALUE		0x81000100
#define VERSAL_PUF_SYNDROME_MODE_4K		0x0
#define VERSAL_PUF_GLBL_VAR_FLTR_OPTION		1
#define VERSAL_PUF_READ_FROM_RAM		0
#define VERSAL_PUF_READ_FROM_EFUSE_CACHE	1
#define VERSAL_PUF_4K_PUF_SYN_LEN_IN_WORDS	140

#define VERSAL_PUF_EFUSE_SYN_WORDS		127
#define VERSAL_PUF_SYNDROME_WORDS		350
#define VERSAL_PUF_ID_WORDS			8
#define VERSAL_PUF_HASH_LEN			4
#define VERSAL_PUF_AUX_LEN			4

struct versal_puf_data {
	uint32_t syndrome_data[VERSAL_PUF_SYNDROME_WORDS];
	uint32_t chash;
	uint32_t aux;
	uint32_t puf_id[VERSAL_PUF_ID_WORDS];
	uint32_t efuse_syn_data[VERSAL_PUF_EFUSE_SYN_WORDS];
};

struct versal_puf_cfg {
	uint8_t reg_mode;
	uint8_t puf_operation;
	uint8_t global_var_filter;
	uint8_t read_option;
	uint32_t shutter_value;
};

struct versal_puf_data_req {
	uint8_t reg_mode;
	uint8_t puf_operation;
	uint8_t global_var_filter;
	uint8_t read_option;
	uint32_t shutter_value;
	uint64_t syndrome_data_addr;
	uint64_t hash_addr;
	uint64_t aux_addr;
	uint64_t puf_id_addr;
	uint64_t syndrome_addr;
	uint64_t efuse_syn_data_addr;
	uint8_t pad[8];
};

enum versal_puf_api {
	VERSAL_PUF_API_FEATURES = 0U,
	VERSAL_PUF_REGISTER,
	VERSAL_PUF_REGENERATE,
	VERSAL_PUF_CLEAR_ID,
};

#define __aligned_puf	__aligned(CACHELINE_LEN)

TEE_Result versal_puf_regenerate(struct versal_puf_data *buf,
				 struct versal_puf_cfg *cfg);
TEE_Result versal_puf_register(struct versal_puf_data *buf,
			       struct versal_puf_cfg *cfg);
TEE_Result versal_puf_check_api(enum versal_puf_api id);
TEE_Result versal_puf_clear_id(void);

#endif /* __DRIVERS_VERSAL_PUF_H */
