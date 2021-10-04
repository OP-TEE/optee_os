/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) Foundries Ltd. 2021
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef __DRIVERS_ZYNQMP_CSU_AES_H_
#define __DRIVERS_ZYNQMP_CSU_AES_H_

#include <drivers/zynqmp_csudma.h>
#include <types_ext.h>
#include <tee_api_types.h>

#define __aligned_csuaes	__aligned_csudma

#define ZYNQMP_GCM_TAG_SIZE	16
#define ZYNQMP_GCM_IV_SIZE	12

enum zynqmp_csu_key {
	ZYNQMP_CSU_AES_KEY_SRC_KUP = 0,
	ZYNQMP_CSU_AES_KEY_SRC_DEV
};

#define ZYNQMP_CSU_AES_DST_LEN(x) ((x) + ZYNQMP_GCM_TAG_SIZE)

TEE_Result zynqmp_csu_aes_encrypt_data(const void *src, size_t src_len,
				       void *dst, size_t dst_len,
				       void *tag, size_t tag_len,
				       const void *iv, size_t iv_len,
				       enum zynqmp_csu_key key);

TEE_Result zynqmp_csu_aes_decrypt_data(const void *src, size_t src_len,
				       void *dst, size_t len,
				       const void *tag, size_t tag_len,
				       const void *iv, size_t iv_len,
				       enum zynqmp_csu_key key);

TEE_Result zynqmp_csu_aes_dt_enable_secure_status(void);

#endif
