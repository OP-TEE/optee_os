/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 *
 * GPCE hash driver definitions.
 */

#ifndef QCOM_GPCE_HASH_H
#define QCOM_GPCE_HASH_H

#include <stdbool.h>
#include <kernel/mutex.h>
#include <mm/core_memprot.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <utee_defines.h>
#include <util.h>

#include "ce_hal.h"
#include "util_blkbuf.h"

#define SHA1_DIGEST_SIZE	U(20)
#define CE_MAX_BLOCK_SIZE	U(64)
#define CE_HW_BLOCK_SIZE	U(16)

#define SHA1_INITIAL_H0	UINT32_C(0x67452301)
#define SHA1_INITIAL_H1	UINT32_C(0xefcdab89)
#define SHA1_INITIAL_H2	UINT32_C(0x98badcfe)
#define SHA1_INITIAL_H3	UINT32_C(0x10325476)
#define SHA1_INITIAL_H4	UINT32_C(0xc3d2e1f0)

#define INIT_DATA_CE_SHA1_h0	TEE_U32_TO_BIG_ENDIAN(SHA1_INITIAL_H0)
#define INIT_DATA_CE_SHA1_h1	TEE_U32_TO_BIG_ENDIAN(SHA1_INITIAL_H1)
#define INIT_DATA_CE_SHA1_h2	TEE_U32_TO_BIG_ENDIAN(SHA1_INITIAL_H2)
#define INIT_DATA_CE_SHA1_h3	TEE_U32_TO_BIG_ENDIAN(SHA1_INITIAL_H3)
#define INIT_DATA_CE_SHA1_h4	TEE_U32_TO_BIG_ENDIAN(SHA1_INITIAL_H4)

struct qce_dev_s {
	/* Serializes access to the Crypto Engine. */
	struct mutex mutex;
	vaddr_t base;
};

struct ce_sha_ctx_s {
	struct Blk_buf_s *iblk_h;
	struct ce_ctx *ce_ctx;
};

struct hash_ctx_s {
	size_t md_sz;
	uint32_t flags;
	struct qce_dev_s *dev;
	void *ctx;
	size_t ctx_sz;
};

#define HASH_GET_DIGEST_CTX(hash, type) ((type *)((hash)->ctx))
#define HASH_IS_CTX_NULL(ctx) (!(ctx))

TEE_Result SHA1_CE_HWIO_init(struct hash_ctx_s *me);
TEE_Result SHA_CMN_CE_init(struct hash_ctx_s *me);
TEE_Result SHA_CMN_CE_update(struct hash_ctx_s *me, const uint8_t *msg,
			     size_t msg_sz);
TEE_Result SHA_CMN_CE_final(struct hash_ctx_s *me, uint8_t *md, size_t md_sz);
TEE_Result SHA_CMN_CE_reset(struct hash_ctx_s *me);
TEE_Result SHA_CMN_CE_cleanup(struct hash_ctx_s *me);
TEE_Result SHA_CMN_CE_copy(struct hash_ctx_s *dst, struct hash_ctx_s *src);
TEE_Result SHA_CMN_HWIO_process_din(void *ctx, const uint8_t *buf,
				    size_t buf_sz, bool first,
				    bool last);

#endif /* QCOM_GPCE_HASH_H */
