// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto.h>
#include <se050.h>
#include <se050_utils.h>
#include <string.h>
#include <util.h>

/* exp: minimal amount of transient memory required to generate an RSA key */
#define TRANSIENT_MEMORY_THRESHOLD	0x140

#define NBR_OID			((uint32_t)(OID_MAX - OID_MIN))
#define IS_WATERMARKED(x)	(((x) & WATERMARKED(0)) == WATERMARKED(0))

static void delete_transient_objects(void)
{
	Se05xSession_t *ctx = NULL;
	uint8_t more = kSE05x_MoreIndicator_NA;
	uint8_t *list = NULL;
	size_t len = 1024;
	smStatus_t status  = SM_NOT_OK;
	uint16_t offset = 0;
	uint32_t id = 0;
	size_t i = 0;

	if (!se050_session)
		return;

	ctx = &se050_session->s_ctx;

	list = calloc(1, len);
	if (!list)
		return;
	do {
		status = Se05x_API_ReadIDList(ctx, offset, 0xFF, &more,
					      list, &len);
		if (status != SM_OK)
			break;

		offset = len;
		for (i = 0; i < len; i += 4) {
			id = (list[i + 0] << (3 * 8)) |
			     (list[i + 1] << (2 * 8)) |
			     (list[i + 2] << (1 * 8)) |
			     (list[i + 3] << (0 * 8));

			if (id >= OID_MAX || id == 0)
				continue;

			if (id & BIT(0))
				Se05x_API_DeleteSecureObject(ctx, id);
		}
	} while (more == kSE05x_MoreIndicator_MORE);

	free(list);
}

static sss_status_t generate_oid(sss_key_object_mode_t mode, uint32_t *val)
{
	uint32_t oid = OID_MIN;
	uint32_t random = 0;
	size_t i = 0;

	for (i = 0; i < NBR_OID; i++) {
		if (crypto_rng_read(&random, sizeof(random)))
			return kStatus_SSS_Fail;

		oid = OID_MIN + (random & OID_MAX);
		if (oid > OID_MAX)
			continue;

		if (mode == kKeyObject_Mode_Transient)
			oid |= BIT(0);
		else
			oid &= ~BIT(0);

		if (!se050_key_exists(oid, &se050_session->s_ctx)) {
			*val = oid;
			return kStatus_SSS_Success;
		}
	}

	return kStatus_SSS_Fail;
}

sss_status_t se050_get_oid(sss_key_object_mode_t mode, uint32_t *val)
{
	sss_status_t status = kStatus_SSS_Success;
	uint16_t mem_t = 0;

	if (!val)
		return kStatus_SSS_Fail;

	status = se050_get_free_memory(&se050_session->s_ctx, &mem_t,
				       kSE05x_MemoryType_TRANSIENT_DESELECT);
	if (status != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	if (mem_t < TRANSIENT_MEMORY_THRESHOLD)
		delete_transient_objects();

	return generate_oid(mode, val);
}

static uint32_t se050_key(uint64_t key)
{
	uint32_t oid = (uint32_t)key;

	if (!IS_WATERMARKED(key))
		return 0;

	if (oid < OID_MIN || oid > OID_MAX)
		return 0;

	return oid;
}

uint32_t se050_rsa_keypair_from_nvm(struct rsa_keypair *key)
{
	uint64_t key_id = 0;

	if (!key)
		return 0;

	if (crypto_bignum_num_bytes(key->d) != sizeof(uint64_t))
		return 0;

	crypto_bignum_bn2bin(key->d, (uint8_t *)&key_id);

	return se050_key(key_id);
}

uint32_t se050_ecc_keypair_from_nvm(struct ecc_keypair *key)
{
	uint64_t key_id = 0;

	if (!key)
		return 0;

	if (crypto_bignum_num_bytes(key->d) != sizeof(uint64_t))
		return 0;

	crypto_bignum_bn2bin(key->d, (uint8_t *)&key_id);

	return se050_key(key_id);
}

uint64_t se050_generate_private_key(uint32_t oid)
{
	return WATERMARKED(oid);
}

void se050_refcount_init_ctx(uint8_t **cnt)
{
	if (!*cnt) {
		*cnt = calloc(1, sizeof(uint8_t));
		if (*cnt)
			**cnt = 1;
		else
			EMSG("can't allocate refcount");
	} else {
		**cnt = **cnt + 1;
	}
}

int se050_refcount_final_ctx(uint8_t *cnt)
{
	if (!cnt)
		return 1;

	if (!*cnt) {
		free(cnt);
		return 1;
	}

	*cnt = *cnt - 1;

	return 0;
}
