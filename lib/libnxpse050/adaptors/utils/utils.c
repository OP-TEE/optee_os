// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto.h>
#include <se050.h>
#include <string.h>

#define BIT(nr) (1UL << (nr))

/* base value for secure objects (transient and persistent) */
#define OID_MIN			((uint32_t)(0x00000001))
#define OID_MAX			((uint32_t)(OID_MIN + 0x7BFFFFFE))
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
	size_t nbr_pobj = 0, nbr_tobj = 0;
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
		if (status != SM_OK) {
			free(list);
			return;
		}

		offset = len;
		for (i = 0; i < len; i += 4) {
			id = (list[i + 0] << (3 * 8)) |
			     (list[i + 1] << (2 * 8)) |
			     (list[i + 2] << (1 * 8)) |
			     (list[i + 3] << (0 * 8));

			if (id >= OID_MAX || id == 0)
				continue;

			/* delete only transient objects */
			if (id & BIT(0)) {
				status = Se05x_API_DeleteSecureObject(ctx, id);
				if (status != SM_OK) {
					EMSG("Error erasing 0x%x", id);
				} else {
					nbr_tobj++;
					DMSG("Erased 0x%x", id);
				}
			} else {
				nbr_pobj++;
			}
		}
	} while (more == kSE05x_MoreIndicator_MORE);

	DMSG("Permanent objects in store %ld", nbr_pobj);
	IMSG("Transient objects deleted  %ld", nbr_tobj);

	free(list);
}

static uint32_t generate_oid(sss_key_object_mode_t mode)
{
	uint32_t oid = OID_MIN;
	uint32_t random = 0;
	size_t i = 0;

	for (i = 0; i < NBR_OID; i++) {
		if (crypto_rng_read(&random, sizeof(random)) != TEE_SUCCESS)
			return 0;

		random &= OID_MAX;

		oid = OID_MIN + random;
		if (oid > OID_MAX)
			continue;

		if (mode == kKeyObject_Mode_Transient)
			oid |= BIT(0);
		else
			oid &= ~BIT(0);

		if (!se050_key_exists(oid, &se050_session->s_ctx))
			return oid;
	}

	return 0;
}

/*
 *
 * @param mode
 * @param val
 *
 * @return sss_status_t
 */
sss_status_t se050_get_oid(sss_key_object_mode_t mode, uint32_t *val)
{
	sss_status_t status = kStatus_SSS_Success;
	uint16_t mem_t = 0, mem_p = 0;
	uint32_t oid = 0;

	if (!val)
		return kStatus_SSS_Fail;

	status = se050_get_free_memory(&se050_session->s_ctx, &mem_t,
				       kSE05x_MemoryType_TRANSIENT_DESELECT);
	if (status != kStatus_SSS_Success) {
		mem_t = 0;
		EMSG("failure retrieving transient free memory");
		return kStatus_SSS_Fail;
	}

	status = se050_get_free_memory(&se050_session->s_ctx, &mem_p,
				       kSE05x_MemoryType_PERSISTENT);
	if (status != kStatus_SSS_Success) {
		mem_p = 0;
		EMSG("failure retrieving persistent free memory");
		return kStatus_SSS_Fail;
	}

	/*
	 * rsa: when the amount of memory falls below these
	 * thresholds, we can no longer store RSA 2048 keys in the SE050
	 * meaning that we can no longer open a TA.
	 *
	 */
	if (mem_t < 0x140) {
		IMSG("low memory threshold hit, releasing transient memory");
		IMSG("free mem persistent 0x%x, transient 0x%x", mem_p, mem_t);
		delete_transient_objects();
	}

	oid = generate_oid(mode);
	if (!oid) {
		EMSG("can't access rng");
		return kStatus_SSS_Fail;
	}

	*val = oid;

	return kStatus_SSS_Success;
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

/*
 * Parse a DER formatted signature and extract the raw data
 * @param p
 * @param p_len
 */
void se050_signature_der2bin(uint8_t *p, size_t *p_len)
{
	uint8_t buffer[256] = { 0 };
	uint8_t *k, *output = p;
	size_t buffer_len = 0;
	size_t len = 0;

	if (!p || !p_len)
		return;

	p++;		/* tag: 0x30      */
	p++;		/* field: total len */
	p++;		/* tag: 0x02      */
	len = *p++;	/* field: r_len */

	if (*p == 0x00) { /* handle special case */
		len = len - 1;
		p++;
	}
	memcpy(buffer, p, len);

	p = p + len;
	p++;		/* tag: 0x2       */
	k = p;
	p++;		/* field: s_len     */

	if (*p == 0x00) { /* handle special case */
		*k = *k - 1;
		p++;
	}
	memcpy(buffer + len, p, *k);
	buffer_len = len + *k;

	memcpy(output, buffer, buffer_len);
	*p_len = buffer_len;
}

/*
 * @param signature
 * @param signature_len
 * @param raw
 * @param raw_len
 */
sss_status_t se050_signature_bin2der(uint8_t *signature, size_t *signature_len,
				     uint8_t *raw, size_t raw_len)
{
	size_t der_len =  6 + raw_len;
	size_t r_len = raw_len / 2;
	size_t s_len = raw_len / 2;

	if (*signature_len < der_len) {
		EMSG("ECDAA Signature buffer overflow");
		return kStatus_SSS_Fail;
	}

	if (raw_len != 48 && raw_len != 56 && raw_len != 64 && raw_len != 96) {
		EMSG("ECDAA Invalid length in bin signature %ld", raw_len);
		return kStatus_SSS_Fail;
	}

	*signature_len = der_len;

	signature[0] = 0x30;
	signature[1] = (uint8_t)(raw_len + 4);
	signature[2] = 0x02;
	signature[3] = (uint8_t)r_len;
	memcpy(&signature[4], &raw[0], r_len);

	signature[3 + r_len + 1] = 0x02;
	signature[3 + r_len + 2] = (uint8_t)s_len;
	memcpy(&signature[3 + r_len + 3], &raw[r_len], s_len);

	return kStatus_SSS_Success;
}

/*
 * @param cnt
 */
void se050_refcount_init_ctx(uint8_t **cnt)
{
	if (!*cnt) {
		*cnt = calloc(1, sizeof(uint8_t));
		if (*cnt)
			**cnt = 1;
	} else {
		**cnt = **cnt + 1;
	}
}

/*
 * @param cnt
 *
 * @return int
 */
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
