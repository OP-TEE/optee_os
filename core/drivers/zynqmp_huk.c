// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 Foundries.io Ltd.
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <assert.h>
#include <drivers/zynqmp_csu_aes.h>
#include <drivers/zynqmp_csu_puf.h>
#include <drivers/zynqmp_huk.h>
#include <drivers/zynqmp_pm.h>
#include <io.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <string_ext.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <utee_defines.h>

static struct {
	uint8_t key[HW_UNIQUE_KEY_LENGTH];
	bool ready;
} huk;

__weak TEE_Result tee_zynqmp_get_device_dna(uint8_t *device_dna, size_t size)
{
	if (size != ZYNQMP_EFUSE_LEN(DNA))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Get Device DNA from the PS eFuses */
	return zynqmp_efuse_read(device_dna, size, DNA, false);
}

/*
 * Generate HUK source data
 *
 * Performs SHA256 over of data:
 * - Device DNA (from PL preferably)
 * - Selected user eFuses (HUK seed)
 *
 * HUK source data is later on AES encrypted with device key to shuffle source
 * data even further with secret key.
 *
 * Note: Even though the device key is secret used details for HUK source data
 * should not be exposed to REE environment.
 *
 * Note: You should not change HUK source data generation parameters after
 * devices have been deployed.
 *
 * @device_dna: Value of Device DNA
 * @device_dna_size: Size of Device DNA
 * @huk_source: Output buffer for HUK source data
 * @huk_source_size: Output buffer size for HUK source data
 * Return a TEE_Result compliant status
 */
static TEE_Result tee_zynqmp_generate_huk_src(const uint8_t *device_dna,
					      size_t device_dna_size,
					      uint8_t *huk_source,
					      size_t huk_source_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t user_efuse = 0;
	void *ctx = NULL;
	int i = 0;

	assert(device_dna_size == ZYNQMP_EFUSE_LEN(DNA));
	assert(huk_source_size == HW_UNIQUE_KEY_LENGTH);

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res)
		return res;

	res = crypto_hash_init(ctx);
	if (res)
		goto out;

	res = crypto_hash_update(ctx, device_dna, device_dna_size);
	if (res)
		goto out;

	/* Hash selected user eFuses */
	for (i = 0; i < (USER7 - USER0 + 1); i++) {
		if (CFG_ZYNQMP_HUK_USER_EFUSE_MASK & BIT(i)) {
			DMSG("Use User eFuse %d for HUK source data", i);

			res = zynqmp_efuse_read((uint8_t *)&user_efuse,
						sizeof(user_efuse), USER0 + i,
						false);
			if (res)
				goto out;

			res = crypto_hash_update(ctx, (uint8_t *)&user_efuse,
						 sizeof(user_efuse));
			if (res)
				goto out;
		}
	}

	res = crypto_hash_final(ctx, huk_source, huk_source_size);
out:
	crypto_hash_free_ctx(ctx);
	memzero_explicit(&user_efuse, sizeof(user_efuse));
	return res;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	vaddr_t csu = core_mmu_get_va(CSU_BASE, MEM_AREA_IO_SEC, CSU_SIZE);
	uint8_t device_dna[ZYNQMP_EFUSE_LEN(DNA)] = { 0 };
	uint8_t src[HW_UNIQUE_KEY_LENGTH] __aligned_csuaes = { 0 };
	uint8_t iv[ZYNQMP_GCM_IV_SIZE] = { 0 };
	uint8_t tag[ZYNQMP_GCM_TAG_SIZE] __aligned_csuaes = { 0 };
	uint8_t sha[HW_UNIQUE_KEY_LENGTH] = { 0 };
	uint8_t dst[ZYNQMP_CSU_AES_DST_LEN(sizeof(src))]
		__aligned_csuaes = { 0 };
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint32_t status = 0;

	static_assert(sizeof(device_dna) == ZYNQMP_GCM_IV_SIZE);

	if (huk.ready)
		goto out;

	ret = tee_zynqmp_get_device_dna(device_dna, sizeof(device_dna));
	if (ret) {
		EMSG("Can't read the Device DNA");
		goto cleanup;
	}

	status = io_read32(csu + ZYNQMP_CSU_STATUS_OFFSET);
	if (!(status & ZYNQMP_CSU_STATUS_AUTH)) {
		/* The DNA is a unique identifier valid but not secure */
		IMSG("CSU authentication disabled, using development HUK");

		/* Use hash of device DNA for development HUK */
		ret = tee_hash_createdigest(TEE_ALG_SHA256, device_dna,
					    sizeof(device_dna), huk.key,
					    sizeof(huk.key));
		if (ret) {
			EMSG("Can't generate the SHA256 for the DNA eFuse");
			goto cleanup;
		}

		huk.ready = true;
		goto out;
	}

	/* Use device DNA for IV */
	memcpy(iv, device_dna, sizeof(device_dna));

	/* Generate HUK source data */
	ret = tee_zynqmp_generate_huk_src(device_dna, sizeof(device_dna), src,
					  sizeof(src));
	if (ret) {
		EMSG("Failed to generate HUK source data");
		goto cleanup;
	}

#ifdef CFG_ZYNQMP_CSU_PUF
	/*
	 * Neither the PMUFW nor the PUF hardware provide an indication of the
	 * PUF KEK registration status. The verification algorithm that follows
	 * encrypts and then decrypts the resulting string regenerating the
	 * PUF KEK in between: if the outputs match, then the PUF KEK was
	 * registered properly and we can use it to generate the HUK.
	 */
	zynqmp_csu_puf_reset();

	ret = zynqmp_csu_puf_regenerate();
	if (ret) {
		EMSG("PUF regeneration error");
		goto cleanup;
	}
#endif

	memcpy(sha, src, sizeof(sha));
	/* The dst buffer must be large enough to include the generated tag */
	ret = zynqmp_csu_aes_encrypt_data(src, sizeof(src), dst, sizeof(dst),
					  tag, sizeof(tag), iv, sizeof(iv),
					  ZYNQMP_CSU_AES_KEY_SRC_DEV);
	if (ret) {
		EMSG("Can't encrypt DNA, please make sure PUF was registered");
		goto cleanup;
	}

#ifdef CFG_ZYNQMP_CSU_PUF
	/* regenerate the PUF KEK */
	ret = zynqmp_csu_puf_regenerate();
	if (ret) {
		EMSG("PUF regeneration error");
		goto cleanup;
	}
#endif
	memset(src, 0, sizeof(src));
	/* Ignore the tag data from the dst buffer - pass a smaller size */
	ret = zynqmp_csu_aes_decrypt_data(dst, sizeof(src), src, sizeof(src),
					  tag, sizeof(tag), iv,
					  ZYNQMP_EFUSE_LEN(DNA),
					  ZYNQMP_CSU_AES_KEY_SRC_DEV);
	if (ret) {
		EMSG("Can't decrypt DNA, please make sure PUF was registered");
		goto cleanup;
	}

	if (memcmp(src, sha, sizeof(sha))) {
		EMSG("PUF not ready, can't create HUK");
		ret = TEE_ERROR_GENERIC;
		goto cleanup;
	}

	IMSG("HUK ready");

	/*
	 * The HUK is the SHA-256 of Device DNA with optional User eFuses
	 * included and then AES-GCM encrypted with the selected Device Key
	 * using the Device DNA as the IV.
	 */
	memcpy(huk.key, dst, sizeof(huk.key));
	huk.ready = true;
out:
	memcpy(hwkey->data, huk.key, HW_UNIQUE_KEY_LENGTH);
	ret = TEE_SUCCESS;

cleanup:
	/* Cleanup stack memory so that there are no left overs */
	memzero_explicit(dst, sizeof(dst));
	memzero_explicit(sha, sizeof(sha));
	memzero_explicit(tag, sizeof(tag));
	memzero_explicit(iv, sizeof(iv));
	memzero_explicit(src, sizeof(src));
	memzero_explicit(device_dna, sizeof(device_dna));

	return ret;
}
