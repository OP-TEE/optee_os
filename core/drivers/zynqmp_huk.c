// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 Foundries.io Ltd.
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <assert.h>
#include <drivers/zynqmp_csu_aes.h>
#include <drivers/zynqmp_csu_puf.h>
#include <drivers/zynqmp_pm.h>
#include <io.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <utee_defines.h>

static struct {
	uint8_t key[HW_UNIQUE_KEY_LENGTH];
	bool ready;
} huk;

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	vaddr_t csu = core_mmu_get_va(CSU_BASE, MEM_AREA_IO_SEC, CSU_SIZE);
	uint8_t src[HW_UNIQUE_KEY_LENGTH] __aligned_csuaes = { 0 };
	uint8_t iv[ZYNQMP_EFUSE_MEM(DNA)] __aligned_efuse = { 0 };
	uint8_t tag[ZYNQMP_GCM_TAG_SIZE] __aligned_csuaes = { 0 };
	uint8_t sha[HW_UNIQUE_KEY_LENGTH] = { 0 };
	uint8_t dst[ZYNQMP_CSU_AES_DST_LEN(sizeof(src))]
		__aligned_csuaes = { 0 };
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint32_t status = 0;

	if (huk.ready)
		goto out;

	COMPILE_TIME_ASSERT(ZYNQMP_EFUSE_LEN(DNA) == ZYNQMP_GCM_IV_SIZE);

	ret = zynqmp_efuse_read(iv, sizeof(iv), DNA, false);
	if (ret) {
		EMSG("Can't read the DNA eFuse");
		return ret;
	}

	if (tee_hash_createdigest(TEE_ALG_SHA256, iv, ZYNQMP_EFUSE_LEN(DNA),
				  src, sizeof(src))) {
		EMSG("Can't generate the SHA256 for the DNA eFuse");
		return ret;
	}

	status = io_read32(csu + ZYNQMP_CSU_STATUS_OFFSET);
	if (!(status & ZYNQMP_CSU_STATUS_AUTH)) {
		/* The DNA is a unique identifier valid but not secure */
		IMSG("CSU authentication disabled, using development HUK");
		memcpy(huk.key, src, sizeof(huk.key));
		huk.ready = true;
		goto out;
	}

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
		return ret;
	}

	memcpy(sha, src, sizeof(sha));
	/* The dst buffer must be large enough to include the generated tag */
	ret = zynqmp_csu_aes_encrypt_data(src, sizeof(src), dst, sizeof(dst),
					  tag, sizeof(tag), iv,
					  ZYNQMP_EFUSE_LEN(DNA),
					  ZYNQMP_CSU_AES_KEY_SRC_DEV);
	if (ret) {
		EMSG("Can't encrypt DNA, please make sure PUF was registered");
		return ret;
	}

	/* regenerate the PUF KEK */
	ret = zynqmp_csu_puf_regenerate();
	if (ret) {
		EMSG("PUF regeneration error");
		return ret;
	}

	memset(src, 0, sizeof(src));
	/* Ignore the tag data from the dst buffer - pass a smaller size */
	ret = zynqmp_csu_aes_decrypt_data(dst, sizeof(src), src, sizeof(src),
					  tag, sizeof(tag), iv,
					  ZYNQMP_EFUSE_LEN(DNA),
					  ZYNQMP_CSU_AES_KEY_SRC_DEV);
	if (ret) {
		EMSG("Can't decrypt DNA, please make sure PUF was registered");
		return ret;
	}

	if (memcmp(src, sha, sizeof(sha))) {
		EMSG("PUF not ready, can't create HUK");
		return TEE_ERROR_GENERIC;
	}

	IMSG("HUK ready");
	/*
	 * The HUK is the SHA-256 DNA eFUSE string AES-GCM encrypted with the
	 * PUF KEK using the DNA eFUSE string as the IV.
	 */
	memcpy(huk.key, dst, sizeof(huk.key));
	huk.ready = true;
out:
	memcpy(hwkey->data, huk.key, HW_UNIQUE_KEY_LENGTH);

	return TEE_SUCCESS;
}
