// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2021
 * Author: Jorge Ramirez <jorge@foundries.io>
 */
#include <config.h>
#include <drivers/zynqmp_csu.h>
#include <drivers/zynqmp_csu_aes.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

/* CSU AES registers */
#define AES_STS_OFFSET			0x00
#define AES_KEY_SRC_OFFSET		0x04
#define AES_KEY_LOAD_OFFSET		0x08
#define AES_START_MSG_OFFSET		0x0C
#define AES_RESET_OFFSET		0x10
#define AES_KEY_CLR_OFFSET		0x14
#define AES_CFG_OFFSET			0x18

#define AES_KEY_LOAD			1
#define AES_STS_AES_BUSY	        BIT(0)
#define AES_STS_AES_KEY_ZEROED		BIT(8)
#define AES_STS_KUP_ZEROED		BIT(9)
#define AES_STS_KEY_INIT_DONE		BIT(4)
#define AES_STS_GCM_TAG_OK		BIT(3)
#define AES_START_MSG			1
#define AES_CFG_ENC			1
#define AES_CFG_DEC			0
#define AES_RESET_SET			1
#define AES_RESET_CLR			0
#define AES_KEY_ZERO			BIT(0)
#define AES_KUP_ZERO			BIT(1)

#define AES_TIMEOUT_USEC		2000000

enum aes_op { AES_DEC, AES_ENC };

static TEE_Result aes_wait(uint32_t event, bool set)
{
	vaddr_t aes = core_mmu_get_va(ZYNQMP_CSU_AES_BASE, MEM_AREA_IO_SEC,
				      ZYNQMP_CSU_AES_SIZE);
	uint64_t tref = timeout_init_us(AES_TIMEOUT_USEC);
	uint32_t status = 0;

	if (!aes)
		return TEE_ERROR_GENERIC;

	while (!timeout_elapsed(tref)) {
		status = io_read32(aes + AES_STS_OFFSET) & event;
		if ((set && status == event) || (!set && status != event))
			return TEE_SUCCESS;
	}

	return TEE_ERROR_GENERIC;
}

static TEE_Result aes_transfer_enc(const void *src, void *dst, size_t dst_len,
				   void *tag, const void *iv)
{
	void *p = (uint8_t *)dst + dst_len - ZYNQMP_GCM_TAG_SIZE;
	uint8_t iv_padded[ZYNQMP_CSUDMA_MIN_SIZE] __aligned_csudma = { 0 };
	TEE_Result ret = TEE_SUCCESS;

	if (dst_len < ZYNQMP_GCM_TAG_SIZE) {
		EMSG("Invalid length");
		return TEE_ERROR_GENERIC;
	}

	ret = zynqmp_csudma_prepare();
	if (ret) {
		EMSG("DMA can't initialize");
		return ret;
	}

	/* Prepare destination */
	ret = zynqmp_csudma_transfer(ZYNQMP_CSUDMA_DST_CHANNEL, dst, dst_len,
				     0);
	if (ret) {
		EMSG("DMA transfer failed, invalid destination buffer");
		goto out;
	}

	/* Inputs */
	memcpy(iv_padded, iv, ZYNQMP_GCM_IV_SIZE);
	ret = zynqmp_csudma_transfer(ZYNQMP_CSUDMA_SRC_CHANNEL,
				     (void *)iv_padded, ZYNQMP_CSUDMA_MIN_SIZE,
				     0);
	if (ret) {
		EMSG("DMA transfer failed, invalid IV buffer");
		goto out;
	}

	ret = zynqmp_csudma_sync(ZYNQMP_CSUDMA_SRC_CHANNEL);
	if (ret) {
		EMSG("DMA IV transfer timeout");
		goto out;
	}

	ret = zynqmp_csudma_transfer(ZYNQMP_CSUDMA_SRC_CHANNEL,
				     (void *)src, dst_len - ZYNQMP_GCM_TAG_SIZE,
				     ZYNQMP_CSUDMA_DONE);
	if (ret) {
		EMSG("DMA transfer failed, invalid source buffer");
		goto out;
	}

	ret = zynqmp_csudma_sync(ZYNQMP_CSUDMA_SRC_CHANNEL);
	if (ret) {
		EMSG("DMA source transfer timeout");
		goto out;
	}

	/* Wait for completion */
	ret = zynqmp_csudma_sync(ZYNQMP_CSUDMA_DST_CHANNEL);
	if (ret) {
		EMSG("DMA destination transfer timeout");
		goto out;
	}

	/* Transfer the GCM tag */
	memcpy(tag, p, ZYNQMP_GCM_TAG_SIZE);
out:
	zynqmp_csudma_unprepare();

	return ret;
}

static TEE_Result aes_transfer_dec(const void *src, void *dst, size_t len,
				   const void *tag, const void *iv)
{
	uint8_t iv_padded[ZYNQMP_CSUDMA_MIN_SIZE] __aligned_csudma = { 0 };
	TEE_Result ret = TEE_SUCCESS;

	ret = zynqmp_csudma_prepare();
	if (ret) {
		EMSG("DMA can't initialize");
		return ret;
	}

	/* Prepare destination */
	ret = zynqmp_csudma_transfer(ZYNQMP_CSUDMA_DST_CHANNEL, dst, len, 0);
	if (ret) {
		EMSG("DMA transfer failed, invalid destination buffer");
		goto out;
	}

	/* Inputs */
	memcpy(iv_padded, iv, ZYNQMP_GCM_IV_SIZE);
	ret = zynqmp_csudma_transfer(ZYNQMP_CSUDMA_SRC_CHANNEL,
				     (void *)iv_padded, ZYNQMP_CSUDMA_MIN_SIZE,
				     0);
	if (ret) {
		EMSG("DMA transfer failed, invalid IV buffer");
		goto out;
	}

	ret = zynqmp_csudma_sync(ZYNQMP_CSUDMA_SRC_CHANNEL);
	if (ret) {
		EMSG("DMA IV transfer timeout");
		goto out;
	}

	ret = zynqmp_csudma_transfer(ZYNQMP_CSUDMA_SRC_CHANNEL, (void *)src,
				     len, ZYNQMP_CSUDMA_DONE);
	if (ret) {
		EMSG("DMA transfer failed, invalid source buffer");
		goto out;
	}

	ret = zynqmp_csudma_sync(ZYNQMP_CSUDMA_SRC_CHANNEL);
	if (ret) {
		EMSG("DMA source transfer timeout");
		goto out;
	}

	ret = zynqmp_csudma_transfer(ZYNQMP_CSUDMA_SRC_CHANNEL, (void *)tag,
				     ZYNQMP_GCM_TAG_SIZE, ZYNQMP_CSUDMA_DONE);
	if (ret) {
		EMSG("DMA transfer failed, invalid tag buffer");
		goto out;
	}

	ret = zynqmp_csudma_sync(ZYNQMP_CSUDMA_SRC_CHANNEL);
	if (ret) {
		EMSG("DMA tag transfer timeout");
		goto out;
	}

	/* Wait for completion*/
	ret = zynqmp_csudma_sync(ZYNQMP_CSUDMA_DST_CHANNEL);
	if (ret)
		EMSG("DMA destination transfer timeout");
out:
	zynqmp_csudma_unprepare();

	return ret;
}

static TEE_Result aes_prepare_op(enum aes_op op, enum zynqmp_csu_key key)
{
	vaddr_t aes = core_mmu_get_va(ZYNQMP_CSU_AES_BASE, MEM_AREA_IO_SEC,
				      ZYNQMP_CSU_AES_SIZE);
	vaddr_t csu = core_mmu_get_va(CSU_BASE, MEM_AREA_IO_SEC, CSU_SIZE);
	TEE_Result ret = TEE_SUCCESS;

	if (!aes || !csu)
		return TEE_ERROR_GENERIC;

	/* Connect DMA0 in/out to AES */
	io_write32(csu + ZYNQMP_CSU_SSS_CFG_OFFSET,
		   ZYNQMP_CSU_SSS_DMA0_STREAM_TO_AES);

	/* Reset the AES */
	io_write32(aes + AES_RESET_OFFSET, AES_RESET_SET);
	io_write32(aes + AES_RESET_OFFSET, AES_RESET_CLR);

	/* Load the key */
	io_write32(aes + AES_KEY_CLR_OFFSET, 0);
	io_write32(aes + AES_KEY_SRC_OFFSET, key);
	io_write32(aes + AES_KEY_LOAD_OFFSET, AES_KEY_LOAD);
	ret = aes_wait(AES_STS_KEY_INIT_DONE, true);
	if (ret) {
		EMSG("Timeout loading the key");
		return TEE_ERROR_GENERIC;
	}

	/* Configure operation */
	io_write32(aes + AES_CFG_OFFSET,
		   op == AES_DEC ? AES_CFG_DEC : AES_CFG_ENC);

	/* Prepare the CSU for the DMA */
	io_write32(csu + ZYNQMP_CSU_DMA_RESET_OFFSET, ZYNQMP_CSU_DMA_RESET_SET);
	io_write32(csu + ZYNQMP_CSU_DMA_RESET_OFFSET, ZYNQMP_CSU_DMA_RESET_CLR);

	/* Start the message */
	io_write32(aes + AES_START_MSG_OFFSET, AES_START_MSG);

	return TEE_SUCCESS;
}

static TEE_Result aes_done_op(enum aes_op op, TEE_Result ret)
{
	vaddr_t aes = core_mmu_get_va(ZYNQMP_CSU_AES_BASE, MEM_AREA_IO_SEC,
				      ZYNQMP_CSU_AES_SIZE);
	uint32_t val = 0;

	if (!aes)
		return TEE_ERROR_GENERIC;

	if (!ret && op == AES_DEC) {
		/* on decompression we must validate the GCM tag */
		val = io_read32(aes + AES_STS_OFFSET) & AES_STS_GCM_TAG_OK;
		if (!val) {
			EMSG("AES-GCM tag mismatch");
			return TEE_ERROR_GENERIC;
		}
	}

	val = io_read32(aes + AES_KEY_CLR_OFFSET);
	io_write32(aes + AES_KEY_CLR_OFFSET, val | AES_KEY_ZERO | AES_KUP_ZERO);
	if (aes_wait(AES_STS_AES_KEY_ZEROED | AES_STS_KUP_ZEROED, true))
		EMSG("Failed to clear the AES key");
	io_write32(aes + AES_KEY_CLR_OFFSET, val);

	io_write32(aes + AES_RESET_OFFSET, AES_RESET_SET);

	return ret;
}

TEE_Result zynqmp_csu_aes_decrypt_data(const void *src, size_t src_len,
				       void *dst, size_t dst_len,
				       const void *tag, size_t tag_len,
				       const void *iv,  size_t iv_len,
				       enum zynqmp_csu_key key)
{
	TEE_Result ret = TEE_SUCCESS;

	if (key != ZYNQMP_CSU_AES_KEY_SRC_DEV) {
		EMSG("Key type not supported");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (src_len % 4 || dst_len != src_len) {
		EMSG("Invalid source size");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (iv_len != ZYNQMP_GCM_IV_SIZE) {
		EMSG("Invalid IV size");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (tag_len != ZYNQMP_GCM_TAG_SIZE) {
		EMSG("Invalid tag size");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!src || !dst || !tag || !iv) {
		EMSG("Invalid input value");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = aes_prepare_op(AES_DEC, key);
	if (ret) {
		EMSG("Decrypt init failed");
		goto out;
	}

	ret = aes_transfer_dec(src, dst, src_len, tag, iv);
	if (ret) {
		EMSG("DMA transfer failed");
		goto out;
	}

	ret = aes_wait(AES_STS_AES_BUSY, false);
	if (ret)
		EMSG("AES-GCM transfer failed");
out:
	return aes_done_op(AES_DEC, ret);
}

TEE_Result zynqmp_csu_aes_encrypt_data(const void *src, size_t src_len,
				       void *dst, size_t dst_len,
				       void *tag, size_t tag_len,
				       const void *iv, size_t iv_len,
				       enum zynqmp_csu_key key)
{
	TEE_Result ret = TEE_SUCCESS;

	if (key != ZYNQMP_CSU_AES_KEY_SRC_DEV) {
		EMSG("Key type not supported");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (src_len % 4 || dst_len != ZYNQMP_CSU_AES_DST_LEN(src_len)) {
		EMSG("Invalid source size");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (iv_len != ZYNQMP_GCM_IV_SIZE) {
		EMSG("Invalid IV size");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (tag_len != ZYNQMP_GCM_TAG_SIZE) {
		EMSG("Invalid tag size");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!src || !dst || !tag || !iv) {
		EMSG("Invalid input value");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = aes_prepare_op(AES_ENC, key);
	if (ret) {
		EMSG("Encrypt init failed");
		goto out;
	}

	ret = aes_transfer_enc(src, dst, dst_len, tag, iv);
	if (ret) {
		EMSG("DMA transfer failed");
		goto out;
	}

	ret = aes_wait(AES_STS_AES_BUSY, false);
	if (ret)
		EMSG("AES transfer failed");
out:
	return aes_done_op(AES_ENC, ret);
}

static const char *const dt_ctrl_match_table[] = {
	"xlnx,zynqmp-aes",
};

TEE_Result zynqmp_csu_aes_dt_enable_secure_status(void)
{
	unsigned int i = 0;
	void *fdt = NULL;
	int node = -1;

	fdt = get_external_dt();
	if (!fdt)
		return TEE_SUCCESS;

	for (i = 0; i < ARRAY_SIZE(dt_ctrl_match_table); i++) {
		node = fdt_node_offset_by_compatible(fdt, 0,
						     dt_ctrl_match_table[i]);
		if (node >= 0)
			break;
	}

	if (node < 0)
		return TEE_SUCCESS;

	if (fdt_get_status(fdt, node) == DT_STATUS_DISABLED)
		return TEE_SUCCESS;

	if (dt_enable_secure_status(fdt, node)) {
		EMSG("Not able to set the AES-GCM DTB entry secure");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}
