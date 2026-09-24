// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * QRNG hardware CTR_DRBG SWKAT-in-DRBG register driver (QRNG HPG
 * section 3.3.2). Not yet confirmed on real hardware: the
 * SWKAT_TESTMODE_SEL encoding for Reseed/Generate is inferred (only
 * Instantiate = 2'b00 is unambiguously documented), and GEN_OUT only
 * exposes the last 128 bits of a 256-bit Generate call.
 */

#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <string.h>
#include <util.h>

#include "qrng_hw_kat.h"

#define QRNG_CM_REG_SIZE	0x1000

#define QRNG_CM_FIPS_TEST_MODE		0x10
#define QRNG_CM_FIPS_TEST_MODE_EN	BIT(0)

#define QRNG_CM_CONTROL				0x14
#define QRNG_CM_CONTROL_SOFT_RST			BIT(0)
#define QRNG_CM_CONTROL_ENABLE				BIT(1)
#define QRNG_CM_CONTROL_DRBG_RESEED_REQ		BIT(2)

#define QRNG_CM_DRBG_ERROR_STATUS	0x120

#define QRNG_CM_DRBG_KAT_STATUS			0x124
#define QRNG_CM_DRBG_KAT_STATUS_HWKAT_BUSY	BIT(0)
#define QRNG_CM_DRBG_KAT_STATUS_SWKAT_DONE	BIT(8)

#define QRNG_CM_DRBG_GEN_WORDS		0x138

#define QRNG_CM_DRBG_SWKAT_CONTROL			0x140
#define QRNG_CM_DRBG_SWKAT_CONTROL_EN			BIT(0)
#define QRNG_CM_DRBG_SWKAT_CONTROL_TESTMODE_SHIFT	1
#define QRNG_CM_DRBG_SWKAT_CONTROL_INSTANCE_SHIFT	8

#define QRNG_CM_DRBG_SWKAT_ENTROPY_IN(n)	(0x144 + 4 * (n))
#define QRNG_CM_DRBG_SWKAT_UPDATE_IN(n)		(0x174 + 4 * (n))
#define QRNG_CM_DRBG_SWKAT_UPDATE_OUT(n)	(0x1A4 + 4 * (n))
#define QRNG_CM_DRBG_SWKAT_GEN_OUT(n)		(0x1D4 + 4 * (n))

#define QRNG_CM_ENTROPY_WORDS	12
#define QRNG_CM_UPDATE_WORDS	12
#define QRNG_CM_GEN_OUT_WORDS	4

#define QRNG_CM_GEN_WORDS_VALUE	2

#define QRNG_CM_TIMEOUT_US	1000000

#define QRNG_CM_TESTMODE_INSTANTIATE	0
#define QRNG_CM_TESTMODE_RESEED		1
#define QRNG_CM_TESTMODE_GENERATE	2

#define QRNG_CM_SWKAT_INSTANCE	0

static struct {
	paddr_t pa;
	vaddr_t va;
} cm = {
	.pa = QCOM_RNG_CM_REG_BASE,
};

static TEE_Result poll_clear(size_t off, uint32_t mask)
{
	uint64_t to = timeout_init_us(QRNG_CM_TIMEOUT_US);

	while (io_read32(cm.va + off) & mask) {
		if (timeout_elapsed(to))
			return TEE_ERROR_BUSY;
	}

	return TEE_SUCCESS;
}

static TEE_Result poll_set(size_t off, uint32_t mask)
{
	uint64_t to = timeout_init_us(QRNG_CM_TIMEOUT_US);

	while (!(io_read32(cm.va + off) & mask)) {
		if (timeout_elapsed(to))
			return TEE_ERROR_BUSY;
	}

	return TEE_SUCCESS;
}

static void write_words(size_t base_off, const uint8_t *buf, size_t nwords)
{
	size_t i = 0;
	uint32_t w = 0;

	for (i = 0; i < nwords; i++) {
		memcpy(&w, buf + i * sizeof(w), sizeof(w));
		io_write32(cm.va + base_off + i * sizeof(w), w);
	}
}

static void read_words(size_t base_off, uint8_t *buf, size_t nwords)
{
	size_t i = 0;
	uint32_t w = 0;

	for (i = 0; i < nwords; i++) {
		w = io_read32(cm.va + base_off + i * sizeof(w));
		memcpy(buf + i * sizeof(w), &w, sizeof(w));
	}
}

TEE_Result qrng_hw_kat_enter_test_mode(void)
{
	TEE_Result res = TEE_SUCCESS;

	if (!cm.va)
		return TEE_ERROR_NOT_SUPPORTED;

	io_write32(cm.va + QRNG_CM_FIPS_TEST_MODE, QRNG_CM_FIPS_TEST_MODE_EN);
	io_write32(cm.va + QRNG_CM_CONTROL, QRNG_CM_CONTROL_ENABLE);

	res = poll_clear(QRNG_CM_DRBG_KAT_STATUS,
			 QRNG_CM_DRBG_KAT_STATUS_HWKAT_BUSY);
	if (res)
		return res;

	if (io_read32(cm.va + QRNG_CM_DRBG_ERROR_STATUS)) {
		io_write32(cm.va + QRNG_CM_CONTROL, 0);
		return TEE_ERROR_GENERIC;
	}

	io_write32(cm.va + QRNG_CM_DRBG_GEN_WORDS, QRNG_CM_GEN_WORDS_VALUE);

	return TEE_SUCCESS;
}

void qrng_hw_kat_exit_test_mode(void)
{
	if (!cm.va)
		return;

	io_write32(cm.va + QRNG_CM_FIPS_TEST_MODE, 0);
	io_write32(cm.va + QRNG_CM_CONTROL,
		   QRNG_CM_CONTROL_ENABLE | QRNG_CM_CONTROL_DRBG_RESEED_REQ);
}

TEE_Result qrng_hw_kat_run_op(enum qrng_hw_kat_op op,
			      const uint8_t *entropy, size_t entropy_len,
			      const uint8_t *key_v_in, size_t key_v_in_len,
			      uint8_t *key_v_out, size_t key_v_out_len,
			      uint8_t *gen_out, size_t gen_out_len)
{
	uint32_t testmode = 0;
	uint32_t ctrl = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!cm.va)
		return TEE_ERROR_NOT_SUPPORTED;
	if (!key_v_out || key_v_out_len != QRNG_HW_KAT_KEY_V_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (op) {
	case QRNG_HW_KAT_OP_INSTANTIATE:
		if (!entropy || entropy_len != QRNG_HW_KAT_ENTROPY_LEN)
			return TEE_ERROR_BAD_PARAMETERS;
		testmode = QRNG_CM_TESTMODE_INSTANTIATE;
		break;
	case QRNG_HW_KAT_OP_RESEED:
		if (!entropy || entropy_len != QRNG_HW_KAT_ENTROPY_LEN)
			return TEE_ERROR_BAD_PARAMETERS;
		if (!key_v_in || key_v_in_len != QRNG_HW_KAT_KEY_V_LEN)
			return TEE_ERROR_BAD_PARAMETERS;
		testmode = QRNG_CM_TESTMODE_RESEED;
		break;
	case QRNG_HW_KAT_OP_GENERATE:
		if (!key_v_in || key_v_in_len != QRNG_HW_KAT_KEY_V_LEN)
			return TEE_ERROR_BAD_PARAMETERS;
		if (!gen_out || gen_out_len != QRNG_HW_KAT_GEN_BLOCK_LEN)
			return TEE_ERROR_BAD_PARAMETERS;
		testmode = QRNG_CM_TESTMODE_GENERATE;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ctrl = SHIFT_U32(QRNG_CM_SWKAT_INSTANCE,
			 QRNG_CM_DRBG_SWKAT_CONTROL_INSTANCE_SHIFT) |
	       SHIFT_U32(testmode, QRNG_CM_DRBG_SWKAT_CONTROL_TESTMODE_SHIFT);
	io_write32(cm.va + QRNG_CM_DRBG_SWKAT_CONTROL, ctrl);

	if (op == QRNG_HW_KAT_OP_INSTANTIATE || op == QRNG_HW_KAT_OP_RESEED)
		write_words(QRNG_CM_DRBG_SWKAT_ENTROPY_IN(0), entropy,
			    QRNG_CM_ENTROPY_WORDS);

	if (op == QRNG_HW_KAT_OP_RESEED || op == QRNG_HW_KAT_OP_GENERATE)
		write_words(QRNG_CM_DRBG_SWKAT_UPDATE_IN(0), key_v_in,
			    QRNG_CM_UPDATE_WORDS);

	io_write32(cm.va + QRNG_CM_DRBG_SWKAT_CONTROL,
		   ctrl | QRNG_CM_DRBG_SWKAT_CONTROL_EN);
	udelay(1);
	io_write32(cm.va + QRNG_CM_DRBG_SWKAT_CONTROL, ctrl);

	res = poll_set(QRNG_CM_DRBG_KAT_STATUS,
		       QRNG_CM_DRBG_KAT_STATUS_SWKAT_DONE);
	if (res)
		return res;

	read_words(QRNG_CM_DRBG_SWKAT_UPDATE_OUT(0), key_v_out,
		   QRNG_CM_UPDATE_WORDS);

	if (op == QRNG_HW_KAT_OP_GENERATE)
		read_words(QRNG_CM_DRBG_SWKAT_GEN_OUT(0), gen_out,
			   QRNG_CM_GEN_OUT_WORDS);

	return TEE_SUCCESS;
}

static TEE_Result qrng_hw_kat_init(void)
{
	cm.va = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC, cm.pa,
					      QRNG_CM_REG_SIZE);
	if (!cm.va)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

early_init(qrng_hw_kat_init);
