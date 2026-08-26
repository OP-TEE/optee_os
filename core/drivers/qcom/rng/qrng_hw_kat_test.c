// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * QRNG hardware CTR_DRBG SWKAT-in-DRBG known-answer test, driven by the
 * ACVP vectors in qrng_hw_kat_vectors.h. GEN_OUT only exposes the last
 * 128 bits of a 256-bit Generate call, so only those 128 bits are
 * compared here -- see qrng_hw_kat.c.
 */

#include <initcall.h>
#include <kernel/panic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <tee_api_types.h>

#include "qrng_hw_kat.h"
#include "qrng_hw_kat_vectors.h"

static TEE_Result chk_report(TEE_Result res, const char *func, int line)
{
	if (res != TEE_SUCCESS)
		EMSG("QRNG_HW_KAT test FAILED at %s:%d res=0x%x",
		     func, line, res);

	return res;
}

#define CHK(expr)	chk_report((expr), __func__, __LINE__)

static TEE_Result
run_instantiate(const struct qrng_hw_kat_test_op *op, uint8_t *key_v)
{
	return CHK(qrng_hw_kat_run_op(QRNG_HW_KAT_OP_INSTANTIATE,
				      op->test.instantiate.entropy,
				      QRNG_HW_KAT_ENTROPY_LEN,
				      NULL, 0,
				      key_v, QRNG_HW_KAT_KEY_V_LEN,
				      NULL, 0));
}

static TEE_Result
run_reseed(const struct qrng_hw_kat_test_op *op, uint8_t *key_v)
{
	return CHK(qrng_hw_kat_run_op(QRNG_HW_KAT_OP_RESEED,
				      op->test.reseed.entropy,
				      QRNG_HW_KAT_ENTROPY_LEN,
				      key_v, QRNG_HW_KAT_KEY_V_LEN,
				      key_v, QRNG_HW_KAT_KEY_V_LEN,
				      NULL, 0));
}

static TEE_Result
run_generate(const struct qrng_hw_kat_test_op *op, uint8_t *key_v,
	     uint8_t *gen_out, uint32_t tc_id)
{
	const uint8_t *expected = NULL;
	const uint8_t *last_block = NULL;
	TEE_Result res = TEE_SUCCESS;

	res = CHK(qrng_hw_kat_run_op(QRNG_HW_KAT_OP_GENERATE,
				     NULL, 0,
				     key_v, QRNG_HW_KAT_KEY_V_LEN,
				     key_v, QRNG_HW_KAT_KEY_V_LEN,
				     gen_out, QRNG_HW_KAT_GEN_BLOCK_LEN));
	if (res != TEE_SUCCESS)
		return res;

	if (!op->test.generate.compare)
		return TEE_SUCCESS;

	expected = op->test.generate.expected_output;
	last_block = expected + (32 - QRNG_HW_KAT_GEN_BLOCK_LEN);

	if (memcmp(gen_out, last_block, QRNG_HW_KAT_GEN_BLOCK_LEN)) {
		EMSG("KAT tcId %u: generate output mismatch (last 128 bits)",
		     tc_id);
		return TEE_ERROR_SECURITY;
	}

	return TEE_SUCCESS;
}

static TEE_Result run_vector(const struct qrng_hw_kat_vector *vec)
{
	uint8_t key_v[QRNG_HW_KAT_KEY_V_LEN];
	uint8_t gen_out[QRNG_HW_KAT_GEN_BLOCK_LEN];
	TEE_Result res = TEE_SUCCESS;
	size_t j = 0;

	for (j = 0; j < vec->ops_len; j++) {
		const struct qrng_hw_kat_test_op *op = &vec->ops[j];

		switch (op->op) {
		case QRNG_HW_KAT_OP_INSTANTIATE:
			res = run_instantiate(op, key_v);
			if (res != TEE_SUCCESS)
				return res;
			break;

		case QRNG_HW_KAT_OP_RESEED:
			res = run_reseed(op, key_v);
			if (res != TEE_SUCCESS)
				return res;
			break;

		case QRNG_HW_KAT_OP_GENERATE:
			res = run_generate(op, key_v, gen_out, vec->tc_id);
			if (res != TEE_SUCCESS)
				return res;
			break;

		default:
			EMSG("KAT tcId %u: unknown op %d", vec->tc_id, op->op);
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result qrng_hw_kat_test_kat(void)
{
	const struct qrng_hw_kat_vector *vectors = NULL;
	size_t vectors_len = 0;
	TEE_Result res = TEE_SUCCESS;
	size_t i = 0;

	res = CHK(qrng_hw_kat_get_vectors(&vectors, &vectors_len));
	if (res != TEE_SUCCESS)
		return res;
	res = CHK(qrng_hw_kat_enter_test_mode());
	if (res != TEE_SUCCESS)
		return res;

	for (i = 0; i < vectors_len; i++) {
		res = CHK(run_vector(&vectors[i]));
		if (res != TEE_SUCCESS)
			return res;
	}

	qrng_hw_kat_exit_test_mode();
	IMSG("QRNG_HW_KAT: KAT sub-test PASSED (%zu vectors, partial verify)",
	     vectors_len);

	return TEE_SUCCESS;
}

static TEE_Result qcom_qrng_hw_kat_run_tests(void)
{
	TEE_Result res = TEE_SUCCESS;

	IMSG("QRNG_HW_KAT: starting tests");

	res = qrng_hw_kat_test_kat();
	if (res != TEE_SUCCESS)
		return res;

	IMSG("QRNG_HW_KAT: all tests PASSED");
	return TEE_SUCCESS;
}

static TEE_Result qrng_hw_kat_test_init(void)
{
	TEE_Result res = qcom_qrng_hw_kat_run_tests();

	if (res != TEE_SUCCESS)
		panic("QRNG_HW_KAT failed");

	return TEE_SUCCESS;
}

driver_init_late(qrng_hw_kat_test_init);
