// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * NIST SP800-90A Hash_DRBG Known-Answer Tests, ported from QTEE
 * tzbsp_test_tmecom.c::TestSwDrbg().
 */

#include <initcall.h>
#include <kernel/panic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <tee_api_types.h>

#include "hash_drbg.h"
#include "hash_drbg_kat_vectors.h"

#define TEST_GENERATE_BUF_SIZE	256

static TEE_Result chk_report(TEE_Result res, const char *func, int line)
{
	if (res != TEE_SUCCESS)
		EMSG("HASH_DRBG test FAILED at %s:%d res=0x%x",
		     func, line, res);

	return res;
}

#define CHK(expr)	chk_report((expr), __func__, __LINE__)

struct drbg_state_snapshot {
	uint64_t reseed_counter;
	uint8_t  V[HASH_DRBG_SEED_LEN];
	uint8_t  C[HASH_DRBG_SEED_LEN];
};

static TEE_Result get_working_state(struct drbg_state_snapshot *s)
{
	if (!s)
		return TEE_ERROR_BAD_PARAMETERS;
	return hash_drbg_test_get_state(&s->reseed_counter,
					s->V, HASH_DRBG_SEED_LEN,
					s->C, HASH_DRBG_SEED_LEN);
}

static TEE_Result hash_drbg_test_get_random(void)
{
	const size_t num_tests = 100;
	uint8_t output[TEST_GENERATE_BUF_SIZE];
	TEE_Result res = TEE_SUCCESS;
	size_t i = 0;

	for (i = 1; i <= num_tests; i++) {
		size_t nbytes = (TEST_GENERATE_BUF_SIZE * i) / num_tests;

		res = CHK(hash_drbg_get_random(output, nbytes));
		if (res != TEE_SUCCESS)
			return res;
	}

	IMSG("HASH_DRBG: get_random sub-test PASSED (%zu iterations)",
	     num_tests);
	return TEE_SUCCESS;
}

static TEE_Result
run_instantiate(size_t i, const struct hash_drbg_kat_instantiate_op *inst,
		struct drbg_state_snapshot *state)
{
	TEE_Result res = TEE_SUCCESS;

	res = CHK(hash_drbg_test_instantiate(inst->entropy, inst->entropy_len,
					     inst->nonce, inst->nonce_len));
	if (res != TEE_SUCCESS)
		return res;
	res = CHK(get_working_state(state));
	if (res != TEE_SUCCESS)
		return res;

	if (memcmp(state->V, inst->V, HASH_DRBG_SEED_LEN) ||
	    memcmp(state->C, inst->C, HASH_DRBG_SEED_LEN) ||
	    state->reseed_counter != inst->reseed_counter) {
		EMSG("KAT vec[%zu] instantiate state mismatch", i);
		hash_drbg_uninstantiate();
		return TEE_ERROR_SECURITY;
	}

	return TEE_SUCCESS;
}

static TEE_Result
run_generate(size_t i, const struct hash_drbg_kat_generate_op *gen,
	     struct drbg_state_snapshot *state, uint8_t *output,
	     size_t output_size)
{
	TEE_Result res = TEE_SUCCESS;

	if (gen->output_len > output_size) {
		EMSG("KAT vec[%zu] output_len %zu > buf %zu",
		     i, gen->output_len, output_size);
		hash_drbg_uninstantiate();
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = CHK(hash_drbg_test_generate(gen->additional_input,
					  gen->additional_input_len,
					  output, gen->output_len));
	if (res != TEE_SUCCESS)
		return res;
	res = CHK(get_working_state(state));
	if (res != TEE_SUCCESS)
		return res;

	if (memcmp(state->V, gen->V, HASH_DRBG_SEED_LEN) ||
	    memcmp(state->C, gen->C, HASH_DRBG_SEED_LEN) ||
	    state->reseed_counter != gen->reseed_counter) {
		EMSG("KAT vec[%zu] generate state mismatch", i);
		hash_drbg_uninstantiate();
		return TEE_ERROR_SECURITY;
	}

	if (gen->output && memcmp(output, gen->output, gen->output_len)) {
		EMSG("KAT vec[%zu] generate output mismatch", i);
		hash_drbg_uninstantiate();
		return TEE_ERROR_SECURITY;
	}

	return TEE_SUCCESS;
}

static TEE_Result
run_reseed(size_t i, const struct hash_drbg_kat_reseed_op *reseed,
	   struct drbg_state_snapshot *state)
{
	TEE_Result res = TEE_SUCCESS;

	res = CHK(hash_drbg_test_reseed(reseed->entropy, reseed->entropy_len,
					reseed->additional_input,
					reseed->additional_input_len));
	if (res != TEE_SUCCESS)
		return res;
	res = CHK(get_working_state(state));
	if (res != TEE_SUCCESS)
		return res;

	if (memcmp(state->V, reseed->V, HASH_DRBG_SEED_LEN) ||
	    memcmp(state->C, reseed->C, HASH_DRBG_SEED_LEN) ||
	    state->reseed_counter != reseed->reseed_counter) {
		EMSG("KAT vec[%zu] reseed state mismatch", i);
		hash_drbg_uninstantiate();
		return TEE_ERROR_SECURITY;
	}

	return TEE_SUCCESS;
}

static TEE_Result hash_drbg_test_kat(void)
{
	const struct hash_drbg_kat_vector *vectors = NULL;
	size_t vectors_len = 0;
	TEE_Result res = TEE_SUCCESS;
	size_t i = 0;
	size_t j = 0;
	uint8_t output[TEST_GENERATE_BUF_SIZE];

	res = CHK(hash_drbg_kat_get_vectors(&vectors, &vectors_len));
	if (res != TEE_SUCCESS)
		return res;
	res = CHK(hash_drbg_test_enable());
	if (res != TEE_SUCCESS)
		return res;

	for (i = 0; i < vectors_len; i++) {
		for (j = 0; j < vectors[i].ops_len; j++) {
			const struct hash_drbg_kat_op *op = &vectors[i].ops[j];
			struct drbg_state_snapshot state;

			switch (op->op) {
			case HASH_DRBG_KAT_OP_INSTANTIATE:
				res = run_instantiate(i, &op->test.instantiate,
						      &state);
				break;
			case HASH_DRBG_KAT_OP_GENERATE:
				res = run_generate(i, &op->test.generate,
						   &state, output,
						   sizeof(output));
				break;
			case HASH_DRBG_KAT_OP_RESEED:
				res = run_reseed(i, &op->test.reseed, &state);
				break;
			default:
				EMSG("KAT vec[%zu] unknown op %d", i, op->op);
				hash_drbg_uninstantiate();
				return TEE_ERROR_BAD_PARAMETERS;
			}

			if (res != TEE_SUCCESS)
				return res;
		}
	}

	hash_drbg_uninstantiate();
	IMSG("HASH_DRBG: KAT sub-test PASSED (%zu vectors)", vectors_len);
	return TEE_SUCCESS;
}

static TEE_Result hash_drbg_test_edge(void)
{
	uint8_t output[TEST_GENERATE_BUF_SIZE];
	struct drbg_state_snapshot state;
	uint8_t dummy[1] = { 0 };
	TEE_Result res = TEE_SUCCESS;

	res = CHK(hash_drbg_test_enable());
	if (res != TEE_SUCCESS)
		return res;
	res = CHK(hash_drbg_test_instantiate(entropy_0_0, entropy_0_0_len,
					     nonce_0_0, nonce_0_0_len));
	if (res != TEE_SUCCESS)
		return res;
	res = CHK(get_working_state(&state));
	if (res != TEE_SUCCESS)
		return res;

	if (memcmp(state.V, V_0_0, HASH_DRBG_SEED_LEN) ||
	    memcmp(state.C, C_0_0, HASH_DRBG_SEED_LEN) ||
	    state.reseed_counter != reseed_counter_0_0) {
		EMSG("EDGE (a): instantiate state mismatch");
		hash_drbg_uninstantiate();
		return TEE_ERROR_SECURITY;
	}

	res = CHK(hash_drbg_test_generate(NULL, 0, output, sizeof(output)));
	if (res != TEE_SUCCESS)
		return res;
	res = CHK(get_working_state(&state));
	if (res != TEE_SUCCESS)
		return res;

	if (memcmp(state.V, V_0_1, HASH_DRBG_SEED_LEN) ||
	    memcmp(state.C, C_0_1, HASH_DRBG_SEED_LEN) ||
	    state.reseed_counter != reseed_counter_0_1) {
		EMSG("EDGE (a): first generate state mismatch");
		hash_drbg_uninstantiate();
		return TEE_ERROR_SECURITY;
	}

	res = CHK(hash_drbg_test_generate(NULL, 0, output, sizeof(output)));
	if (res != TEE_SUCCESS)
		return res;
	res = CHK(get_working_state(&state));
	if (res != TEE_SUCCESS)
		return res;

	if (memcmp(state.V, V_0_2, HASH_DRBG_SEED_LEN) ||
	    memcmp(state.C, C_0_2, HASH_DRBG_SEED_LEN) ||
	    state.reseed_counter != reseed_counter_0_2 ||
	    memcmp(output, output_0_2, sizeof(output))) {
		EMSG("EDGE (a): second generate state/output mismatch");
		hash_drbg_uninstantiate();
		return TEE_ERROR_SECURITY;
	}

	hash_drbg_uninstantiate();

	res = CHK(hash_drbg_test_enable());
	if (res != TEE_SUCCESS)
		return res;
	res = CHK(hash_drbg_test_instantiate(entropy_30_0, entropy_30_0_len,
					     nonce_30_0, nonce_30_0_len));
	if (res != TEE_SUCCESS)
		return res;
	res = CHK(get_working_state(&state));
	if (res != TEE_SUCCESS)
		return res;

	if (memcmp(state.V, V_30_0, HASH_DRBG_SEED_LEN) ||
	    memcmp(state.C, C_30_0, HASH_DRBG_SEED_LEN) ||
	    state.reseed_counter != reseed_counter_30_0) {
		EMSG("EDGE (b): instantiate state mismatch");
		hash_drbg_uninstantiate();
		return TEE_ERROR_SECURITY;
	}

	res = CHK(hash_drbg_test_reseed(entropy_30_1, entropy_30_1_len,
					dummy, 0));
	if (res != TEE_SUCCESS)
		return res;
	res = CHK(get_working_state(&state));
	if (res != TEE_SUCCESS)
		return res;

	if (memcmp(state.V, V_30_1, HASH_DRBG_SEED_LEN) ||
	    memcmp(state.C, C_30_1, HASH_DRBG_SEED_LEN) ||
	    state.reseed_counter != reseed_counter_30_1) {
		EMSG("EDGE (b): reseed state mismatch");
		hash_drbg_uninstantiate();
		return TEE_ERROR_SECURITY;
	}

	hash_drbg_uninstantiate();
	IMSG("HASH_DRBG: edge-case sub-test PASSED");
	return TEE_SUCCESS;
}

static TEE_Result qcom_hash_drbg_run_tests(void)
{
	TEE_Result res = TEE_SUCCESS;

	IMSG("HASH_DRBG: starting tests");

	res = hash_drbg_test_get_random();
	if (res != TEE_SUCCESS)
		return res;

	res = hash_drbg_test_kat();
	if (res != TEE_SUCCESS)
		return res;

	res = hash_drbg_test_edge();
	if (res != TEE_SUCCESS)
		return res;

	IMSG("HASH_DRBG: all tests PASSED");
	return TEE_SUCCESS;
}

static TEE_Result hash_drbg_kat_init(void)
{
	TEE_Result res = qcom_hash_drbg_run_tests();

	if (res != TEE_SUCCESS)
		panic("HASH_DRBG KAT failed");

	return TEE_SUCCESS;
}

driver_init_late(hash_drbg_kat_init);
