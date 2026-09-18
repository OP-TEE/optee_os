/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * QRNG hardware CTR_DRBG (AES-256, no derivation function) SWKAT-in-DRBG
 * register driver. Independent of hash_drbg.h/.c, which port the
 * software SP800-90A Hash_DRBG KAT.
 */
#ifndef QRNG_HW_KAT_H
#define QRNG_HW_KAT_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

#define QRNG_HW_KAT_ENTROPY_LEN	48
#define QRNG_HW_KAT_KEY_V_LEN	48
#define QRNG_HW_KAT_GEN_BLOCK_LEN	16

enum qrng_hw_kat_op {
	QRNG_HW_KAT_OP_INSTANTIATE,
	QRNG_HW_KAT_OP_RESEED,
	QRNG_HW_KAT_OP_GENERATE,
};

TEE_Result qrng_hw_kat_enter_test_mode(void);

void qrng_hw_kat_exit_test_mode(void);

/*
 * Not yet confirmed on real hardware: the SWKAT_TESTMODE_SEL encoding
 * for Reseed/Generate is inferred, and GEN_OUT only returns the last
 * 128 bits of a Generate call's output. See qrng_hw_kat.c.
 */
TEE_Result qrng_hw_kat_run_op(enum qrng_hw_kat_op op,
			      const uint8_t *entropy, size_t entropy_len,
			      const uint8_t *key_v_in, size_t key_v_in_len,
			      uint8_t *key_v_out, size_t key_v_out_len,
			      uint8_t *gen_out, size_t gen_out_len);

#endif /* QRNG_HW_KAT_H */
