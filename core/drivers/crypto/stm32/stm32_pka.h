/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021-2024, STMicroelectronics - All Rights Reserved
 */

#ifndef STM32_PKA_H
#define STM32_PKA_H

#include <drivers/clk.h>
#include <drivers/rstctrl.h>
#include <kernel/mutex.h>
#include <mm/core_memprot.h>
#include <stdint.h>

#define PKA_MAX_ECC_LEN		640
#define PKA_MAX_ECC_SIZE	(PKA_MAX_ECC_LEN / 8)

enum stm32_pka_curve_id {
	PKA_NIST_P192,
	PKA_NIST_P224,
	PKA_NIST_P256,
	PKA_NIST_P384,
	PKA_NIST_P521,

	PKA_LAST_CID
};

/*
 * struct stm32_pka_bn - Internal representation of binary number
 *
 * @val: a byte array with most significant bytes first
 * @size: number of bytes in @val
 */
struct stm32_pka_bn {
	uint8_t *val;
	size_t size;
};

struct stm32_pka_point {
	struct stm32_pka_bn x;
	struct stm32_pka_bn y;
};

TEE_Result stm32_pka_get_max_size(size_t *bytes, size_t *bits,
				  const enum stm32_pka_curve_id cid);
TEE_Result stm32_pka_compute_montgomery(const struct stm32_pka_bn *n,
					const size_t n_len,
					struct stm32_pka_bn *r2modn);
TEE_Result stm32_pka_ecc_compute_montgomery(struct stm32_pka_bn *r2modn,
					    const enum stm32_pka_curve_id cid);
TEE_Result stm32_pka_is_point_on_curve(const struct stm32_pka_point *p,
				       const struct stm32_pka_bn *r2modn,
				       const enum stm32_pka_curve_id cid);
TEE_Result stm32_pka_ecc_scalar_mul(const struct stm32_pka_bn *k,
				    const struct stm32_pka_point *p,
				    struct stm32_pka_point *kp,
				    const enum stm32_pka_curve_id cid);
TEE_Result stm32_pka_edac_gen_pubkey(const struct stm32_pka_bn *k,
				     struct stm32_pka_point *pk,
				     const enum stm32_pka_curve_id cid);
TEE_Result stm32_pka_ecdsa_sign(const void *hash, unsigned int hash_size,
				struct stm32_pka_bn *sig_r,
				struct stm32_pka_bn *sig_s,
				const struct stm32_pka_bn *d,
				const struct stm32_pka_bn *k,
				const enum stm32_pka_curve_id cid);
TEE_Result stm32_pka_ecdsa_verif(const void *hash, unsigned int hash_size,
				 const struct stm32_pka_bn *sig_r,
				 const struct stm32_pka_bn *sig_s,
				 const struct stm32_pka_point *pk,
				 const enum stm32_pka_curve_id cid);
#endif /* STM32_PKA_H */
