/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __AUTH_PAS_SIG_H
#define __AUTH_PAS_SIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

#define PAS_SIG_MAX_HASH_SIZE		48U
#define PAS_SIG_MAX_SIG_SIZE		512U

TEE_Result pas_sig_verify_cert_chain(const uint8_t *chain_der,
				     size_t chain_der_len, bool eku_enforced,
				     uint32_t num_roots,
				     uint32_t root_cert_sel,
				     const uint8_t **leaf_der,
				     size_t *leaf_der_len,
				     const uint8_t **roots_der,
				     size_t *roots_der_len);

TEE_Result pas_sig_check_root_cert_index(uint32_t root_cert_sel,
					 uint32_t num_roots,
					 uint32_t activation_list,
					 uint32_t revocation_list);

TEE_Result pas_sig_check_root_of_trust(uint32_t rot_hash_algo,
				       size_t rot_hash_len,
				       const uint8_t *root_der,
				       size_t root_der_len,
				       const uint8_t *expected);

TEE_Result pas_sig_algo_from_leaf(const uint8_t *leaf_der,
				  size_t leaf_der_len, uint32_t *sig_algo,
				  uint32_t *sig_hash_algo);

TEE_Result pas_sig_verify_signature(uint32_t sig_algo,
				    uint32_t sig_hash_algo,
				    const uint8_t *leaf_der,
				    size_t leaf_der_len,
				    const uint8_t *msg, size_t msg_len,
				    const uint8_t *sig, size_t sig_len);

#endif /* __AUTH_PAS_SIG_H */
