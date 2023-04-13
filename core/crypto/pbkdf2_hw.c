// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2022, HiSilicon Limited. */

#include <crypto/crypto.h>
#include <crypto/pbkdf2_support.h>

/* This is a hardware pbkdf2 function, without mac simulation */
TEE_Result __weak hw_pbkdf2(uint32_t hash_id __unused,
			    const uint8_t *password __unused,
			    size_t password_len __unused,
			    const uint8_t *salt __unused,
			    size_t salt_len __unused,
			    uint32_t iteration_count __unused,
			    uint8_t *derived_key __unused,
			    size_t derived_key_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
