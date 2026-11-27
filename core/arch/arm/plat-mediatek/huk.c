// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, BayLibre
 */

#include <compiler.h>
#include <inttypes.h>
#include <io.h>
#include <kernel/tee_common_otp.h>
#include <kernel/thread.h>
#include <stdbool.h>
#include <string_ext.h>
#include <trace.h>
#include <util.h>

/* Secure EL1 SiP service: a0 is the word count, a1-a4 contain the key. */
#define MTK_SIP_GET_HUK		0x82000010
#define MTK_HUK_WORDS		4

/* Reject predictable output instead of deriving storage keys from it. */
static bool huk_is_blank(const uint8_t *key, size_t len)
{
	uint8_t all_and = 0xff;
	uint8_t all_or = 0;
	size_t n = 0;

	for (n = 0; n < len; n++) {
		all_and &= key[n];
		all_or |= key[n];
	}

	return !all_or || all_and == 0xff;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	struct thread_smc_args args = { .a0 = MTK_SIP_GET_HUK };
	TEE_Result res = TEE_ERROR_NO_DATA;

	COMPILE_TIME_ASSERT(MTK_HUK_WORDS * sizeof(uint32_t) ==
			    HW_UNIQUE_KEY_LENGTH);
	memset(hwkey->data, 0, sizeof(hwkey->data));
	thread_smccc(&args);
	/* SMC32 call: only the low 32 bits of the result registers count */
	if ((uint32_t)args.a0 != MTK_HUK_WORDS) {
		EMSG("MTK_SIP_GET_HUK failed: %#"PRIx32, (uint32_t)args.a0);
		goto out;
	}

	/* Little-endian words, as the existing MediaTek firmware users store */
	put_unaligned_le32(hwkey->data, args.a1);
	put_unaligned_le32(hwkey->data + 4, args.a2);
	put_unaligned_le32(hwkey->data + 8, args.a3);
	put_unaligned_le32(hwkey->data + 12, args.a4);

	if (huk_is_blank(hwkey->data, sizeof(hwkey->data))) {
		EMSG("MTK_SIP_GET_HUK returned a blank key");
		memzero_explicit(hwkey->data, sizeof(hwkey->data));
		goto out;
	}

	res = TEE_SUCCESS;
out:
	memzero_explicit(&args, sizeof(args));
	return res;
}
