/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef UTEE_TYPES_H
#define UTEE_TYPES_H

enum utee_property {
	UTEE_PROP_TEE_API_VERSION = 0,
	UTEE_PROP_TEE_DESCR,
	UTEE_PROP_TEE_DEV_ID,
	UTEE_PROP_TEE_SYS_TIME_PROT_LEVEL,
	UTEE_PROP_TEE_TA_TIME_PROT_LEVEL,
	UTEE_PROP_TEE_CRYPTOGRAPHY_ECC,
	UTEE_PROP_TEE_TS_ANTIROLL_PROT_LEVEL,
	UTEE_PROP_TEE_TRUSTEDOS_IMPL_VERSION,
	UTEE_PROP_TEE_TRUSTEDOS_IMPL_BIN_VERSION,
	UTEE_PROP_TEE_TRUSTEDOS_MANUFACTURER,
	UTEE_PROP_TEE_FW_IMPL_VERSION,
	UTEE_PROP_TEE_FW_IMPL_BIN_VERSION,
	UTEE_PROP_TEE_FW_MANUFACTURER,
	UTEE_PROP_CLIENT_ID,
	UTEE_PROP_TA_APP_ID,
};

enum utee_time_category {
	UTEE_TIME_CAT_SYSTEM = 0,
	UTEE_TIME_CAT_TA_PERSISTENT,
	UTEE_TIME_CAT_REE
};

/*
 * Cache operation types.
 * Used when extensions TEE_CacheClean() / TEE_CacheFlush() /
 * TEE_CacheInvalidate() are used
 */
enum utee_cache_operation {
	TEE_CACHECLEAN = 0,
	TEE_CACHEFLUSH,
	TEE_CACHEINVALIDATE,
};

#endif /* UTEE_TYPES_H */
