/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#ifndef TEE_INTERNAL_API_EXTENSIONS_H
#define TEE_INTERNAL_API_EXTENSIONS_H

/* trace support */
#include <trace.h>
#include <stdio.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>

void tee_user_mem_mark_heap(void);
size_t tee_user_mem_check_heap(void);
/* Hint implementation defines */
#define TEE_USER_MEM_HINT_NO_FILL_ZERO       0x80000000

/*
 * Cache maintenance support (TA requires the CACHE_MAINTENANCE property)
 *
 * TEE_CacheClean() Write back to memory any dirty data cache lines. The line
 *                  is marked as not dirty. The valid bit is unchanged.
 *
 * TEE_CacheFlush() Purges any valid data cache lines. Any dirty cache lines
 *                  are first written back to memory, then the cache line is
 *                  invalidated.
 *
 * TEE_CacheInvalidate() Invalidate any valid data cache lines. Any dirty line
 *                       are not written back to memory.
 */
TEE_Result TEE_CacheClean(char *buf, size_t len);
TEE_Result TEE_CacheFlush(char *buf, size_t len);
TEE_Result TEE_CacheInvalidate(char *buf, size_t len);

/*
 * tee_map_zi() - Map zero initialized memory
 * @len:	Number of bytes
 * @flags:	0 or TEE_MEMORY_ACCESS_ANY_OWNER to allow sharing with other TAs
 *
 * Returns valid pointer on success or NULL on error.
 */
void *tee_map_zi(size_t len, uint32_t flags);

/*
 * tee_unmap() - Unmap previously mapped memory
 * @buf:	Buffer
 * @len:	Number of bytes
 *
 * Note that supplied @buf and @len has to match exactly what has
 * previously been returned by tee_map_zi().
 *
 * Return TEE_SUCCESS on success or TEE_ERRROR_* on failure.
 */
TEE_Result tee_unmap(void *buf, size_t len);

/*
 * Convert a UUID string @s into a TEE_UUID @uuid
 * Expected format for @s is: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
 * 'x' being any hexadecimal digit (0-9a-fA-F)
 */
TEE_Result tee_uuid_from_str(TEE_UUID *uuid, const char *s);

/*
 * tee_invoke_supp_plugin() - invoke a tee-supplicant's plugin
 * @uuid:       uuid of the plugin
 * @cmd:        command for the plugin
 * @sub_cmd:    subcommand for the plugin
 * @buf:        data [for/from] the plugin [in/out]
 * @len:        length of the input buf
 * @outlen:     pointer to length of the output data (if they will be used)
 *
 * Return TEE_SUCCESS on success or TEE_ERRROR_* on failure.
 */
TEE_Result tee_invoke_supp_plugin(const TEE_UUID *uuid, uint32_t cmd,
				  uint32_t sub_cmd, void *buf, size_t len,
				  size_t *outlen);

#endif
