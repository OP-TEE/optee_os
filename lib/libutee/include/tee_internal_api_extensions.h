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

#ifndef TEE_INTERNAL_API_EXTENSIONS_H
#define TEE_INTERNAL_API_EXTENSIONS_H

/* trace support */
#include <trace.h>
#include <stdio.h>
#include <tee_api_types.h>

/*
 * User mem module
 *
 */
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

#endif
