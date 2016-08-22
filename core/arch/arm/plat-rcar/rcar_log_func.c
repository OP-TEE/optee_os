/*
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
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

#include <string.h>
#include <platform_config.h>
#include <kernel/misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/tz_proc_def.h>
#include <mm/core_mmu.h>
#include "rcar_log_func.h"
#include "rcar_common.h"
#include "rcar_version.h"

struct log_buf_header_t *log_secram_header;
static int8_t *log_nonsec_ptr;
uint32_t log_spin_lock;
int32_t is_normal_world_initialized;
const int8_t version_of_renesas[] __attribute__((__section__(".version"))) =
	VERSION_OF_RENESAS;

void log_buf_init(void)
{
	const int8_t secram_prefix[] = LOG_SEC_PREFIX;
	int32_t i;

	/* initialize global variable */
	log_secram_header = (struct log_buf_header_t *)OPTEE_LOG_BASE;
	log_nonsec_ptr = (int8_t *)OPTEE_LOG_NS_BASE;
	log_spin_lock = (uint32_t)SPINLOCK_UNLOCK;
	is_normal_world_initialized = 0;

	/* initialize SDRAM area */
	for (i = 0; i < LOG_SEC_PREFIX_LEN; i++) {
		if (secram_prefix[i] != log_secram_header->prefix[i]) {
			break;
		}
	}
	if ((i < LOG_SEC_PREFIX_LEN) ||
	    (log_secram_header->index >= LOG_AREA_MAX_SIZE)) {
		(void)memset((int8_t *)log_secram_header,
			0, sizeof(struct log_buf_header_t));
		(void)memcpy(log_secram_header->prefix,
			secram_prefix, sizeof(log_secram_header->prefix));
	}
}

void log_buf_write(const struct msg_block_t *msg_block, int32_t msg_block_num)
{
	int8_t *log_area = NULL;
	uint32_t end_index;
	size_t ram_wsize;
	size_t total_wsize = 0U;
	size_t index_wsize;
	size_t head_wsize;
	int32_t i;

	for (i = 0; i < msg_block_num; i++) {
		if ((log_secram_header == NULL) ||
		    (total_wsize >= LOG_AREA_MAX_SIZE)) {
			break;
		}
		if (log_area == NULL) {
			log_area = (int8_t *)(&log_secram_header[1]);
		}
		ram_wsize = msg_block[i].size;
		if ((total_wsize + ram_wsize) > LOG_AREA_MAX_SIZE) {
			ram_wsize = LOG_AREA_MAX_SIZE - total_wsize;
		}

		end_index = log_secram_header->index + ram_wsize;
		head_wsize = 0U;

		if (end_index > LOG_AREA_MAX_SIZE) {
			head_wsize = end_index - LOG_AREA_MAX_SIZE;
		}
		index_wsize = ram_wsize - head_wsize;

		(void)memcpy(&log_area[log_secram_header->index],
			&msg_block[i].addr[0], index_wsize);
		total_wsize += index_wsize;

		if (0U < head_wsize) {
			(void)memcpy(&log_area[0],
				&msg_block[i].addr[index_wsize], head_wsize);
			total_wsize += head_wsize;
			log_secram_header->index = head_wsize;
		} else {
			log_secram_header->index += index_wsize;
			if (log_secram_header->index == LOG_AREA_MAX_SIZE) {
				log_secram_header->index = 0U;
			}
		}

		if (log_secram_header->size < LOG_AREA_MAX_SIZE) {
			log_secram_header->size += index_wsize;
		}
	}
}

#ifdef RCAR_DEBUG_LOG
void log_debug_send(const struct msg_block_t *msg_block, int32_t msg_block_num)
{
	struct tee_ta_session *sess = NULL;
	struct teesmc32_param params;
	uint32_t cpu_id;
	int8_t *log_area;
	size_t log_offs = 0U;
	size_t memcpy_size;
	int32_t i;

	if (log_nonsec_ptr != NULL) {
		cpu_id = get_core_pos();
		log_area = &log_nonsec_ptr[cpu_id * LOG_NS_CPU_AREA_SIZE];

		for (i = 0; i < msg_block_num; i++) {
			memcpy_size = msg_block[i].size;
			if ((log_offs + memcpy_size) > LOG_SEND_MAX_SIZE) {
				memcpy_size = LOG_SEND_MAX_SIZE - log_offs;
			}
			(void)memcpy(&log_area[log_offs],
				msg_block[i].addr, memcpy_size);
			log_offs += memcpy_size;
		}
		log_area[log_offs] = (int8_t)'\0';

		tee_ta_get_current_session(&sess);
		if (sess != NULL) {
			tee_ta_set_current_session(NULL);
		}

		memset(&params, 0, sizeof(params));
		params.attr = TEESMC_ATTR_TYPE_VALUE_INPUT;
		params.u.value.a = cpu_id;
		params.u.value.b = 0U;

		thread_rpc_cmd(TEE_RPC_DEBUG_LOG, 1, &params);

		if (sess != NULL) {
			tee_ta_set_current_session(sess);
		}
	}
}
#endif
