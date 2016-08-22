/*
 * Copyright (c) 2014, Linaro Limited
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
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <trace.h>
#include <arm.h>
#include <kernel/tee_time.h>
#include "rcar_log_func.h"
#include "rcar_common.h"

const char trace_ext_prefix[] = "TEE-CORE";
int trace_level = TRACE_LEVEL;
static uint32_t interrupt_ctx_log_flag = INTCTX_LOG_DEFAULT;

void trace_ext_puts(const char *str)
{
	int8_t time_buf[LOG_TIME_BUF_MAX_SIZE] = {0};
	size_t time_len = 0U;
	TEE_Time sys_time = {0U, 0U};
	TEE_Result ret;
	int32_t res;
	struct msg_block_t msg_block[MSG_BLK_MAX_NUM];
	int32_t msg_block_num = 0;
	uint32_t cpsr;
#ifdef RCAR_DEBUG_LOG
	const int8_t TERM_LOG_PREFIX[] = "[OP-TEE]";
	const size_t TERM_LOG_PREFIX_LEN = sizeof(TERM_LOG_PREFIX) - 1U;
	size_t log_sum_size = 0U;
	int32_t i;
#endif

	if ((str != NULL) && (log_secram_header != NULL)) {
		cpu_spin_lock_irqsave(&log_spin_lock, &cpsr);

		if ((interrupt_ctx_log_flag != INTCTX_LOG_NOT_OUTPUT) ||
		    ((cpsr & ARM32_CPSR_F) == 0U)) {
			ret = arm_cntpct_get_sys_time(&sys_time);
			if (ret == TEE_SUCCESS) {
				res = snprintf((char *)time_buf,
					sizeof(time_buf),
					"[%u.%06u][%d]",
					sys_time.seconds,
					sys_time.millis * 1000U,
					(int32_t)get_core_pos());
				if (0 < res) {
					time_len = (size_t)res;
				}
			}

			msg_block[SECRAM_IDX_TIME].addr = time_buf;
			msg_block[SECRAM_IDX_TIME].size = time_len;
			msg_block[SECRAM_IDX_MESG].addr = (const int8_t *)str;
			msg_block[SECRAM_IDX_MESG].size = strlen(str);
			msg_block_num = SECRAM_MSG_BLK_NUM;

			log_buf_write(msg_block, msg_block_num);
		}

		cpu_spin_unlock_irqrestore(&log_spin_lock, cpsr);

#ifdef RCAR_DEBUG_LOG
		if ((is_normal_world_initialized != 0) &&
		    (msg_block_num > 0)) {
			msg_block[TRMLOG_IDX_PRFX].addr = TERM_LOG_PREFIX;
			msg_block[TRMLOG_IDX_PRFX].size = TERM_LOG_PREFIX_LEN;
			msg_block[TRMLOG_IDX_TIME].addr = time_buf;
			msg_block[TRMLOG_IDX_TIME].size = time_len;
			msg_block[TRMLOG_IDX_MESG].addr = (const int8_t *)str;
			msg_block[TRMLOG_IDX_MESG].size = strlen(str);
			msg_block_num = TRMLOG_MSG_BLK_NUM;

			/* Log size is limited to 256 byte */
			for (i = 0; i < msg_block_num; i++) {
				log_sum_size += msg_block[i].size;
			}
			if (log_sum_size > MAX_PRINT_SIZE) {
				msg_block[msg_block_num - 1].size -=
					log_sum_size - (uint32_t)MAX_PRINT_SIZE;
			}

			if ((cpsr & ARM32_CPSR_F) == 0U) {
				/* User context */
				log_debug_send(msg_block, msg_block_num);
			} else {
				/* Interrupt context */
			}
		}
#endif
	}
}

int trace_ext_get_thread_id(void)
{
	return -1;
}
