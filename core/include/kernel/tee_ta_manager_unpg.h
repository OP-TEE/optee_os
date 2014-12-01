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

#ifndef TEE_TA_MANAGER_UNPG_H
#define TEE_TA_MANAGER_UNPG_H

#include <types_ext.h>
#include <kernel/tee_common_unpg.h>

#include <kernel/tee_ta.h>
#include <mm/tee_mm_unpg.h>
#include <sys/queue.h>
#include "tee_api_types.h"
#include "user_ta_header.h"

TAILQ_HEAD(tee_ta_session_head, tee_ta_session);
TAILQ_HEAD(tee_ta_ctx_head, tee_ta_ctx);
TAILQ_HEAD(tee_cryp_state_head, tee_cryp_state);
TAILQ_HEAD(tee_obj_head, tee_obj);
TAILQ_HEAD(tee_storage_enum_head, tee_storage_enum);

/* normal world user mapping if loaded by tee supplicant */
struct tee_ta_nwumap {
	paddr_t ph;
	size_t size;
};

/* Context of a loaded TA */
struct tee_ta_ctx {
	TAILQ_ENTRY(tee_ta_ctx) link;
	/* list of sessions opened by this TA */
	struct tee_ta_session_head open_sessions;
	/* List of cryp states created by this TA */
	struct tee_cryp_state_head cryp_states;
	/* List of storage objects opened by this TA */
	struct tee_obj_head objects;
	/* List of storage enumerators opened by this TA */
	struct tee_storage_enum_head storage_enums;
	ta_head_t *head;	/* ptr to the ta head in secure memory */
	uintptr_t mem_swap;	/* ptr to code and data in memory swap */
	tee_mm_entry_t *mm;	/* secure world memory */
	uint32_t smem_size;	/* the size of the secure memory */
	uint32_t rw_data;	/* rw data stored on heap */
	uint32_t rw_data_usage;	/* bitfield with rw data page usage */
	tee_mm_entry_t *mm_heap_stack;	/* shared section of heap and stack */
	size_t heap_size;	/* size of heap */
	size_t stack_size;	/* size of stack */
	uint32_t load_addr;	/* elf load addr (from TAs address space) */
	uint32_t context;	/* Context ID of the process */
	void *mmu;		/* TA mmu support (section or coarse mapping) */
	uint32_t num_res_funcs;	/* number of reserved ta_func_head_t (2 or 0) */
	uint32_t flags;		/* TA_FLAGS from sub header */
	uint32_t panicked;	/* True if TA has panicked, written from asm */
	uint32_t panic_code;	/* Code supplied for panic */
	uint32_t ref_count;	/* Reference counter for multi session TA */
	bool busy;		/* context is busy and cannot be entered */
	void *ta_time_offs;	/* Time reference used by the TA */
	ta_static_head_t *static_ta;	/* TA head struct for other cores */
	void *rlhandle;		/* private handle for other cores */
};

struct tee_ta_session {
	TAILQ_ENTRY(tee_ta_session) link;
	struct tee_ta_ctx *ctx;	/* TA context */
	/* session of calling TA if != NULL */
	struct tee_ta_session *calling_sess;
	TEE_Identity clnt_id;	/* Identify of client */
	bool cancel;		/* True if TAF is cancelled */
	bool cancel_mask;	/* True if cancel is masked */
	TEE_Time cancel_time;	/* Time when to cancel the TAF */
	void *user_ctx;		/* ??? */
};

struct tee_ta_param {
	uint32_t types;
	TEE_Param params[4];
	uint32_t param_attr[4];
};

/* Registered contexts */
extern struct tee_ta_ctx_head tee_ctxes;

#ifdef CFG_TEE_PAGER

/*-----------------------------------------------------------------------------
 * tee_ta_load_page - Loads a page at address va_addr
 * Parameters:
 * va_addr - The address somewhere in the page to be loaded (in)
 * Returns:
 *           A session handle to the session related to the memory accessed
 * NOTE: This function is executed in abort mode. Pls take care of stack usage
 *---------------------------------------------------------------------------*/
void *tee_ta_load_page(const uint32_t va_addr);

/*-----------------------------------------------------------------------------
 * tee_ta_check_rw - Checks if a page at va_addr contains rw data which should
 * be saved
 * Parameters:
 * va_addr - The address somewhere in the page to be removed (in)
 * session_handle - The session handle of the page
 * Returns:
 *           Returns 1 if the page contains data, 0 otherwise
 * NOTE: This function is executed in abort mode. Pls take care of stack usage
 *---------------------------------------------------------------------------*/
uint32_t tee_ta_check_rw(const uint32_t va_addr, const void *session_handle);

/*-----------------------------------------------------------------------------
 * tee_ta_save_rw removes a page at address va_addr
 * Parameters:
 * va_addr - The address somewhere in the page to be removed (in)
 * session_handle - The session handle of the page
 * Returns:
 *           void
 * NOTE: This function is executed in abort mode. Pls take care of stack usage
 *---------------------------------------------------------------------------*/
void tee_ta_save_rw(const uint32_t va_addr, const void *session_handle);
#endif /* CFG_TEE_PAGER */

#endif /* TEE_TA_MANAGER_UNPG_H */
