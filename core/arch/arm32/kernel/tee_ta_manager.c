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

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include <tee_api_types.h>
#include <user_ta_header.h>
#include <kernel/tee_compat.h>
#include <tee/tee_svc.h>
#include <mm/tee_mmu.h>
#include <kernel/tee_misc.h>
#include <tee/tee_svc_cryp.h>
#include <kernel/tee_common.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/tee_ta_manager_unpg.h>
#include <kernel/tee_ta_static.h>
#include <mm/tee_mm.h>
#include <kernel/tee_core_trace.h>
#include <kernel/tee_rpc.h>
#include <kernel/tee_rpc_types.h>
#include <tee/tee_hash.h>
#include <tee/tee_obj.h>
#include <tee/tee_svc_storage.h>
#include <kernel/tee_time.h>
#include <sm/tee_mon.h>
#include "user_ta_header.h"
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <kernel/thread.h>
#include <sm/teesmc.h>


/* Use this invalid ID for a static TA, since
 * session is not needed for calling static TA.
 */
#define TEE_SESSION_ID_STATIC_TA 0xFFFFFFFF

#define TEE_TA_STACK_ALIGNMENT   8

enum tee_user_ta_func {
	USER_TA_FUNC_OPEN_CLIENT_SESSION = 0,
	USER_TA_FUNC_CLOSE_CLIENT_SESSION,
	USER_TA_FUNC_INVOKE_COMMAND
};

typedef enum {
	COMMAND_INVOKE_COMMAND = 0,
	COMMAND_OPEN_SESSION,
	COMMAND_CREATE_ENTRY_POINT,
	COMMAND_CLOSE_SESSION,
	COMMAND_DESTROY_ENTRY_POINT,
} command_t;

/*
 * Only one session is running in the single threaded solution, once
 * we allow more threads we have to store this in thread local storage.
 */
static struct tee_ta_session *tee_rs;

/* Enters a user TA */
static TEE_Result tee_user_ta_enter(TEE_ErrorOrigin *err,
				    struct tee_ta_session *session,
				    enum tee_user_ta_func func,
				    uint32_t cancel_req_to, uint32_t cmd,
				    struct tee_ta_param *param);

static TEE_Result tee_ta_param_pa2va(struct tee_ta_session *sess,
				     struct tee_ta_param *param);

struct param_ta {
	struct tee_ta_session *sess;
	uint32_t cmd;
	struct tee_ta_param *param;
	TEE_Result res;
};

static TEE_Result tee_ta_rpc_free(struct tee_ta_nwumap *map);

static void jumper_invokecommand(void *voidargs)
{
	struct param_ta *args = (struct param_ta *)voidargs;

	INMSG("");
	args->res = args->sess->ctx->static_ta->invoke_command_entry_point(
			(void *)args->sess->user_ctx,
			(uint32_t)args->cmd,
			(uint32_t)args->param->types,
			(TEE_Param *)args->param->params);
	OUTMSG("%lx", args->res);
}

static void jumper_opensession(void *voidargs)
{
	struct param_ta *args = (struct param_ta *)voidargs;

	INMSG("");
	args->res = args->sess->ctx->static_ta->open_session_entry_point(
			(uint32_t)args->param->types,
			(TEE_Param *)args->param->params,
			(void **)&args->sess->user_ctx);
	OUTMSG("%lx", args->res);
}

static void jumper_createentrypoint(void *voidargs)
{
	struct param_ta *args = (struct param_ta *)voidargs;

	INMSG("");
	args->res = args->sess->ctx->static_ta->create_entry_point();
	OUTMSG("%lx", args->res);
}

static void jumper_closesession(void *voidargs)
{
	struct param_ta *args = (struct param_ta *)voidargs;

	INMSG("");
	args->sess->ctx->static_ta->close_session_entry_point(
			(void *)args->sess->user_ctx);
	args->res = TEE_SUCCESS;
	OUTMSG("%lx", args->res);
}

static void jumper_destroyentrypoint(void *voidargs)
{
	struct param_ta *args = (struct param_ta *)voidargs;

	INMSG("");
	args->sess->ctx->static_ta->destroy_entry_point();
	args->res = TEE_SUCCESS;
	OUTMSG("%lx", args->res);
}

/* Stack size is updated to take into account */
/* the size of the needs of the tee internal libs */

static TEE_Result invoke_ta(struct tee_ta_session *sess, uint32_t cmd,
			    struct tee_ta_param *param, command_t commandtype)
{
	struct param_ta ptas;

	ptas.sess = sess;
	ptas.cmd = cmd;
	ptas.param = param;
	ptas.res = TEE_ERROR_TARGET_DEAD;

	tee_rs = sess;

	switch (commandtype) {
	case COMMAND_INVOKE_COMMAND:
		jumper_invokecommand(&ptas);
		break;
	case COMMAND_OPEN_SESSION:
		jumper_opensession(&ptas);
		break;
	case COMMAND_CREATE_ENTRY_POINT:
		jumper_createentrypoint(&ptas);
		break;
	case COMMAND_CLOSE_SESSION:
		jumper_closesession(&ptas);
		break;
	case COMMAND_DESTROY_ENTRY_POINT:
		jumper_destroyentrypoint(&ptas);
		break;
	default:
		EMSG("Do not know how to run the command %d", commandtype);
		ptas.res = TEE_ERROR_GENERIC;
		break;
	}

	tee_rs = NULL;

	OUTRMSG(ptas.res);
	return ptas.res;
}

/* set trace level for all installed TAs (TA generic code) */
int tee_ta_set_trace_level(int level)
{
	struct tee_ta_ctx *ctx;

	if ((level > TRACE_MAX) && (level < TRACE_MIN))
		return -1;

	TAILQ_FOREACH(ctx, &tee_ctxes, link) {
		if (ctx->static_ta)
			ctx->static_ta->prop_tracelevel = level;

		/* non-static TA should be done too */
	}
	return 0;
}

/*-----------------------------------------------------------------------------
 * Find TA in session list based on a UUID (input)
 * Returns a pointer to the session
 *---------------------------------------------------------------------------*/
static struct tee_ta_ctx *tee_ta_context_find(const TEE_UUID *uuid)
{
	struct tee_ta_ctx *ctx;

	TAILQ_FOREACH(ctx, &tee_ctxes, link) {
		if (memcmp(&ctx->head->uuid, uuid, sizeof(TEE_UUID)) == 0)
			return ctx;
	}

	return NULL;
}

static void tee_ta_init_got(struct tee_ta_ctx *const ctx)
{
	uint32_t *ptr;
	uint32_t *end_ptr;
	uint32_t va_start;

	/*
	 * GOT and find_service_addr follows right after ro section.
	 */
	if ((TA_HEAD_GOT_MASK & ctx->head->rel_dyn_got_size) == 0)
		return;

	va_start = ctx->load_addr;

	ptr = (uint32_t *)(tee_ta_get_exec(ctx) + ctx->head->ro_size);
	end_ptr = (uint32_t *)((uint32_t) ptr +
			(TA_HEAD_GOT_MASK & ctx->head->rel_dyn_got_size));

	while (ptr < end_ptr) {
		*ptr += va_start;
#ifdef PAGER_DEBUG_PRINT
		DMSG("GOT [0x%x] = 0x%x", ptr, *ptr);
#endif
		ptr++;
	}
}

static void tee_ta_init_zi(struct tee_ta_ctx *const ctx)
{
	/* setup ZI data */
	uint32_t start = tee_ta_get_exec(ctx) +
	    ctx->head->rw_size + ctx->head->ro_size;

	memset((void *)start, 0, ctx->head->zi_size);
}

static void tee_ta_init_serviceaddr(struct tee_ta_ctx *const ctx)
{
	/*
	 * Kernel TA
	 *
	 * Find service follows right after GOT.
	 */
	uint32_t saddr = tee_ta_get_exec(ctx) + ctx->head->ro_size +
	    (ctx->head->rel_dyn_got_size & TA_HEAD_GOT_MASK);
	uint32_t *fsaddr = (uint32_t *)saddr;

	*fsaddr = 0;		/* we do not have any services */

#ifdef PAGER_DEBUG_PRINT
	DMSG("find_service_addr [0x%x] = 0x%x", fsaddr, *fsaddr);
#endif
}

/*
 * Process rel.dyn
 */
static void tee_ta_init_reldyn(struct tee_ta_ctx *const ctx)
{
	uint32_t rel_dyn_size = ctx->head->rel_dyn_got_size >> 16;
	uint32_t n;
	uint32_t saddr =
	    tee_ta_get_exec(ctx) + ctx->head->ro_size - rel_dyn_size;

	for (n = 0; n < rel_dyn_size; n += sizeof(struct ta_rel_dyn)) {
		struct ta_rel_dyn *rel_dyn = (struct ta_rel_dyn *)(saddr + n);
		uint32_t *data;

		if (rel_dyn->info != 0x17) {
			DMSG("Unknown rel_dyn info 0x%x", rel_dyn->info);
			TEE_ASSERT(0);
		}

		data = (uint32_t *)(ctx->load_addr + rel_dyn->addr);
		*data += ctx->load_addr;
#ifdef PAGER_DEBUG_PRINT
		DMSG("rel.dyn [0x%x] = 0x%x", data, *data);
#endif
	}
}

/*
 * Setup global variables initialized from TEE Core
 */
static void tee_ta_init_heap(struct tee_ta_ctx *const ctx, uint32_t heap_size)
{
	uint32_t *data;
	tee_uaddr_t heap_start_addr;

	/*
	 * User TA
	 *
	 * Heap base follows right after GOT
	 */

	/* XXX this function shouldn't know this mapping */
	heap_start_addr = ((TEE_DDR_VLOFFSET + 1) << SECTION_SHIFT) - heap_size;

	data = (uint32_t *)(tee_ta_get_exec(ctx) + ctx->head->ro_size +
			     (ctx->head->rel_dyn_got_size & TA_HEAD_GOT_MASK));

	*data = heap_start_addr;
#ifdef PAGER_DEBUG_PRINT
	DMSG("heap_base [0x%x] = 0x%x", data, *data);
#endif
}

/*-----------------------------------------------------------------------------
 * Loads TA header and hashes.
 * Verifies the TA signature.
 * Returns session ptr and TEE_Result.
 *---------------------------------------------------------------------------*/
static TEE_Result tee_ta_load(const kta_signed_header_t *signed_ta,
			      struct tee_ta_ctx **ta_ctx)
{
	/* ta & ta_session is assumed to be != NULL from previous checks */
	TEE_Result res;
	uint32_t size;
	size_t nbr_hashes;
	int head_size;
	uint32_t hash_type_size;
	uint32_t hash_size;
	void *head = NULL;
	void *ptr = NULL;
	uint32_t heap_size = 0;	/* gcc warning */
	struct tee_ta_ctx *ctx = NULL;
	ta_head_t *ta =
	    (void *)((uint8_t *)signed_ta + signed_ta->size_of_signed_header);

	/*
	 * ------------------------------------------------------------------
	 * 1st step: load in secure memory and check consisteny, signature.
	 * Note: this step defines the user/kernel priviledge of the TA.
	 * ------------------------------------------------------------------
	 */

	/*
	 * Check that the GOT ends up at a properly aligned address.
	 * See tee_ta_load_page() for update of GOT.
	 */
	if ((ta->ro_size % 4) != 0) {
		DMSG("Bad ro_size %u", ta->ro_size);
		return TEE_ERROR_BAD_FORMAT;
	}

	nbr_hashes = ((ta->ro_size + ta->rw_size) >> SMALL_PAGE_SHIFT) + 1;
	if (nbr_hashes > TEE_PVMEM_PSIZE)
		return TEE_ERROR_OUT_OF_MEMORY;

#ifdef CFG_NO_TA_HASH_SIGN
	hash_type_size = 0;
#else
	/* COPY HEADERS & HASHES: ta_head + ta_func_head(s) + hashes */
	if (tee_hash_get_digest_size(ta->hash_type, &hash_type_size) !=
	    TEE_SUCCESS) {
		DMSG("warning: invalid signed header: invalid hash id found!");
		return TEE_ERROR_SECURITY;
	}
#endif
	hash_size = hash_type_size * nbr_hashes;
	head_size =
	    sizeof(ta_head_t) +
	    ta->nbr_func * sizeof(ta_func_head_t) + hash_size;

	head = malloc(head_size);
	if (head == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* cpy headers from normal world memory */
	memcpy(head, ta, head_size - hash_size);

	/* cpy hashes from normal world memory */
	ptr =
	    (void *)((uint8_t *)head +
		     sizeof(ta_head_t) + ta->nbr_func * sizeof(ta_func_head_t));

	memcpy(ptr, (void *)((uint8_t *)ta + sizeof(ta_head_t) +
			     ta->nbr_func * sizeof(ta_func_head_t) +
			     ta->ro_size + ta->rw_size), hash_size);

	/* COPY SIGNATURE: alloc signature */
	ptr = malloc(signed_ta->size_of_signed_header);
	if (ptr == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto error_return;
	}

	/* cpy signature to secure memory */
	memcpy(ptr, signed_ta, signed_ta->size_of_signed_header);

	/*
	 * We may check signed TAs in this place
	 */


	/*
	 * End of check of signed header from secure:
	 * hashes are safe and validated.
	 */

	free(ptr);
	ptr = NULL;

	/*
	 * ------------------------------------------------------------------
	 * 2nd step: Register context
	 * Alloc and init the ta context structure, alloc physvical/virtual
	 * memories to store/map the TA.
	 * ------------------------------------------------------------------
	 */

	/*
	 * Register context
	 */

	/* code below must be protected by mutex (multi-threaded) */
	ctx = calloc(1, sizeof(struct tee_ta_ctx));
	if (ctx == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto error_return;
	}
	TAILQ_INIT(&ctx->open_sessions);
	TAILQ_INIT(&ctx->cryp_states);
	TAILQ_INIT(&ctx->objects);
	TAILQ_INIT(&ctx->storage_enums);
	ctx->head = (ta_head_t *)head;

	/* by default NSec DDR: starts at TA function code. */
	ctx->nmem = (void *)((uint32_t) ta + sizeof(ta_head_t) +
			     ta->nbr_func * sizeof(ta_func_head_t));

	ctx->num_res_funcs = ctx->head->zi_size >> 20;
	ctx->head->zi_size &= 0xfffff;
	if (ctx->num_res_funcs > ctx->head->nbr_func) {
		res = TEE_ERROR_BAD_FORMAT;
		goto error_return;
	}

	/* full required execution size (not stack etc...) */
	size = ctx->head->ro_size + ctx->head->rw_size + ctx->head->zi_size;

	if (ctx->num_res_funcs == 2) {
		ta_func_head_t *ta_func_head =
		    (ta_func_head_t *)((uint32_t) ctx->head +
					sizeof(ta_head_t));

		struct user_ta_sub_head *sub_head =
		    (struct user_ta_sub_head *)&ta_func_head[ctx->head->
							     nbr_func -
							     ctx->
							     num_res_funcs];
		/* man_flags: mandatory flags */
		uint32_t man_flags = TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR;
		uint32_t opt_flags = man_flags | TA_FLAG_SINGLE_INSTANCE |
		    TA_FLAG_MULTI_SESSION | TA_FLAG_UNSAFE_NW_PARAMS;

		/*
		 * sub_head is the end area of func_head; the 2 last
		 * (2 'resisdent func') func_head area.
		 * sub_head structure is... twice the func_head struct. magic.
		 * sub_head stores the flags, heap_size, stack_size.
		 */
		TEE_ASSERT((sizeof(struct user_ta_sub_head)) ==
			   (2 * sizeof(struct user_ta_func_head)));

		/*
		 * As we support only UserTA: assue all TA are user TA !
		 */
		sub_head->flags |= TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR;

		/* check input flags bitmask consistency and save flags */
		if ((sub_head->flags & opt_flags) != sub_head->flags ||
		    (sub_head->flags & man_flags) != man_flags) {
			EMSG("TA flag issue: flags=%x opt=%X man=%X",
			     sub_head->flags, opt_flags, man_flags);
			res = TEE_ERROR_BAD_FORMAT;
			goto error_return;
		}

		ctx->flags = sub_head->flags;

		/* Check if multi instance && single session config  */
		if (((ctx->flags & TA_FLAG_SINGLE_INSTANCE) == 0) &&
		    ((ctx->flags & TA_FLAG_MULTI_SESSION) == 0)) {
			/*
			 * assume MultiInstance/SingleSession,
			 * same as MultiInstance/MultiSession
			 */
			ctx->flags |= TA_FLAG_MULTI_SESSION;
		}

		/* Ensure proper aligment of stack */
		ctx->stack_size = TEE_ROUNDUP(sub_head->stack_size,
					      TEE_TA_STACK_ALIGNMENT);

		heap_size = sub_head->heap_size;

		if (ctx->stack_size + heap_size > SECTION_SIZE) {
			EMSG("Too large combined stack and HEAP");
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto error_return;
		}

		/*
		 * Allocate heap and stack
		 */
		ctx->mm_heap_stack =
		    tee_mm_alloc(&tee_mm_sec_ddr, SECTION_SIZE);
		if (ctx->mm_heap_stack == 0) {
			EMSG("Failed to allocate %u bytes\n", SECTION_SIZE);
			EMSG("  of memory for user heap and stack\n");
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto error_return;
		}

	} else if (ctx->num_res_funcs != 0) {
		/* Unknown sub header */
		res = TEE_ERROR_BAD_FORMAT;
		goto error_return;
	}

	if ((ctx->flags & TA_FLAG_EXEC_DDR) != 0) {
		/*
		 * Note that only User TA can be supported in DDR
		 * if executing in DDR, the size of the execution area
		 */
		size +=
		    sizeof(ta_head_t) + ta->nbr_func * sizeof(ta_func_head_t) +
		    (ta->rel_dyn_got_size & TA_HEAD_GOT_MASK);

		ctx->mm = tee_mm_alloc(&tee_mm_sec_ddr, size);

		if (ctx->mm != NULL) {
			/* cpy ddr TA into reserved memory space */
			struct tee_ta_param param = { 0 };
			void *dst;


			res = tee_mmu_init(ctx);
			if (res != TEE_SUCCESS)
				goto error_return;

			res = tee_mmu_map(ctx, &param);
			if (res != TEE_SUCCESS) {
				EMSG("call tee_mmu_map_uta() failed %X", res);
				goto error_return;
			}

			tee_mmu_set_ctx(ctx);

			dst = (void *)tee_mmu_get_load_addr(ctx);
			if (!tee_vbuf_is_non_sec(ta, size)) {
				EMSG("User TA isn't in non-secure memory");
				res = TEE_ERROR_SECURITY;
				goto error_return;
			}
			memcpy(dst, ta, size);

			core_cache_maintenance(DCACHE_AREA_CLEAN, dst, size);
			core_cache_maintenance(ICACHE_AREA_INVALIDATE, dst,
					      size);
		}

	} else {
		SMSG("no TA is currently supported in TEE RAM: abort.");
		res = TEE_ERROR_NOT_SUPPORTED;
		goto error_return;
	}

	if (ctx->mm == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto error_return;
	}

	/* XXX is this used for a user TA in DDR? */
	ctx->smem_size = size;

	if ((ctx->flags & TA_FLAG_EXEC_DDR) == 0) {
		/*
		 * HANDLE RW DATA
		 * Allocate data here and not in the abort handler to
		 * avoid running out of memory in abort mode.
		 */
		ctx->rw_data =
		    (uint32_t) (char *)malloc(ctx->head->zi_size +
					      ctx->head->rw_size);
		if (ctx->rw_data == 0) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto error_return;
		}
		ctx->rw_data_usage = 0;
	}

	if ((ctx->flags & TA_FLAG_EXEC_DDR) != 0) {
		ctx->load_addr = tee_mmu_get_load_addr(ctx);
	} else {
		ctx->load_addr =
		    ((ctx->mm->offset << SMALL_PAGE_SHIFT) + TEE_PVMEM_LO) -
		    sizeof(ta_head_t) -
		    ctx->head->nbr_func * sizeof(ta_func_head_t);
	}

	ctx->ref_count = 1;

	TAILQ_INSERT_TAIL(&tee_ctxes, ctx, link);
	*ta_ctx = ctx;
	/*
	 * Note that the setup below will cause at least one page fault so it's
	 * important that the session is fully registered at this stage.
	 */

	/* Init rel.dyn, GOT, Service ptr, ZI and heap */
	tee_ta_init_reldyn(ctx);
	tee_ta_init_got(ctx);
	if ((ctx->flags & TA_FLAG_USER_MODE) != 0)
		tee_ta_init_heap(ctx, heap_size);
	else
		tee_ta_init_serviceaddr(ctx);
	tee_ta_init_zi(ctx);

	DMSG("Loaded TA at 0x%x, ro_size %u, rw_size %u, zi_size %u",
	     tee_mm_get_smem(ctx->mm), ctx->head->ro_size,
	     ctx->head->rw_size, ctx->head->zi_size);
	DMSG("ELF load address 0x%x", ctx->load_addr);

	tee_rs = NULL;
	tee_mmu_set_ctx(NULL);
	/* end thread protection (multi-threaded) */

	return TEE_SUCCESS;

error_return:
	tee_rs = NULL;
	tee_mmu_set_ctx(NULL);
	free(head);
	free(ptr);
	if (ctx != NULL) {
		if ((ctx->flags & TA_FLAG_USER_MODE) != 0)
			tee_mmu_final(ctx);
		tee_mm_free(ctx->mm_heap_stack);
		tee_mm_free(ctx->mm);
		/* If pub DDR was allocated for nmem free it */
		tee_mm_free(tee_mm_find
			    (&tee_mm_pub_ddr, (uintptr_t) ctx->nmem));
		free(ctx);
	}
	return res;
}

/* Maps kernal TA params */
static TEE_Result tee_ta_param_pa2va(struct tee_ta_session *sess,
				     struct tee_ta_param *param)
{
	size_t n;
	void *va;

	/*
	 * If kernel TA is called from another TA the mapping
	 * of that TA is borrowed and the addresses are already
	 * virtual.
	 */
	if (sess != NULL && sess->calling_sess != NULL)
		return TEE_SUCCESS;

	for (n = 0; n < 4; n++) {
		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			if (core_pa2va
			    ((uint32_t) param->params[n].memref.buffer,
			     (uint32_t *)&va))
				return TEE_ERROR_BAD_PARAMETERS;
			param->params[n].memref.buffer = va;
			break;

		default:
			continue;
		}
	}

	return TEE_SUCCESS;
}

/*-----------------------------------------------------------------------------
 * Initialises a session based on the UUID or ptr to the ta
 * Returns ptr to the session (ta_session) and a TEE_Result
 *---------------------------------------------------------------------------*/
static TEE_Result tee_ta_init_session(uint32_t *session_id,
				      struct tee_ta_session_head *open_sessions,
				      const TEE_UUID *uuid,
				      const kta_signed_header_t *signed_ta,
				      struct tee_ta_session **ta_session)
{
	TEE_Result res;
	struct tee_ta_session *s;

	if (*session_id != 0) {
		/* Session specified */
		res = tee_ta_verify_session_pointer((struct tee_ta_session *)
						    *session_id, open_sessions);

		if (res == TEE_SUCCESS)
			*ta_session = (struct tee_ta_session *)*session_id;

		DMSG("   ... Re-open session => %p", (void *)*ta_session);
		return res;
	}

	if (uuid != NULL) {
		/* Session not specified, find one based on uuid */
		struct tee_ta_ctx *ctx = NULL;

		ctx = tee_ta_context_find(uuid);
		if (ctx == NULL)
			goto load_ta;

		if ((ctx->flags & TA_FLAG_SINGLE_INSTANCE) == 0)
			goto load_ta;

		if ((ctx->flags & TA_FLAG_MULTI_SESSION) == 0)
			return TEE_ERROR_BUSY;

		DMSG("   ... Re-open TA %08lx-%04x-%04x",
		     ctx->head->uuid.timeLow,
		     ctx->head->uuid.timeMid, ctx->head->uuid.timeHiAndVersion);

		s = calloc(1, sizeof(struct tee_ta_session));
		if (s == NULL)
			return TEE_ERROR_OUT_OF_MEMORY;

		ctx->ref_count++;
		s->ctx = ctx;
		s->cancel_mask = true;
		*ta_session = s;
		*session_id = (uint32_t) s;
		TAILQ_INSERT_TAIL(open_sessions, s, link);
		return TEE_SUCCESS;
	}

load_ta:
	s = calloc(1, sizeof(struct tee_ta_session));
	if (s == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_ERROR_ITEM_NOT_FOUND;
	if (signed_ta != NULL) {
		DMSG("   Load dynamic TA");
		/* load and verify */
		res = tee_ta_load(signed_ta, &s->ctx);
	} else if (uuid != NULL) {
		DMSG("   Lookup for Static TA %08lx-%04x-%04x",
		     uuid->timeLow, uuid->timeMid, uuid->timeHiAndVersion);
		/* Load Static TA */
		ta_static_head_t *ta;
		for (ta = &__start_ta_head_section;
		     ta < &__stop_ta_head_section; ta++) {
			if (memcmp(&ta->uuid, uuid, sizeof(TEE_UUID)) == 0) {
				/* Load a new TA and create a session */
				DMSG("      Open %s", ta->name);
				s->ctx = calloc(1, sizeof(struct tee_ta_ctx));
				if (s->ctx == NULL) {
					free(s);
					return TEE_ERROR_OUT_OF_MEMORY;
				}
				TAILQ_INIT(&s->ctx->open_sessions);
				TAILQ_INIT(&s->ctx->cryp_states);
				TAILQ_INIT(&s->ctx->objects);
				s->ctx->num_res_funcs = 0;
				s->ctx->ref_count = 1;
				s->ctx->flags = TA_FLAG_MULTI_SESSION;
				s->ctx->head = (ta_head_t *)ta;
				s->ctx->static_ta = ta;
				TAILQ_INSERT_TAIL(&tee_ctxes, s->ctx, link);
				res = TEE_SUCCESS;
			}
		}
	}

	if (res != TEE_SUCCESS) {
		if (uuid != NULL)
			EMSG("   ... Not found %08lx-%04x-%04x",
			     ((uuid) ? uuid->timeLow : 0xDEAD),
			     ((uuid) ? uuid->timeMid : 0xDEAD),
			     ((uuid) ? uuid->timeHiAndVersion : 0xDEAD));
		else
			EMSG("   ... Not found");
		free(s);
		return res;
	} else
		DMSG("      %s : %08lx-%04x-%04x",
		     s->ctx->static_ta ? s->ctx->static_ta->name : "dyn TA",
		     s->ctx->head->uuid.timeLow,
		     s->ctx->head->uuid.timeMid,
		     s->ctx->head->uuid.timeHiAndVersion);

	s->cancel_mask = true;
	*ta_session = s;
	*session_id = (uint32_t) s;
	TAILQ_INSERT_TAIL(open_sessions, s, link);

	/*
	 * Call create_entry_point: for the static TA: to be cleaned.
	 * Here, we should call the TA "create" entry point, if TA supports
	 * it. Else, no TA code to call here.
	 * Note that this can be move to open_session in order static-TA and
	 * user-TA behaves the same
	 */
	if ((s->ctx->static_ta != NULL) &&
	    (s->ctx->static_ta->create_entry_point != NULL)) {
		DMSG("     Call create_entry_point");
		res = invoke_ta(s, 0, 0, COMMAND_CREATE_ENTRY_POINT);
		if (res != TEE_SUCCESS) {
			EMSG("      => (ret=%lx)", res);
			tee_ta_close_session((uint32_t) s, open_sessions);
		}
	}

	return res;
}

static void tee_ta_set_invoke_timeout(struct tee_ta_session *sess,
				      uint32_t cancel_req_to)
{
	TEE_Time current_time;
	TEE_Time cancel_time = { UINT32_MAX, UINT32_MAX };

	if (cancel_req_to == TEE_TIMEOUT_INFINITE)
		goto out;

	if (tee_time_get_sys_time(&current_time) != TEE_SUCCESS)
		goto out;

	/* Check that it doesn't wrap */
	if (current_time.seconds + (cancel_req_to / 1000) >=
	    current_time.seconds) {
		cancel_time.seconds =
		    current_time.seconds + cancel_req_to / 1000;
		cancel_time.millis = current_time.millis + cancel_req_to % 1000;
		if (cancel_time.millis > 1000) {
			cancel_time.seconds++;
			cancel_time.millis -= 1000;
		}
	}

out:
	sess->cancel_time = cancel_time;
}

static TEE_Result tee_user_ta_enter(TEE_ErrorOrigin *err,
				    struct tee_ta_session *session,
				    enum tee_user_ta_func func,
				    uint32_t cancel_req_to, uint32_t cmd,
				    struct tee_ta_param *param)
{
	TEE_Result res;
	TEE_Param *usr_params;
	tee_paddr_t usr_stack;
	tee_uaddr_t stack_uaddr;
	tee_uaddr_t start_uaddr;
	struct tee_ta_ctx *ctx = session->ctx;
	ta_func_head_t *ta_func_head =
	    (ta_func_head_t *)((uint32_t) ctx->head + sizeof(ta_head_t));
	tee_uaddr_t params_uaddr;
	TEE_ErrorOrigin serr = TEE_ORIGIN_TEE;

	TEE_ASSERT((ctx->flags & TA_FLAG_EXEC_DDR) != 0);

	TEE_ASSERT((uint32_t) func <=
		   (ctx->head->nbr_func - ctx->num_res_funcs));

	/* Set timeout of entry */
	tee_ta_set_invoke_timeout(session, cancel_req_to);

	/* Map user space memory */
	res = tee_mmu_map(ctx, param);
	if (res != TEE_SUCCESS)
		goto cleanup_return;

	/* Switch to user ctx */
	tee_ta_set_current_session(session);

	/* Make room for usr_params at top of stack */
	usr_stack = tee_mm_get_smem(ctx->mm_heap_stack) + ctx->stack_size;
	usr_params = (TEE_Param *)usr_stack;
	memcpy(usr_params, param->params, sizeof(param->params));
	usr_stack -= sizeof(param->params);

	res = tee_mmu_kernel_to_user(ctx, (tee_vaddr_t)usr_params,
				     &params_uaddr);
	if (res != TEE_SUCCESS)
		goto cleanup_return;

	res = tee_mmu_kernel_to_user(ctx, usr_stack, &stack_uaddr);
	if (res != TEE_SUCCESS)
		goto cleanup_return;

	start_uaddr = ctx->load_addr + ta_func_head[func].start;

	switch (func) {
	case USER_TA_FUNC_OPEN_CLIENT_SESSION:
		res =
		    tee_svc_enter_user_mode(param->types, params_uaddr,
					    (uint32_t) session, 0, stack_uaddr,
					    start_uaddr, &ctx->panicked,
					    &ctx->panic_code);

		/*
		 * According to GP spec the origin should allways be set to the
		 * TA after TA execution
		 */
		serr = TEE_ORIGIN_TRUSTED_APP;
		break;

	case USER_TA_FUNC_CLOSE_CLIENT_SESSION:
		res = tee_svc_enter_user_mode((uint32_t) session, 0, 0, 0,
					      stack_uaddr, start_uaddr,
					      &ctx->panicked, &ctx->panic_code);

		serr = TEE_ORIGIN_TRUSTED_APP;
		break;

	case USER_TA_FUNC_INVOKE_COMMAND:
		res =
		    tee_svc_enter_user_mode(cmd, param->types, params_uaddr,
					    (uint32_t) session, stack_uaddr,
					    start_uaddr, &ctx->panicked,
					    &ctx->panic_code);

		serr = TEE_ORIGIN_TRUSTED_APP;
		break;

	default:
		serr = TEE_ORIGIN_TEE;
		res = TEE_ERROR_BAD_STATE;
	}

	if (ctx->panicked) {
		DMSG("tee_user_ta_enter: TA panicked with code 0x%x\n",
		     ctx->panic_code);
		serr = TEE_ORIGIN_TEE;
		res = TEE_ERROR_TARGET_DEAD;
	}

	/* Copy out value results */
	memcpy(param->params, usr_params, sizeof(param->params));

cleanup_return:
	/* Restore original ROM mapping */
	tee_ta_set_current_session(NULL);

	/*
	 * Clear the cancel state now that the user TA has returned. The next
	 * time the TA will be invoked will be with a new operation and should
	 * not have an old cancellation pending.
	 */
	session->cancel = false;

	/*
	 * Can't update *err until now since it may point to an address
	 * mapped for the user mode TA.
	 */
	*err = serr;

	return res;
}

/*
 * Load a TA via RPC with UUID defined by input param uuid. The virtual
 * address of the TA is recieved in out parameter ta
 *
 * Function is not thread safe
 */
TEE_Result tee_ta_rpc_load(const TEE_UUID *uuid, kta_signed_header_t **ta,
			   struct tee_ta_nwumap *map, uint32_t *ret_orig)
{
	TEE_Result res;
	struct teesmc32_arg *arg;
	struct teesmc32_param *params;
	paddr_t pharg = 0;
	paddr_t phpayload = 0;
	paddr_t cookie = 0;
	struct tee_rpc_load_ta_cmd *cmd_load_ta;
	struct tee_ta_nwumap nwunmap;

	if (uuid == NULL || ta == NULL || ret_orig == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/* get a rpc buffer */
	pharg = thread_rpc_alloc_arg(TEESMC32_GET_ARG_SIZE(2));
	thread_st_rpc_alloc_payload(sizeof(struct tee_rpc_load_ta_cmd),
				   &phpayload, &cookie);
	if (!pharg || !phpayload) {
		*ret_orig = TEE_ORIGIN_TEE;
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (!TEE_ALIGNMENT_IS_OK(pharg, struct teesmc32_arg) ||
	    !TEE_ALIGNMENT_IS_OK(phpayload, struct tee_rpc_load_ta_cmd)) {
		*ret_orig = TEE_ORIGIN_TEE;
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	if (core_pa2va(pharg, (uint32_t *)&arg) ||
		core_pa2va(phpayload, (uint32_t *)&cmd_load_ta)) {
		*ret_orig = TEE_ORIGIN_TEE;
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	arg->cmd = TEE_RPC_LOAD_TA;
	arg->num_params = 2;
	/* Set a suitable error code in case our resquest is ignored. */
	arg->ret = TEE_ERROR_NOT_IMPLEMENTED;
	params = TEESMC32_GET_PARAMS(arg);
	params[0].attr = TEESMC_ATTR_TYPE_MEMREF_INOUT |
			 TEESMC_ATTR_CACHE_DEFAULT << TEESMC_ATTR_CACHE_SHIFT;
	params[1].attr = TEESMC_ATTR_TYPE_MEMREF_OUTPUT |
			 TEESMC_ATTR_CACHE_DEFAULT << TEESMC_ATTR_CACHE_SHIFT;

	params[0].u.memref.buf_ptr = phpayload;
	params[0].u.memref.size = sizeof(struct tee_rpc_load_ta_cmd);
	params[1].u.memref.buf_ptr = 0;
	params[1].u.memref.size = 0;

	memset(cmd_load_ta, 0, sizeof(struct tee_rpc_load_ta_cmd));
	memcpy(&cmd_load_ta->uuid, uuid, sizeof(TEE_UUID));

	thread_rpc_cmd(pharg);
	res = arg->ret;

	if (res != TEE_SUCCESS) {
		*ret_orig = TEE_ORIGIN_COMMS;
		goto out;
	}

	nwunmap.ph = (paddr_t)cmd_load_ta->va;
	nwunmap.size = params[1].u.memref.size;
	if (core_pa2va(params[1].u.memref.buf_ptr, (uint32_t *)ta)) {
		tee_ta_rpc_free(&nwunmap);
		*ret_orig = TEE_ORIGIN_TEE;
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	*map = nwunmap;

out:
	thread_rpc_free_arg(pharg);
	thread_st_rpc_free_payload(cookie);
	return res;
}

static TEE_Result tee_ta_rpc_free(struct tee_ta_nwumap *map)
{
	TEE_Result res;
	struct teesmc32_arg *arg;
	struct teesmc32_param *params;
	paddr_t pharg = 0;

	/* get a rpc buffer */
	pharg = thread_rpc_alloc_arg(TEESMC32_GET_ARG_SIZE(1));
	if (!pharg) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (!TEE_ALIGNMENT_IS_OK(pharg, struct teesmc32_arg)) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	if (core_pa2va(pharg, (uint32_t *)&arg)) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	arg->cmd = TEE_RPC_FREE_TA;
	arg->num_params = 1;
	/* Set a suitable error code in case our resquest is ignored. */
	arg->ret = TEE_ERROR_NOT_IMPLEMENTED;
	params = TEESMC32_GET_PARAMS(arg);
	params[0].attr = TEESMC_ATTR_TYPE_MEMREF_INPUT |
			 TEESMC_ATTR_CACHE_DEFAULT << TEESMC_ATTR_CACHE_SHIFT;

	params[0].u.memref.buf_ptr = map->ph;
	params[0].u.memref.size = map->size;

	thread_rpc_cmd(pharg);
	res = arg->ret;
out:
	thread_rpc_free_arg(pharg);
	return res;
}

/*-----------------------------------------------------------------------------
 * Close a Trusted Application and free available resources
 *---------------------------------------------------------------------------*/
TEE_Result tee_ta_close_session(uint32_t id,
				struct tee_ta_session_head *open_sessions)
{
	struct tee_ta_session *sess, *next;
	TEE_Result res = TEE_SUCCESS;

	DMSG("tee_ta_close_session(%x)", (unsigned int)id);

	if (id == 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	TAILQ_FOREACH(sess, open_sessions, link) {
		if (id == (uint32_t) sess) {
			struct tee_ta_ctx *ctx = sess->ctx;

			DMSG("   ... Destroy session");

			if (ctx->locked)
				return TEE_ERROR_BUSY;

			if (ctx->busy)
				return TEE_STE_ERROR_SYSTEM_BUSY;
			ctx->busy = true;

			if ((ctx->static_ta != NULL) &&
			    (ctx->static_ta->close_session_entry_point
				!= NULL) &&
			    (!ctx->panicked)) {
				DMSG("   ... close_session_entry_point");
				res =
				    invoke_ta(sess, 0, 0,
					      COMMAND_CLOSE_SESSION);

			} else if (((ctx->flags & TA_FLAG_USER_MODE) != 0) &&
				   (!ctx->panicked)) {
				TEE_ErrorOrigin err;
				struct tee_ta_param param = { 0 };

				tee_user_ta_enter(
					&err, sess,
					USER_TA_FUNC_CLOSE_CLIENT_SESSION,
					TEE_TIMEOUT_INFINITE, 0,
					&param);
			}

			TAILQ_REMOVE(open_sessions, sess, link);

			ctx->busy = false;

			TEE_ASSERT(ctx->ref_count > 0);
			ctx->ref_count--;
			if (ctx->ref_count > 0) {
				free(sess);
				sess = NULL;
				return TEE_SUCCESS;
			}

			/*
			 * Clean all traces of the TA, both RO and RW data.
			 * No L2 cache maintenance to avoid sync problems
			 */
			if ((ctx->flags & TA_FLAG_EXEC_DDR) != 0) {
				void *pa;
				void *va;
				uint32_t s;

				tee_mmu_set_ctx(ctx);

				if (ctx->mm != NULL) {
					pa = (void *)tee_mm_get_smem(ctx->mm);
					if (tee_mmu_user_pa2va(ctx, pa, &va) ==
					    TEE_SUCCESS) {
						s = tee_mm_get_bytes(ctx->mm);
						memset(va, 0, s);
						core_cache_maintenance
						    (DCACHE_AREA_CLEAN, va, s);
					}
				}

				if (ctx->mm_heap_stack != NULL) {
					pa = (void *)tee_mm_get_smem
							(ctx->mm_heap_stack);
					if (tee_mmu_user_pa2va(ctx, pa, &va) ==
					    TEE_SUCCESS) {
						s = tee_mm_get_bytes
							(ctx->mm_heap_stack);
						memset(va, 0, s);
						core_cache_maintenance
						    (DCACHE_AREA_CLEAN, va, s);
					}
				}
				tee_mmu_set_ctx(NULL);
			}

			DMSG("   ... Destroy TA ctx");

			TAILQ_REMOVE(&tee_ctxes, ctx, link);

			/*
			 * Close sessions opened by this TA
			 * TAILQ_FOREACH() macro cannot be used as the element
			 * is removed inside tee_ta_close_session
			 */

			for (struct tee_ta_session *linked_sess =
			     TAILQ_FIRST(&ctx->open_sessions); linked_sess;
			     linked_sess = next) {
				next = linked_sess->link.tqe_next;
				(void)tee_ta_close_session((uint32_t)
							   linked_sess,
							   &ctx->open_sessions);
			}

			if ((ctx->static_ta != NULL) &&
			    (ctx->static_ta->destroy_entry_point != NULL) &&
			    (!ctx->panicked)) {
				DMSG("   ... destroy_entry_point");
				res =
				    invoke_ta(sess, 0, 0,
					      COMMAND_DESTROY_ENTRY_POINT);
			}

			free(sess);
			sess = NULL;

			/* If TA was loaded in reserved DDR free the alloc. */
			tee_mm_free(tee_mm_find
				    (&tee_mm_pub_ddr, (uintptr_t) ctx->nmem));

			if (ctx->nwumap.size != 0)
				tee_ta_rpc_free(&ctx->nwumap);

			if ((ctx->flags & TA_FLAG_USER_MODE) != 0) {
				tee_mmu_final(ctx);
				tee_mm_free(ctx->mm_heap_stack);
			}
			if (ctx->static_ta == NULL) {
				tee_mm_free(ctx->mm);
				free((void *)ctx->rw_data);
				free(ctx->head);
			}

			/* Free cryp states created by this TA */
			tee_svc_cryp_free_states(ctx);
			/* Close cryp objects opened by this TA */
			tee_obj_close_all(ctx);
			/* Free emums created by this TA */
			tee_svc_storage_close_all_enum(ctx);

			free(ctx);

			return res;
		}
	}

	EMSG(" .... Session %p to removed is not found", (void *)sess);
	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result tee_ta_make_current_session_resident(void)
{
	tee_mm_entry_t *mm;
	void *addr;
	size_t len;
	struct tee_ta_ctx *ctx = tee_rs->ctx;

	/*
	 * Below reserved DDR is allocated for the backing memory of the TA
	 * and then the backing memory is copied to the new location and
	 * the pointer to normal world memory is updated.
	 */

	if (tee_mm_addr_is_within_range(&tee_mm_pub_ddr, (uintptr_t) ctx->nmem))
		/* The backing pages are already in reserved DDR */
		goto func_ret;

	len = ctx->head->ro_size + ctx->head->rw_size;
	mm = tee_mm_alloc(&tee_mm_pub_ddr, len);
	if (mm == NULL) {
		DMSG("Out of pub DDR, cannot allocate %u", len);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	addr = (void *)tee_mm_get_smem(mm);

	memcpy(addr, ctx->nmem, len);
	ctx->nmem = addr;

func_ret:
	ctx->locked = true;
	return TEE_SUCCESS;
}

void tee_ta_unlock_current_session(void)
{
	struct tee_ta_ctx *ctx = tee_rs->ctx;

	ctx->locked = false;
}

static TEE_Result tee_ta_verify_param(struct tee_ta_session *sess,
				      struct tee_ta_param *param)
{
	tee_paddr_t p;
	size_t l;
	int n;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
		case TEE_PARAM_TYPE_MEMREF_INPUT:

			p = (tee_paddr_t)param->params[n].memref.buffer;
			l = param->params[n].memref.size;

			if (core_pbuf_is(CORE_MEM_NSEC_SHM, p, l))
				break;
			if ((sess->ctx->flags & TA_FLAG_UNSAFE_NW_PARAMS) &&
				core_pbuf_is(CORE_MEM_MULTPURPOSE, p, l))
				break;
			if ((sess->clnt_id.login == TEE_LOGIN_TRUSTED_APP) &&
				core_pbuf_is(CORE_MEM_TA_RAM, p, l))
				break;

			return TEE_ERROR_SECURITY;
		default:
			break;
		}
	}
	return TEE_SUCCESS;
}

TEE_Result tee_ta_open_session(TEE_ErrorOrigin *err,
			       struct tee_ta_session **sess,
			       struct tee_ta_session_head *open_sessions,
			       const TEE_UUID *uuid,
			       const kta_signed_header_t *ta,
			       const TEE_Identity *clnt_id,
			       uint32_t cancel_req_to,
			       struct tee_ta_param *param)
{
	TEE_Result res;
	uint32_t id = (uint32_t) *sess;
	struct tee_ta_session *s = 0;
	bool sess_inited = (*sess != NULL);
	struct tee_ta_ctx *ctx;

	res = tee_ta_init_session(&id, open_sessions, uuid, ta, &s);
	if (res != TEE_SUCCESS) {
		EMSG("tee_ta_init_session() failed with error 0x%lx", res);
		*err = TEE_ORIGIN_TEE;
		return res;
	}

	ctx = s->ctx;
	ctx->nwumap.size = 0;

	if (ctx->panicked) {
		EMSG("Calls tee_ta_close_session()");
		tee_ta_close_session(id, open_sessions);
		*err = TEE_ORIGIN_TEE;
		return TEE_ERROR_TARGET_DEAD;
	}

	*sess = s;
	/* Save idenity of the owner of the session */
	s->clnt_id = *clnt_id;

	/*
	 * Session context is ready.
	 */
	if (sess_inited)
		goto out;

	if (((ctx->flags & TA_FLAG_USER_MODE) != 0 || ctx->static_ta != NULL) &&
	    (!sess_inited)) {
		/* Only User TA:s has a callback for open session */

		res = tee_ta_verify_param(s, param);
		if (res == TEE_SUCCESS) {
			/* case the static TA */
			if ((ctx->static_ta != NULL) &&
			    (ctx->static_ta->open_session_entry_point != NULL)
			   ) {
				res =
				    invoke_ta(s, 0, param,
					      COMMAND_OPEN_SESSION);

				/*
				 * Clear the cancel state now that the user TA
				 * has returned. The next time the TA will be
				 * invoked will be with a new operation and
				 * should not have an old cancellation pending.
				 */
				s->cancel = false;
			} else {
				res = tee_user_ta_enter(
					err, s,
					USER_TA_FUNC_OPEN_CLIENT_SESSION,
					cancel_req_to, 0, param);
			}
		}

		if (ctx->panicked || (res != TEE_SUCCESS))
			tee_ta_close_session(id, open_sessions);
	}

out:
	/*
	 * Origin error equal to TEE_ORIGIN_TRUSTED_APP for "regular" error,
	 * apart from panicking.
	 */
	if (ctx->panicked)
		*err = TEE_ORIGIN_TEE;
	else
		*err = TEE_ORIGIN_TRUSTED_APP;

	if (res != TEE_SUCCESS)
		EMSG("Failed. Return error 0x%lx", res);

	return res;
}

TEE_Result tee_ta_invoke_command(TEE_ErrorOrigin *err,
				 struct tee_ta_session *sess,
				 const TEE_Identity *clnt_id,
				 uint32_t cancel_req_to, uint32_t cmd,
				 struct tee_ta_param *param)
{
	TEE_Result res;

	if (sess->ctx->panicked) {
		EMSG("   Panicked !");
		*err = TEE_ORIGIN_TEE;
		OUTRMSG(TEE_ERROR_TARGET_DEAD);
	}

	if (sess->ctx->busy) {
		*err = TEE_ORIGIN_TEE;
		return TEE_STE_ERROR_SYSTEM_BUSY;
	}
	sess->ctx->busy = true;

	res = tee_ta_verify_param(sess, param);
	if (res != TEE_SUCCESS) {
		*err = TEE_ORIGIN_TEE;
		goto function_exit;
	}

	if ((sess->ctx->static_ta != NULL) &&
	    (sess->ctx->static_ta->invoke_command_entry_point != NULL)) {
		res = tee_ta_param_pa2va(sess, param);
		if (res != TEE_SUCCESS) {
			*err = TEE_ORIGIN_TEE;
			goto function_exit;
		}

		/* Set timeout of entry */
		tee_ta_set_invoke_timeout(sess, cancel_req_to);

		DMSG("   invoke_command_entry_point(%p)", sess->user_ctx);
		res = invoke_ta(sess, cmd, param, COMMAND_INVOKE_COMMAND);

		/*
		 * Clear the cancel state now that the user TA has returned.
		 * The next time the TA will be invoked will be with a new
		 * operation and should not have an old cancellation pending.
		 */
		sess->cancel = false;

		/*
		 * According to GP spec the origin should allways be set to the
		 * TA after TA execution
		 */
		*err = TEE_ORIGIN_TRUSTED_APP;
	} else {
		assert((sess->ctx->flags & TA_FLAG_USER_MODE) != 0);
		res = tee_user_ta_enter(err, sess, USER_TA_FUNC_INVOKE_COMMAND,
					cancel_req_to, cmd, param);
	}

	if (sess->ctx->panicked) {
		*err = TEE_ORIGIN_TEE;
		res = TEE_ERROR_TARGET_DEAD;
	}

function_exit:
	sess->ctx->busy = false;
	if (res != TEE_SUCCESS)
		EMSG("  => Error: %lx of %ld\n", res, *err);
	return res;
}

TEE_Result tee_ta_cancel_command(TEE_ErrorOrigin *err,
				 struct tee_ta_session *sess,
				 const TEE_Identity *clnt_id)
{
	*err = TEE_ORIGIN_TEE;

	sess->cancel = true;
	return TEE_SUCCESS;
}

TEE_Result tee_ta_get_current_session(struct tee_ta_session **sess)
{
	if (tee_rs == NULL)
		return TEE_ERROR_BAD_STATE;
	*sess = tee_rs;
	return TEE_SUCCESS;
}

void tee_ta_set_current_session(struct tee_ta_session *sess)
{
	if (tee_rs != sess) {
		struct tee_ta_ctx *ctx = NULL;

		if (sess != NULL)
			ctx = sess->ctx;

		tee_rs = sess;
		tee_mmu_set_ctx(ctx);
	}
	/*
	 * If sess == NULL we must have kernel mapping,
	 * if sess != NULL we must not have kernel mapping.
	 */
	assert((sess == NULL) == tee_mmu_is_kernel_mapping());
}

TEE_Result tee_ta_get_client_id(TEE_Identity *id)
{
	TEE_Result res;
	struct tee_ta_session *sess;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	if (id == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	*id = sess->clnt_id;
	return TEE_SUCCESS;
}

uintptr_t tee_ta_get_exec(const struct tee_ta_ctx *const ctx)
{
	if ((ctx->flags & TA_FLAG_EXEC_DDR) == 0) {
		return tee_mm_get_smem(ctx->mm);
	} else {
		return tee_mmu_get_load_addr(ctx) + sizeof(ta_head_t) +
		    ctx->head->nbr_func * sizeof(ta_func_head_t);
	}
}

TEE_Result tee_ta_verify_session_pointer(struct tee_ta_session *sess,
					 struct tee_ta_session_head
					 *open_sessions)
{
	struct tee_ta_session *s;

	if (sess == (struct tee_ta_session *)TEE_SESSION_ID_STATIC_TA)
		return TEE_SUCCESS;

	TAILQ_FOREACH(s, open_sessions, link) {
		if (s == sess)
			return TEE_SUCCESS;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}
