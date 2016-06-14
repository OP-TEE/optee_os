/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015, Linaro Limited
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

#include <compiler.h>
#include <keep.h>
#include <types_ext.h>
#include <stdlib.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/user_ta.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/tee_mm.h>
#include <mm/tee_mmu.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_cryp_utl.h>
#include <tee/tee_obj.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_svc.h>
#include <tee/tee_svc_storage.h>
#include <signed_hdr.h>
#include <ta_pub_key.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

#include "elf_load.h"
#include "elf_common.h"

#define STACK_ALIGNMENT   (sizeof(long) * 2)

static TEE_Result load_header(const struct shdr *signed_ta,
		struct shdr **sec_shdr)
{
	size_t s;

	if (!tee_vbuf_is_non_sec(signed_ta, sizeof(*signed_ta)))
		return TEE_ERROR_SECURITY;

	s = SHDR_GET_SIZE(signed_ta);
	if (!tee_vbuf_is_non_sec(signed_ta, s))
		return TEE_ERROR_SECURITY;

	/* Copy signed header into secure memory */
	*sec_shdr = malloc(s);
	if (!*sec_shdr)
		return TEE_ERROR_OUT_OF_MEMORY;
	memcpy(*sec_shdr, signed_ta, s);

	return TEE_SUCCESS;
}

static TEE_Result check_shdr(struct shdr *shdr)
{
	struct rsa_public_key key;
	TEE_Result res;
	uint32_t e = TEE_U32_TO_BIG_ENDIAN(ta_pub_key_exponent);
	size_t hash_size;

	if (shdr->magic != SHDR_MAGIC || shdr->img_type != SHDR_TA)
		return TEE_ERROR_SECURITY;

	if (TEE_ALG_GET_MAIN_ALG(shdr->algo) != TEE_MAIN_ALGO_RSA)
		return TEE_ERROR_SECURITY;

	res = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(shdr->algo),
				       &hash_size);
	if (res != TEE_SUCCESS)
		return res;
	if (hash_size != shdr->hash_size)
		return TEE_ERROR_SECURITY;

	if (!crypto_ops.acipher.alloc_rsa_public_key ||
	    !crypto_ops.acipher.free_rsa_public_key ||
	    !crypto_ops.acipher.rsassa_verify ||
	    !crypto_ops.bignum.bin2bn)
		return TEE_ERROR_NOT_SUPPORTED;

	res = crypto_ops.acipher.alloc_rsa_public_key(&key, shdr->sig_size);
	if (res != TEE_SUCCESS)
		return res;

	res = crypto_ops.bignum.bin2bn((uint8_t *)&e, sizeof(e), key.e);
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_ops.bignum.bin2bn(ta_pub_key_modulus,
				       ta_pub_key_modulus_size, key.n);
	if (res != TEE_SUCCESS)
		goto out;

	res = crypto_ops.acipher.rsassa_verify(shdr->algo, &key, -1,
				SHDR_GET_HASH(shdr), shdr->hash_size,
				SHDR_GET_SIG(shdr), shdr->sig_size);
out:
	crypto_ops.acipher.free_rsa_public_key(&key);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_SECURITY;
	return TEE_SUCCESS;
}

static uint32_t elf_flags_to_mattr(uint32_t flags, bool init_attrs)
{
	uint32_t mattr = TEE_MATTR_PRW;

	if (!init_attrs) {
		if (flags & PF_X)
			mattr |= TEE_MATTR_UX;
		if (flags & PF_W)
			mattr |= TEE_MATTR_UW;
		if (flags & PF_R)
			mattr |= TEE_MATTR_UR;
	}

	return mattr;
}

static TEE_Result load_elf_segments(struct user_ta_ctx *utc,
			struct elf_load_state *elf_state, bool init_attrs)
{
	TEE_Result res;
	paddr_t pa;
	uint32_t mattr;
	size_t idx = 0;

	tee_mmu_map_clear(utc);
	/*
	 * Add stack segment
	 */
	pa = tee_mm_get_smem(utc->mm_stack);
	mattr = elf_flags_to_mattr(PF_W | PF_R, init_attrs);
	tee_mmu_map_stack(utc, pa, tee_mm_get_bytes(utc->mm_stack), mattr);

	/*
	 * Add code segment
	 */
	pa = tee_mm_get_smem(utc->mm);
	while (true) {
		vaddr_t offs;
		size_t size;
		uint32_t flags;

		res = elf_load_get_next_segment(elf_state, &idx, &offs, &size,
						&flags);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			return TEE_SUCCESS;
		if (res != TEE_SUCCESS)
			return res;

		mattr = elf_flags_to_mattr(flags, init_attrs);
		res = tee_mmu_map_add_segment(utc, pa, offs, size, mattr);
		if (res != TEE_SUCCESS)
			return res;
	}
}

static TEE_Result load_elf(struct user_ta_ctx *utc, struct shdr *shdr,
			const struct shdr *nmem_shdr)
{
	TEE_Result res;
	size_t hash_ctx_size;
	void *hash_ctx = NULL;
	uint32_t hash_algo;
	uint8_t *nwdata = (uint8_t *)nmem_shdr + SHDR_GET_SIZE(shdr);
	size_t nwdata_len = shdr->img_size;
	void *digest = NULL;
	struct elf_load_state *elf_state = NULL;
	struct ta_head *ta_head;
	void *p;
	size_t vasize;

	if (!tee_vbuf_is_non_sec(nwdata, nwdata_len))
		return TEE_ERROR_SECURITY;

	if (!crypto_ops.hash.get_ctx_size || !crypto_ops.hash.init ||
	    !crypto_ops.hash.update || !crypto_ops.hash.final) {
		res = TEE_ERROR_NOT_IMPLEMENTED;
		goto out;
	}
	hash_algo = TEE_DIGEST_HASH_TO_ALGO(shdr->algo);
	res = crypto_ops.hash.get_ctx_size(hash_algo, &hash_ctx_size);
	if (res != TEE_SUCCESS)
		goto out;
	hash_ctx = malloc(hash_ctx_size);
	if (!hash_ctx) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	res = crypto_ops.hash.init(hash_ctx, hash_algo);
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_ops.hash.update(hash_ctx, hash_algo,
				     (uint8_t *)shdr, sizeof(struct shdr));
	if (res != TEE_SUCCESS)
		goto out;

	res = elf_load_init(hash_ctx, hash_algo, nwdata, nwdata_len,
			    &elf_state);
	if (res != TEE_SUCCESS)
		goto out;

	res = elf_load_head(elf_state, sizeof(struct ta_head), &p, &vasize,
			    &utc->is_32bit);
	if (res != TEE_SUCCESS)
		goto out;
	ta_head = p;

	utc->mm = tee_mm_alloc(&tee_mm_sec_ddr, vasize);
	if (!utc->mm) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Currently all TA must execute from DDR */
	if (!(ta_head->flags & TA_FLAG_EXEC_DDR)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	/* Temporary assignment to setup memory mapping */
	utc->ctx.flags = TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR;

	/* Ensure proper aligment of stack */
	utc->stack_size = ROUNDUP(ta_head->stack_size, STACK_ALIGNMENT);

	utc->mm_stack = tee_mm_alloc(&tee_mm_sec_ddr, utc->stack_size);
	if (!utc->mm_stack) {
		EMSG("Failed to allocate %zu bytes for user stack",
		     utc->stack_size);
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * Map physical memory into TA virtual memory
	 */

	res = tee_mmu_init(utc);
	if (res != TEE_SUCCESS)
		goto out;

	res = load_elf_segments(utc, elf_state, true /* init attrs */);
	if (res != TEE_SUCCESS)
		goto out;

	tee_mmu_set_ctx(&utc->ctx);

	res = elf_load_body(elf_state, tee_mmu_get_load_addr(&utc->ctx));
	if (res != TEE_SUCCESS)
		goto out;

	digest = malloc(shdr->hash_size);
	if (!digest) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = crypto_ops.hash.final(hash_ctx, hash_algo, digest,
				    shdr->hash_size);
	if (res != TEE_SUCCESS)
		goto out;

	if (memcmp(digest, SHDR_GET_HASH(shdr), shdr->hash_size) != 0) {
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	/*
	 * Replace the init attributes with attributes used when the TA is
	 * running.
	 */
	res = load_elf_segments(utc, elf_state, false /* final attrs */);
	if (res != TEE_SUCCESS)
		goto out;

	cache_maintenance_l1(DCACHE_AREA_CLEAN,
			     (void *)tee_mmu_get_load_addr(&utc->ctx), vasize);
	cache_maintenance_l1(ICACHE_AREA_INVALIDATE,
			     (void *)tee_mmu_get_load_addr(&utc->ctx), vasize);
out:
	elf_load_final(elf_state);
	free(digest);
	free(hash_ctx);
	return res;
}

/*-----------------------------------------------------------------------------
 * Loads TA header and hashes.
 * Verifies the TA signature.
 * Returns context ptr and TEE_Result.
 *---------------------------------------------------------------------------*/
static TEE_Result ta_load(const TEE_UUID *uuid, const struct shdr *signed_ta,
			struct tee_ta_ctx **ta_ctx)
{
	TEE_Result res;
	/* man_flags: mandatory flags */
	uint32_t man_flags = TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR;
	/* opt_flags: optional flags */
	uint32_t opt_flags = man_flags | TA_FLAG_SINGLE_INSTANCE |
	    TA_FLAG_MULTI_SESSION | TA_FLAG_UNSAFE_NW_PARAMS |
	    TA_FLAG_INSTANCE_KEEP_ALIVE;
	struct user_ta_ctx *utc = NULL;
	struct shdr *sec_shdr = NULL;
	struct ta_head *ta_head;

	res = load_header(signed_ta, &sec_shdr);
	if (res != TEE_SUCCESS)
		goto error_return;

	res = check_shdr(sec_shdr);
	if (res != TEE_SUCCESS)
		goto error_return;

	/*
	 * ------------------------------------------------------------------
	 * 2nd step: Register context
	 * Alloc and init the ta context structure, alloc physical/virtual
	 * memories to store/map the TA.
	 * ------------------------------------------------------------------
	 */

	/*
	 * Register context
	 */

	/* code below must be protected by mutex (multi-threaded) */
	utc = calloc(1, sizeof(struct user_ta_ctx));
	if (!utc) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto error_return;
	}
	TAILQ_INIT(&utc->open_sessions);
	TAILQ_INIT(&utc->cryp_states);
	TAILQ_INIT(&utc->objects);
	TAILQ_INIT(&utc->storage_enums);
#if defined(CFG_SE_API)
	utc->se_service = NULL;
#endif

	res = load_elf(utc, sec_shdr, signed_ta);
	if (res != TEE_SUCCESS)
		goto error_return;

	utc->load_addr = tee_mmu_get_load_addr(&utc->ctx);
	ta_head = (struct ta_head *)(vaddr_t)utc->load_addr;

	if (memcmp(&ta_head->uuid, uuid, sizeof(TEE_UUID)) != 0) {
		res = TEE_ERROR_SECURITY;
		goto error_return;
	}

	/* check input flags bitmask consistency and save flags */
	if ((ta_head->flags & opt_flags) != ta_head->flags ||
	    (ta_head->flags & man_flags) != man_flags) {
		EMSG("TA flag issue: flags=%x opt=%X man=%X",
		     ta_head->flags, opt_flags, man_flags);
		res = TEE_ERROR_BAD_FORMAT;
		goto error_return;
	}

	utc->ctx.flags = ta_head->flags;
	utc->ctx.uuid = ta_head->uuid;
	utc->entry_func = ta_head->entry.ptr64;

	utc->ctx.ref_count = 1;

	condvar_init(&utc->ctx.busy_cv);
	TAILQ_INSERT_TAIL(&tee_ctxes, &utc->ctx, link);
	*ta_ctx = &utc->ctx;

	DMSG("Loaded TA at 0x%" PRIxPTR, tee_mm_get_smem(utc->mm));
	DMSG("ELF load address 0x%x", utc->load_addr);

	tee_mmu_set_ctx(NULL);
	/* end thread protection (multi-threaded) */

	free(sec_shdr);
	return TEE_SUCCESS;

error_return:
	free(sec_shdr);
	tee_mmu_set_ctx(NULL);
	if (utc) {
		tee_mmu_final(utc);
		tee_mm_free(utc->mm_stack);
		tee_mm_free(utc->mm);
		free(utc);
	}
	return res;
}

static void init_utee_param(struct utee_params *up,
			const struct tee_ta_param *p)
{
	size_t n;

	up->types = p->types;
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uintptr_t a;
		uintptr_t b;

		switch (TEE_PARAM_TYPE_GET(p->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			a = (uintptr_t)p->params[n].memref.buffer;
			b = p->params[n].memref.size;
			break;
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			a = p->params[n].value.a;
			b = p->params[n].value.b;
			break;
		default:
			a = 0;
			b = 0;
			break;
		}
		/* See comment for struct utee_params in utee_types.h */
		up->vals[n * 2] = a;
		up->vals[n * 2 + 1] = b;
	}
}

static void update_from_utee_param(struct tee_ta_param *p,
			const struct utee_params *up)
{
	size_t n;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(p->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			/* See comment for struct utee_params in utee_types.h */
			p->params[n].memref.size = up->vals[n * 2 + 1];
			break;
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			/* See comment for struct utee_params in utee_types.h */
			p->params[n].value.a = up->vals[n * 2];
			p->params[n].value.b = up->vals[n * 2 + 1];
			break;
		default:
			break;
		}
	}
}

static void clear_vfp_state(struct user_ta_ctx *utc __unused)
{
#ifdef CFG_WITH_VFP
	thread_user_clear_vfp(&utc->vfp);
#endif
}

static TEE_Result user_ta_enter(TEE_ErrorOrigin *err,
			struct tee_ta_session *session,
			enum utee_entry_func func, uint32_t cmd,
			struct tee_ta_param *param)
{
	TEE_Result res;
	struct utee_params *usr_params;
	tee_uaddr_t usr_stack;
	struct user_ta_ctx *utc = to_user_ta_ctx(session->ctx);
	TEE_ErrorOrigin serr = TEE_ORIGIN_TEE;
	struct tee_ta_session *s __maybe_unused;

	TEE_ASSERT((utc->ctx.flags & TA_FLAG_EXEC_DDR) != 0);

	/* Map user space memory */
	res = tee_mmu_map_param(utc, param);
	if (res != TEE_SUCCESS)
		goto cleanup_return;

	/* Switch to user ctx */
	tee_ta_push_current_session(session);

	/* Make room for usr_params at top of stack */
	usr_stack = (tee_uaddr_t)phys_to_virt(tee_mm_get_smem(utc->mm_stack) +
				 utc->stack_size - 1, MEM_AREA_TA_VASPACE) + 1;
	usr_stack -= ROUNDUP(sizeof(struct utee_params), STACK_ALIGNMENT);
	usr_params = (struct utee_params *)usr_stack;
	init_utee_param(usr_params, param);

	res = thread_enter_user_mode(func, tee_svc_kaddr_to_uref(session),
				     (vaddr_t)usr_params, cmd, usr_stack,
				     utc->entry_func, utc->is_32bit,
				     &utc->ctx.panicked, &utc->ctx.panic_code);

	clear_vfp_state(utc);
	/*
	 * According to GP spec the origin should allways be set to the
	 * TA after TA execution
	 */
	serr = TEE_ORIGIN_TRUSTED_APP;

	if (utc->ctx.panicked) {
		DMSG("tee_user_ta_enter: TA panicked with code 0x%x\n",
		     utc->ctx.panic_code);
		serr = TEE_ORIGIN_TEE;
		res = TEE_ERROR_TARGET_DEAD;
	}

	/* Copy out value results */
	update_from_utee_param(param, usr_params);

	s = tee_ta_pop_current_session();
	assert(s == session);
cleanup_return:

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
static TEE_Result rpc_load(const TEE_UUID *uuid, struct shdr **ta,
			uint64_t *cookie_ta)
{
	TEE_Result res;
	struct optee_msg_param params[2];
	paddr_t phta = 0;
	uint64_t cta = 0;


	if (!uuid || !ta || !cookie_ta)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(params, 0, sizeof(params));
	params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	memcpy(&params[0].u.value, uuid, sizeof(TEE_UUID));
	params[1].attr = OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT;
	params[1].u.tmem.buf_ptr = 0;
	params[1].u.tmem.size = 0;
	params[1].u.tmem.shm_ref = 0;

	res = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_LOAD_TA, 2, params);
	if (res != TEE_SUCCESS)
		return res;

	thread_rpc_alloc_payload(params[1].u.tmem.size, &phta, &cta);
	if (!phta)
		return TEE_ERROR_OUT_OF_MEMORY;

	*ta = phys_to_virt(phta, MEM_AREA_NSEC_SHM);
	if (!*ta) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	*cookie_ta = cta;

	params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	memcpy(&params[0].u.value, uuid, sizeof(TEE_UUID));
	params[1].attr = OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT;
	params[1].u.tmem.buf_ptr = phta;
	params[1].u.tmem.shm_ref = cta;
	/* Note that params[1].u.tmem.size is already assigned */

	res = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_LOAD_TA, 2, params);
out:
	if (res != TEE_SUCCESS)
		thread_rpc_free_payload(cta);
	return res;
}

static TEE_Result init_session_with_signed_ta(const TEE_UUID *uuid,
				const struct shdr *signed_ta,
				struct tee_ta_session *s)
{
	TEE_Result res;

	DMSG("   Load dynamic TA");
	/* load and verify */
	res = ta_load(uuid, signed_ta, &s->ctx);
	if (res != TEE_SUCCESS)
		return res;

	DMSG("      dyn TA : %pUl", (void *)&s->ctx->uuid);

	return res;
}

static TEE_Result user_ta_enter_open_session(struct tee_ta_session *s,
			struct tee_ta_param *param, TEE_ErrorOrigin *eo)
{
	return user_ta_enter(eo, s, UTEE_ENTRY_FUNC_OPEN_SESSION, 0, param);
}

static TEE_Result user_ta_enter_invoke_cmd(struct tee_ta_session *s,
			uint32_t cmd, struct tee_ta_param *param,
			TEE_ErrorOrigin *eo)
{
	return user_ta_enter(eo, s, UTEE_ENTRY_FUNC_INVOKE_COMMAND, cmd, param);
}

static void user_ta_enter_close_session(struct tee_ta_session *s)
{
	TEE_ErrorOrigin eo;
	struct tee_ta_param param = { 0 };

	user_ta_enter(&eo, s, UTEE_ENTRY_FUNC_CLOSE_SESSION, 0, &param);
}

static void user_ta_dump_state(struct tee_ta_ctx *ctx)
{
	struct user_ta_ctx *utc __maybe_unused = to_user_ta_ctx(ctx);

	EMSG_RAW("- load addr : 0x%x    ctx-idr: %d",
		 utc->load_addr, utc->context);
	EMSG_RAW("- code area : 0x%" PRIxPTR " %zu",
		 tee_mm_get_smem(utc->mm), tee_mm_get_bytes(utc->mm));
	EMSG_RAW("- stack: 0x%" PRIxPTR " stack:%zu",
		 tee_mm_get_smem(utc->mm_stack), utc->stack_size);
}
KEEP_PAGER(user_ta_dump_state);

static void user_ta_ctx_destroy(struct tee_ta_ctx *ctx)
{
	struct user_ta_ctx *utc = to_user_ta_ctx(ctx);

	/*
	 * Clean all traces of the TA, both RO and RW data.
	 * No L2 cache maintenance to avoid sync problems
	 */
	if (ctx->flags & TA_FLAG_EXEC_DDR) {
		paddr_t pa;
		void *va;
		uint32_t s;

		if (utc->mm) {
			pa = tee_mm_get_smem(utc->mm);
			va = phys_to_virt(pa, MEM_AREA_TA_RAM);
			if (va) {
				s = tee_mm_get_bytes(utc->mm);
				memset(va, 0, s);
				cache_maintenance_l1(DCACHE_AREA_CLEAN, va, s);
			}
		}

		if (utc->mm_stack) {
			pa = tee_mm_get_smem(utc->mm_stack);
			va = phys_to_virt(pa, MEM_AREA_TA_RAM);
			if (va) {
				s = tee_mm_get_bytes(utc->mm_stack);
				memset(va, 0, s);
				cache_maintenance_l1(DCACHE_AREA_CLEAN, va, s);
			}
		}
	}

	/*
	 * Close sessions opened by this TA
	 * Note that tee_ta_close_session() removes the item
	 * from the utc->open_sessions list.
	 */
	while (!TAILQ_EMPTY(&utc->open_sessions)) {
		tee_ta_close_session(TAILQ_FIRST(&utc->open_sessions),
				     &utc->open_sessions, KERN_IDENTITY);
	}

	tee_mmu_final(utc);
	tee_mm_free(utc->mm_stack);
	tee_mm_free(utc->mm);

	/* Free cryp states created by this TA */
	tee_svc_cryp_free_states(utc);
	/* Close cryp objects opened by this TA */
	tee_obj_close_all(utc);
	/* Free emums created by this TA */
	tee_svc_storage_close_all_enum(utc);

	free(utc);
}

static const struct tee_ta_ops user_ta_ops __rodata_unpaged = {
	.enter_open_session = user_ta_enter_open_session,
	.enter_invoke_cmd = user_ta_enter_invoke_cmd,
	.enter_close_session = user_ta_enter_close_session,
	.dump_state = user_ta_dump_state,
	.destroy = user_ta_ctx_destroy,
};

TEE_Result tee_ta_init_user_ta_session(const TEE_UUID *uuid,
			struct tee_ta_session *s)
{
	TEE_Result res;
	struct shdr *ta = NULL;
	uint64_t cookie_ta = 0;


	/* Request TA from tee-supplicant */
	res = rpc_load(uuid, &ta, &cookie_ta);
	if (res != TEE_SUCCESS)
		return res;

	res = init_session_with_signed_ta(uuid, ta, s);
	/*
	 * Free normal world shared memory now that the TA either has been
	 * copied into secure memory or the TA failed to be initialized.
	 */
	thread_rpc_free_payload(cookie_ta);

	if (res == TEE_SUCCESS)
		s->ctx->ops = &user_ta_ops;
	return res;
}
