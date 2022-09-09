// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019-2021, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <io.h>
#include <kernel/misc.h>
#include <kernel/msg_param.h>
#include <kernel/notif.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <kernel/virtualization.h>
#include <mm/core_mmu.h>
#include <optee_msg.h>
#include <optee_rpc_cmd.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>
#include <string.h>
#include <tee/entry_fast.h>
#include <tee/entry_std.h>
#include <tee/tee_cryp_utl.h>
#include <tee/tee_fs_rpc.h>

static bool thread_prealloc_rpc_cache;
static unsigned int thread_rpc_pnum;

static_assert(NOTIF_VALUE_DO_BOTTOM_HALF ==
	      OPTEE_SMC_ASYNC_NOTIF_VALUE_DO_BOTTOM_HALF);

void thread_handle_fast_smc(struct thread_smc_args *args)
{
	thread_check_canaries();

	if (IS_ENABLED(CFG_VIRTUALIZATION) &&
	    virt_set_guest(args->a7)) {
		args->a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		goto out;
	}

	tee_entry_fast(args);

	if (IS_ENABLED(CFG_VIRTUALIZATION))
		virt_unset_guest();

out:
	/* Fast handlers must not unmask any exceptions */
	assert(thread_get_exceptions() == THREAD_EXCP_ALL);
}

uint32_t thread_handle_std_smc(uint32_t a0, uint32_t a1, uint32_t a2,
			       uint32_t a3, uint32_t a4, uint32_t a5,
			       uint32_t a6 __unused, uint32_t a7 __maybe_unused)
{
	uint32_t rv = OPTEE_SMC_RETURN_OK;

	thread_check_canaries();

	if (IS_ENABLED(CFG_VIRTUALIZATION) && virt_set_guest(a7))
		return OPTEE_SMC_RETURN_ENOTAVAIL;

	/*
	 * thread_resume_from_rpc() and thread_alloc_and_run() only return
	 * on error. Successful return is done via thread_exit() or
	 * thread_rpc().
	 */
	if (a0 == OPTEE_SMC_CALL_RETURN_FROM_RPC) {
		thread_resume_from_rpc(a3, a1, a2, a4, a5);
		rv = OPTEE_SMC_RETURN_ERESUME;
	} else {
		thread_alloc_and_run(a0, a1, a2, a3, 0, 0);
		rv = OPTEE_SMC_RETURN_ETHREAD_LIMIT;
	}

	if (IS_ENABLED(CFG_VIRTUALIZATION))
		virt_unset_guest();

	return rv;
}

/**
 * Free physical memory previously allocated with thread_rpc_alloc_arg()
 *
 * @cookie:	cookie received when allocating the buffer
 */
static void thread_rpc_free_arg(uint64_t cookie)
{
	if (cookie) {
		uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = {
			OPTEE_SMC_RETURN_RPC_FREE
		};

		reg_pair_from_64(cookie, rpc_args + 1, rpc_args + 2);
		thread_rpc(rpc_args);
	}
}

static uint32_t get_msg_arg(struct mobj *mobj, size_t offset,
			    size_t *num_params, struct optee_msg_arg **arg,
			    struct optee_msg_arg **rpc_arg)
{
	void *p = NULL;
	size_t sz = 0;

	if (!mobj)
		return OPTEE_SMC_RETURN_EBADADDR;

	p = mobj_get_va(mobj, offset, sizeof(struct optee_msg_arg));
	if (!p || !IS_ALIGNED_WITH_TYPE(p, struct optee_msg_arg))
		return OPTEE_SMC_RETURN_EBADADDR;

	*arg = p;
	*num_params = READ_ONCE((*arg)->num_params);
	if (*num_params > OPTEE_MSG_MAX_NUM_PARAMS)
		return OPTEE_SMC_RETURN_EBADADDR;

	sz = OPTEE_MSG_GET_ARG_SIZE(*num_params);
	if (!mobj_get_va(mobj, offset, sz))
		return OPTEE_SMC_RETURN_EBADADDR;

	if (rpc_arg) {
		size_t rpc_sz = 0;

		rpc_sz = OPTEE_MSG_GET_ARG_SIZE(THREAD_RPC_MAX_NUM_PARAMS);
		p = mobj_get_va(mobj, offset + sz, rpc_sz);
		if (!p)
			return OPTEE_SMC_RETURN_EBADADDR;
		*rpc_arg = p;
	}

	return OPTEE_SMC_RETURN_OK;
}

static void clear_prealloc_rpc_cache(struct thread_ctx *thr)
{
	thread_rpc_free_arg(mobj_get_cookie(thr->rpc_mobj));
	mobj_put(thr->rpc_mobj);
	thr->rpc_arg = NULL;
	thr->rpc_mobj = NULL;
}

static uint32_t call_entry_std(struct optee_msg_arg *arg, size_t num_params,
			       struct optee_msg_arg *rpc_arg)
{
	struct thread_ctx *thr = threads + thread_get_id();
	uint32_t rv = 0;

	if (rpc_arg) {
		/*
		 * In case the prealloc RPC arg cache is enabled, clear the
		 * cached object for this thread.
		 *
		 * Normally it doesn't make sense to have the prealloc RPC
		 * arg cache enabled together with a supplied RPC arg
		 * struct. But if it is we must use the supplied struct and
		 * at the same time make sure to not break anything.
		 */
		if (IS_ENABLED(CFG_PREALLOC_RPC_CACHE) &&
		    thread_prealloc_rpc_cache)
			clear_prealloc_rpc_cache(thr);
		thr->rpc_arg = rpc_arg;
	}

	if (tee_entry_std(arg, num_params))
		rv = OPTEE_SMC_RETURN_EBADCMD;
	else
		rv = OPTEE_SMC_RETURN_OK;

	thread_rpc_shm_cache_clear(&thr->shm_cache);
	if (rpc_arg)
		thr->rpc_arg = NULL;

	if (rv == OPTEE_SMC_RETURN_OK &&
	    !(IS_ENABLED(CFG_PREALLOC_RPC_CACHE) && thread_prealloc_rpc_cache))
		clear_prealloc_rpc_cache(thr);

	return rv;
}

static uint32_t std_entry_with_parg(paddr_t parg, bool with_rpc_arg)
{
	size_t sz = sizeof(struct optee_msg_arg);
	struct optee_msg_arg *rpc_arg = NULL;
	struct optee_msg_arg *arg = NULL;
	struct mobj *mobj = NULL;
	size_t num_params = 0;
	uint32_t rv = 0;

	/* Check if this region is in static shared space */
	if (core_pbuf_is(CORE_MEM_NSEC_SHM, parg, sz)) {
		if (!IS_ALIGNED_WITH_TYPE(parg, struct optee_msg_arg))
			goto bad_addr;

		arg = phys_to_virt(parg, MEM_AREA_NSEC_SHM,
				   sizeof(struct optee_msg_arg));
		if (!arg)
			goto bad_addr;

		num_params = READ_ONCE(arg->num_params);
		if (num_params > OPTEE_MSG_MAX_NUM_PARAMS)
			return OPTEE_SMC_RETURN_EBADADDR;

		sz = OPTEE_MSG_GET_ARG_SIZE(num_params);
		if (with_rpc_arg) {
			rpc_arg = (void *)((uint8_t *)arg + sz);
			sz += OPTEE_MSG_GET_ARG_SIZE(THREAD_RPC_MAX_NUM_PARAMS);
		}
		if (!core_pbuf_is(CORE_MEM_NSEC_SHM, parg, sz))
			goto bad_addr;

		return call_entry_std(arg, num_params, rpc_arg);
	} else {
		if (parg & SMALL_PAGE_MASK)
			goto bad_addr;
		/*
		 * mobj_mapped_shm_alloc checks if parg resides in nonsec
		 * ddr.
		 */
		mobj = mobj_mapped_shm_alloc(&parg, 1, 0, 0);
		if (!mobj)
			goto bad_addr;
		if (with_rpc_arg)
			rv = get_msg_arg(mobj, 0, &num_params, &arg, &rpc_arg);
		else
			rv = get_msg_arg(mobj, 0, &num_params, &arg, NULL);
		if (!rv)
			rv = call_entry_std(arg, num_params, rpc_arg);
		mobj_put(mobj);
		return rv;
	}

bad_addr:
	EMSG("Bad arg address 0x%"PRIxPA, parg);
	return OPTEE_SMC_RETURN_EBADADDR;
}

static uint32_t std_entry_with_regd_arg(uint64_t cookie, size_t offset)
{
	struct optee_msg_arg *rpc_arg = NULL;
	struct optee_msg_arg *arg = NULL;
	size_t num_params = 0;
	struct mobj *mobj = NULL;
	uint32_t rv = 0;

	mobj = mobj_reg_shm_get_by_cookie(cookie);
	if (!mobj) {
		EMSG("Bad arg cookie 0x%"PRIx64, cookie);
		return OPTEE_SMC_RETURN_EBADADDR;
	}

	if (mobj_inc_map(mobj)) {
		rv = OPTEE_SMC_RETURN_ENOMEM;
		goto out;
	}

	rv = get_msg_arg(mobj, offset, &num_params, &arg, &rpc_arg);
	if (!rv)
		rv = call_entry_std(arg, num_params, rpc_arg);

	mobj_dec_map(mobj);
out:
	mobj_put(mobj);

	return rv;
}

static uint32_t std_smc_entry(uint32_t a0, uint32_t a1, uint32_t a2,
			      uint32_t a3 __unused)
{
	const bool with_rpc_arg = true;

	switch (a0) {
	case OPTEE_SMC_CALL_WITH_ARG:
		return std_entry_with_parg(reg_pair_to_64(a1, a2),
					   !with_rpc_arg);
	case OPTEE_SMC_CALL_WITH_RPC_ARG:
		return std_entry_with_parg(reg_pair_to_64(a1, a2),
					   with_rpc_arg);
	case OPTEE_SMC_CALL_WITH_REGD_ARG:
		return std_entry_with_regd_arg(reg_pair_to_64(a1, a2), a3);
	default:
		EMSG("Unknown SMC 0x%"PRIx32, a0);
		return OPTEE_SMC_RETURN_EBADCMD;
	}
}

/*
 * Helper routine for the assembly function thread_std_smc_entry()
 *
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
uint32_t __weak __thread_std_smc_entry(uint32_t a0, uint32_t a1, uint32_t a2,
				       uint32_t a3, uint32_t a4 __unused,
				       uint32_t a5 __unused)
{
	if (IS_ENABLED(CFG_VIRTUALIZATION))
		virt_on_stdcall();

	return std_smc_entry(a0, a1, a2, a3);
}

bool thread_disable_prealloc_rpc_cache(uint64_t *cookie)
{
	bool rv = false;
	size_t n = 0;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	thread_lock_global();

	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (threads[n].state != THREAD_STATE_FREE) {
			rv = false;
			goto out;
		}
	}

	rv = true;

	if (IS_ENABLED(CFG_PREALLOC_RPC_CACHE)) {
		for (n = 0; n < CFG_NUM_THREADS; n++) {
			if (threads[n].rpc_arg) {
				*cookie = mobj_get_cookie(threads[n].rpc_mobj);
				mobj_put(threads[n].rpc_mobj);
				threads[n].rpc_arg = NULL;
				threads[n].rpc_mobj = NULL;
				goto out;
			}
		}
	}

	*cookie = 0;
	thread_prealloc_rpc_cache = false;
out:
	thread_unlock_global();
	thread_unmask_exceptions(exceptions);
	return rv;
}

bool thread_enable_prealloc_rpc_cache(void)
{
	bool rv = false;
	size_t n = 0;
	uint32_t exceptions = 0;

	if (!IS_ENABLED(CFG_PREALLOC_RPC_CACHE))
		return true;

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	thread_lock_global();

	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (threads[n].state != THREAD_STATE_FREE) {
			rv = false;
			goto out;
		}
	}

	rv = true;
	thread_prealloc_rpc_cache = true;
out:
	thread_unlock_global();
	thread_unmask_exceptions(exceptions);
	return rv;
}

static struct mobj *rpc_shm_mobj_alloc(paddr_t pa, size_t sz, uint64_t cookie)
{
	/* Check if this region is in static shared space */
	if (core_pbuf_is(CORE_MEM_NSEC_SHM, pa, sz))
		return mobj_shm_alloc(pa, sz, cookie);

	if (IS_ENABLED(CFG_CORE_DYN_SHM) &&
	    !(pa & SMALL_PAGE_MASK) && sz <= SMALL_PAGE_SIZE)
		return mobj_mapped_shm_alloc(&pa, 1, 0, cookie);

	return NULL;
}

/**
 * Allocates data for struct optee_msg_arg.
 *
 * @size:	size in bytes of struct optee_msg_arg
 *
 * @returns	mobj that describes allocated buffer or NULL on error
 */
static struct mobj *thread_rpc_alloc_arg(size_t size)
{
	paddr_t pa;
	uint64_t co;
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = {
		OPTEE_SMC_RETURN_RPC_ALLOC, size
	};
	struct mobj *mobj = NULL;

	thread_rpc(rpc_args);

	/* Registers 1 and 2 passed from normal world */
	pa = reg_pair_to_64(rpc_args[0], rpc_args[1]);
	/* Registers 4 and 5 passed from normal world */
	co = reg_pair_to_64(rpc_args[2], rpc_args[3]);

	if (!IS_ALIGNED_WITH_TYPE(pa, struct optee_msg_arg))
		goto err;

	mobj = rpc_shm_mobj_alloc(pa, size, co);
	if (!mobj)
		goto err;

	return mobj;
err:
	thread_rpc_free_arg(co);
	mobj_put(mobj);
	return NULL;
}

static bool set_rmem(struct optee_msg_param *param,
		     struct thread_param *tpm)
{
	param->attr = tpm->attr - THREAD_PARAM_ATTR_MEMREF_IN +
		      OPTEE_MSG_ATTR_TYPE_RMEM_INPUT;
	param->u.rmem.offs = tpm->u.memref.offs;
	param->u.rmem.size = tpm->u.memref.size;
	if (tpm->u.memref.mobj) {
		param->u.rmem.shm_ref = mobj_get_cookie(tpm->u.memref.mobj);
		if (!param->u.rmem.shm_ref)
			return false;
	} else {
		param->u.rmem.shm_ref = 0;
	}

	return true;
}

static bool set_tmem(struct optee_msg_param *param,
		     struct thread_param *tpm)
{
	paddr_t pa = 0;
	uint64_t shm_ref = 0;
	struct mobj *mobj = tpm->u.memref.mobj;

	param->attr = tpm->attr - THREAD_PARAM_ATTR_MEMREF_IN +
		      OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
	if (mobj) {
		shm_ref = mobj_get_cookie(mobj);
		if (!shm_ref)
			return false;
		if (mobj_get_pa(mobj, tpm->u.memref.offs, 0, &pa))
			return false;
	}

	param->u.tmem.size = tpm->u.memref.size;
	param->u.tmem.buf_ptr = pa;
	param->u.tmem.shm_ref = shm_ref;

	return true;
}

static uint32_t get_rpc_arg(uint32_t cmd, size_t num_params,
			    struct thread_param *params, void **arg_ret,
			    uint64_t *carg_ret)
{
	struct thread_ctx *thr = threads + thread_get_id();
	struct optee_msg_arg *arg = thr->rpc_arg;
	size_t sz = OPTEE_MSG_GET_ARG_SIZE(THREAD_RPC_MAX_NUM_PARAMS);

	if (num_params > THREAD_RPC_MAX_NUM_PARAMS)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!arg) {
		struct mobj *mobj = thread_rpc_alloc_arg(sz);

		if (!mobj)
			return TEE_ERROR_OUT_OF_MEMORY;

		arg = mobj_get_va(mobj, 0, sz);
		if (!arg) {
			thread_rpc_free_arg(mobj_get_cookie(mobj));
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		thr->rpc_arg = arg;
		thr->rpc_mobj = mobj;
	}

	memset(arg, 0, OPTEE_MSG_GET_ARG_SIZE(num_params));
	arg->cmd = cmd;
	arg->num_params = num_params;
	arg->ret = TEE_ERROR_GENERIC; /* in case value isn't updated */

	for (size_t n = 0; n < num_params; n++) {
		switch (params[n].attr) {
		case THREAD_PARAM_ATTR_NONE:
			arg->params[n].attr = OPTEE_MSG_ATTR_TYPE_NONE;
			break;
		case THREAD_PARAM_ATTR_VALUE_IN:
		case THREAD_PARAM_ATTR_VALUE_OUT:
		case THREAD_PARAM_ATTR_VALUE_INOUT:
			arg->params[n].attr = params[n].attr -
					      THREAD_PARAM_ATTR_VALUE_IN +
					      OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
			arg->params[n].u.value.a = params[n].u.value.a;
			arg->params[n].u.value.b = params[n].u.value.b;
			arg->params[n].u.value.c = params[n].u.value.c;
			break;
		case THREAD_PARAM_ATTR_MEMREF_IN:
		case THREAD_PARAM_ATTR_MEMREF_OUT:
		case THREAD_PARAM_ATTR_MEMREF_INOUT:
			if (!params[n].u.memref.mobj ||
			    mobj_matches(params[n].u.memref.mobj,
					 CORE_MEM_NSEC_SHM)) {
				if (!set_tmem(arg->params + n, params + n))
					return TEE_ERROR_BAD_PARAMETERS;
			} else  if (mobj_matches(params[n].u.memref.mobj,
						 CORE_MEM_REG_SHM)) {
				if (!set_rmem(arg->params + n, params + n))
					return TEE_ERROR_BAD_PARAMETERS;
			} else {
				return TEE_ERROR_BAD_PARAMETERS;
			}
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	*arg_ret = arg;
	*carg_ret = mobj_get_cookie(thr->rpc_mobj);

	return TEE_SUCCESS;
}

static uint32_t get_rpc_arg_res(struct optee_msg_arg *arg, size_t num_params,
				struct thread_param *params)
{
	for (size_t n = 0; n < num_params; n++) {
		switch (params[n].attr) {
		case THREAD_PARAM_ATTR_VALUE_OUT:
		case THREAD_PARAM_ATTR_VALUE_INOUT:
			params[n].u.value.a = arg->params[n].u.value.a;
			params[n].u.value.b = arg->params[n].u.value.b;
			params[n].u.value.c = arg->params[n].u.value.c;
			break;
		case THREAD_PARAM_ATTR_MEMREF_OUT:
		case THREAD_PARAM_ATTR_MEMREF_INOUT:
			/*
			 * rmem.size and tmem.size is the same type and
			 * location.
			 */
			params[n].u.memref.size = arg->params[n].u.rmem.size;
			break;
		default:
			break;
		}
	}

	return arg->ret;
}

uint32_t thread_rpc_cmd(uint32_t cmd, size_t num_params,
			struct thread_param *params)
{
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = { OPTEE_SMC_RETURN_RPC_CMD };
	void *arg = NULL;
	uint64_t carg = 0;
	uint32_t ret = 0;

	/* The source CRYPTO_RNG_SRC_JITTER_RPC is safe to use here */
	plat_prng_add_jitter_entropy(CRYPTO_RNG_SRC_JITTER_RPC,
				     &thread_rpc_pnum);

	ret = get_rpc_arg(cmd, num_params, params, &arg, &carg);
	if (ret)
		return ret;

	reg_pair_from_64(carg, rpc_args + 1, rpc_args + 2);
	thread_rpc(rpc_args);

	return get_rpc_arg_res(arg, num_params, params);
}

/**
 * Free physical memory previously allocated with thread_rpc_alloc()
 *
 * @cookie:	cookie received when allocating the buffer
 * @bt:		must be the same as supplied when allocating
 * @mobj:	mobj that describes allocated buffer
 *
 * This function also frees corresponding mobj.
 */
static void thread_rpc_free(unsigned int bt, uint64_t cookie, struct mobj *mobj)
{
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = { OPTEE_SMC_RETURN_RPC_CMD };
	void *arg = NULL;
	uint64_t carg = 0;
	struct thread_param param = THREAD_PARAM_VALUE(IN, bt, cookie, 0);
	uint32_t ret = get_rpc_arg(OPTEE_RPC_CMD_SHM_FREE, 1, &param,
				   &arg, &carg);

	mobj_put(mobj);

	if (!ret) {
		reg_pair_from_64(carg, rpc_args + 1, rpc_args + 2);
		thread_rpc(rpc_args);
	}
}

static struct mobj *get_rpc_alloc_res(struct optee_msg_arg *arg,
				      unsigned int bt, size_t size)
{
	struct mobj *mobj = NULL;
	uint64_t cookie = 0;
	size_t sz = 0;
	paddr_t p = 0;

	if (arg->ret || arg->num_params != 1)
		goto err;

	if (arg->params[0].attr != OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT  &&
	    arg->params[0].attr != (OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT |
				    OPTEE_MSG_ATTR_NONCONTIG))
		goto err;

	p = arg->params[0].u.tmem.buf_ptr;
	sz = READ_ONCE(arg->params[0].u.tmem.size);
	cookie = arg->params[0].u.tmem.shm_ref;
	if (sz < size)
		goto err;

	if (arg->params[0].attr == OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT)
		mobj = rpc_shm_mobj_alloc(p, sz, cookie);
	else
		mobj = msg_param_mobj_from_noncontig(p, sz, cookie, true);

	if (!mobj) {
		thread_rpc_free(bt, cookie, mobj);
		goto err;
	}

	assert(mobj_is_nonsec(mobj));
	return mobj;
err:
	EMSG("RPC allocation failed. Non-secure world result: ret=%#"
	     PRIx32" ret_origin=%#"PRIx32, arg->ret, arg->ret_origin);
	return NULL;
}

/**
 * Allocates shared memory buffer via RPC
 *
 * @size:	size in bytes of shared memory buffer
 * @align:	required alignment of buffer
 * @bt:		buffer type OPTEE_RPC_SHM_TYPE_*
 *
 * Returns a pointer to MOBJ for the memory on success, or NULL on failure.
 */
static struct mobj *thread_rpc_alloc(size_t size, size_t align, unsigned int bt)
{
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = { OPTEE_SMC_RETURN_RPC_CMD };
	void *arg = NULL;
	uint64_t carg = 0;
	struct thread_param param = THREAD_PARAM_VALUE(IN, bt, size, align);
	uint32_t ret = get_rpc_arg(OPTEE_RPC_CMD_SHM_ALLOC, 1, &param,
				   &arg, &carg);

	if (ret)
		return NULL;

	reg_pair_from_64(carg, rpc_args + 1, rpc_args + 2);
	thread_rpc(rpc_args);

	return get_rpc_alloc_res(arg, bt, size);
}

struct mobj *thread_rpc_alloc_payload(size_t size)
{
	return thread_rpc_alloc(size, 8, OPTEE_RPC_SHM_TYPE_APPL);
}

struct mobj *thread_rpc_alloc_kernel_payload(size_t size)
{
	/*
	 * Error out early since kernel private dynamic shared memory
	 * allocations don't currently use the `OPTEE_MSG_ATTR_NONCONTIG` bit
	 * and therefore cannot be larger than a page.
	 */
	if (IS_ENABLED(CFG_CORE_DYN_SHM) && size > SMALL_PAGE_SIZE)
		return NULL;

	return thread_rpc_alloc(size, 8, OPTEE_RPC_SHM_TYPE_KERNEL);
}

void thread_rpc_free_kernel_payload(struct mobj *mobj)
{
	thread_rpc_free(OPTEE_RPC_SHM_TYPE_KERNEL, mobj_get_cookie(mobj), mobj);
}

void thread_rpc_free_payload(struct mobj *mobj)
{
	thread_rpc_free(OPTEE_RPC_SHM_TYPE_APPL, mobj_get_cookie(mobj),
			mobj);
}

struct mobj *thread_rpc_alloc_global_payload(size_t size)
{
	return thread_rpc_alloc(size, 8, OPTEE_RPC_SHM_TYPE_GLOBAL);
}

void thread_rpc_free_global_payload(struct mobj *mobj)
{
	thread_rpc_free(OPTEE_RPC_SHM_TYPE_GLOBAL, mobj_get_cookie(mobj),
			mobj);
}
