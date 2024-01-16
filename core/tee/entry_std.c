// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <assert.h>
#include <compiler.h>
#include <initcall.h>
#include <io.h>
#include <kernel/linker.h>
#include <kernel/msg_param.h>
#include <kernel/notif.h>
#include <kernel/panic.h>
#include <kernel/tee_misc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <optee_msg.h>
#include <string.h>
#include <tee/entry_std.h>
#include <tee/tee_cryp_utl.h>
#include <tee/uuid.h>
#include <util.h>

#define SHM_CACHE_ATTRS	\
	(uint32_t)(core_mmu_is_shm_cached() ? \
		   TEE_MATTR_MEM_TYPE_CACHED : TEE_MATTR_MEM_TYPE_DEV)

/* Sessions opened from normal world */
static struct tee_ta_session_head tee_open_sessions =
TAILQ_HEAD_INITIALIZER(tee_open_sessions);

#ifdef CFG_CORE_RESERVED_SHM
static struct mobj *shm_mobj;
#endif
#ifdef CFG_SECURE_DATA_PATH
static struct mobj **sdp_mem_mobjs;
#endif

static unsigned int session_pnum;

static bool __maybe_unused param_mem_from_mobj(struct param_mem *mem,
					       struct mobj *mobj,
					       const paddr_t pa,
					       const size_t sz)
{
	paddr_t b;

	if (mobj_get_pa(mobj, 0, 0, &b) != TEE_SUCCESS)
		panic("mobj_get_pa failed");

	if (!core_is_buffer_inside(pa, MAX(sz, 1UL), b, mobj->size))
		return false;

	mem->mobj = mobj_get(mobj);
	mem->offs = pa - b;
	mem->size = sz;
	return true;
}

#ifdef CFG_CORE_FFA
static TEE_Result set_fmem_param(const struct optee_msg_param_fmem *fmem,
				 struct param_mem *mem)
{
	size_t req_size = 0;
	uint64_t global_id = READ_ONCE(fmem->global_id);
	size_t sz = READ_ONCE(fmem->size);

	if (global_id == OPTEE_MSG_FMEM_INVALID_GLOBAL_ID && !sz) {
		mem->mobj = NULL;
		mem->offs = 0;
		mem->size = 0;
		return TEE_SUCCESS;
	}
	mem->mobj = mobj_ffa_get_by_cookie(global_id,
					   READ_ONCE(fmem->internal_offs));
	if (!mem->mobj)
		return TEE_ERROR_BAD_PARAMETERS;

	mem->offs = reg_pair_to_64(READ_ONCE(fmem->offs_high),
				   READ_ONCE(fmem->offs_low));
	mem->size = sz;

	/*
	 * Check that the supplied offset and size is covered by the
	 * previously verified MOBJ.
	 */
	if (ADD_OVERFLOW(mem->offs, mem->size, &req_size) ||
	    mem->mobj->size < req_size)
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}
#else /*!CFG_CORE_FFA*/
/* fill 'struct param_mem' structure if buffer matches a valid memory object */
static TEE_Result set_tmem_param(const struct optee_msg_param_tmem *tmem,
				 uint32_t attr, struct param_mem *mem)
{
	struct mobj __maybe_unused **mobj;
	paddr_t pa = READ_ONCE(tmem->buf_ptr);
	size_t sz = READ_ONCE(tmem->size);

	/*
	 * Handle NULL memory reference
	 */
	if (!pa) {
		mem->mobj = NULL;
		mem->offs = 0;
		mem->size = 0;
		return TEE_SUCCESS;
	}

	/* Handle non-contiguous reference from a shared memory area */
	if (attr & OPTEE_MSG_ATTR_NONCONTIG) {
		uint64_t shm_ref = READ_ONCE(tmem->shm_ref);

		mem->mobj = msg_param_mobj_from_noncontig(pa, sz, shm_ref,
							  false);
		if (!mem->mobj)
			return TEE_ERROR_BAD_PARAMETERS;
		mem->offs = 0;
		mem->size = sz;
		return TEE_SUCCESS;
	}

#ifdef CFG_CORE_RESERVED_SHM
	/* Handle memory reference in the contiguous shared memory */
	if (param_mem_from_mobj(mem, shm_mobj, pa, sz))
		return TEE_SUCCESS;
#endif

#ifdef CFG_SECURE_DATA_PATH
	/* Handle memory reference to Secure Data Path memory areas */
	for (mobj = sdp_mem_mobjs; *mobj; mobj++)
		if (param_mem_from_mobj(mem, *mobj, pa, sz))
			return TEE_SUCCESS;
#endif

	return TEE_ERROR_BAD_PARAMETERS;
}

#ifdef CFG_CORE_DYN_SHM
static TEE_Result set_rmem_param(const struct optee_msg_param_rmem *rmem,
				 struct param_mem *mem)
{
	size_t req_size = 0;
	uint64_t shm_ref = READ_ONCE(rmem->shm_ref);
	size_t sz = READ_ONCE(rmem->size);

	mem->mobj = mobj_reg_shm_get_by_cookie(shm_ref);
	if (!mem->mobj)
		return TEE_ERROR_BAD_PARAMETERS;

	mem->offs = READ_ONCE(rmem->offs);
	mem->size = sz;

	/*
	 * Check that the supplied offset and size is covered by the
	 * previously verified MOBJ.
	 */
	if (ADD_OVERFLOW(mem->offs, mem->size, &req_size) ||
	    mem->mobj->size < req_size)
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}
#endif /*CFG_CORE_DYN_SHM*/
#endif /*!CFG_CORE_FFA*/

static TEE_Result copy_in_params(const struct optee_msg_param *params,
				 uint32_t num_params,
				 struct tee_ta_param *ta_param,
				 uint64_t *saved_attr)
{
	TEE_Result res;
	size_t n;
	uint8_t pt[TEE_NUM_PARAMS] = { 0 };

	if (num_params > TEE_NUM_PARAMS)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(ta_param, 0, sizeof(*ta_param));

	for (n = 0; n < num_params; n++) {
		uint32_t attr;

		saved_attr[n] = READ_ONCE(params[n].attr);

		if (saved_attr[n] & OPTEE_MSG_ATTR_META)
			return TEE_ERROR_BAD_PARAMETERS;

		attr = saved_attr[n] & OPTEE_MSG_ATTR_TYPE_MASK;
		switch (attr) {
		case OPTEE_MSG_ATTR_TYPE_NONE:
			pt[n] = TEE_PARAM_TYPE_NONE;
			break;
		case OPTEE_MSG_ATTR_TYPE_VALUE_INPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
			pt[n] = TEE_PARAM_TYPE_VALUE_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
			ta_param->u[n].val.a = READ_ONCE(params[n].u.value.a);
			ta_param->u[n].val.b = READ_ONCE(params[n].u.value.b);
			break;
#ifdef CFG_CORE_FFA
		case OPTEE_MSG_ATTR_TYPE_FMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_FMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_FMEM_INOUT:
			res = set_fmem_param(&params[n].u.fmem,
					     &ta_param->u[n].mem);
			if (res)
				return res;
			pt[n] = TEE_PARAM_TYPE_MEMREF_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_FMEM_INPUT;
			break;
#else /*!CFG_CORE_FFA*/
		case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
			res = set_tmem_param(&params[n].u.tmem, saved_attr[n],
					     &ta_param->u[n].mem);
			if (res)
				return res;
			pt[n] = TEE_PARAM_TYPE_MEMREF_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
			break;
#ifdef CFG_CORE_DYN_SHM
		case OPTEE_MSG_ATTR_TYPE_RMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
			res = set_rmem_param(&params[n].u.rmem,
					     &ta_param->u[n].mem);
			if (res)
				return res;
			pt[n] = TEE_PARAM_TYPE_MEMREF_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_RMEM_INPUT;
			break;
#endif /*CFG_CORE_DYN_SHM*/
#endif /*!CFG_CORE_FFA*/
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	ta_param->types = TEE_PARAM_TYPES(pt[0], pt[1], pt[2], pt[3]);

	return TEE_SUCCESS;
}

static void cleanup_shm_refs(const uint64_t *saved_attr,
			     struct tee_ta_param *param, uint32_t num_params)
{
	size_t n;

	for (n = 0; n < MIN((unsigned int)TEE_NUM_PARAMS, num_params); n++) {
		switch (saved_attr[n]) {
		case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
#ifdef CFG_CORE_DYN_SHM
		case OPTEE_MSG_ATTR_TYPE_RMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
#endif
			mobj_put(param->u[n].mem.mobj);
			break;
		default:
			break;
		}
	}
}

static void copy_out_param(struct tee_ta_param *ta_param, uint32_t num_params,
			   struct optee_msg_param *params, uint64_t *saved_attr)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		switch (TEE_PARAM_TYPE_GET(ta_param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			switch (saved_attr[n] & OPTEE_MSG_ATTR_TYPE_MASK) {
			case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
			case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
				params[n].u.tmem.size = ta_param->u[n].mem.size;
				break;
			case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
			case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
				params[n].u.rmem.size = ta_param->u[n].mem.size;
				break;
			default:
				break;
			}
			break;
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			params[n].u.value.a = ta_param->u[n].val.a;
			params[n].u.value.b = ta_param->u[n].val.b;
			break;
		default:
			break;
		}
	}
}

/*
 * Extracts mandatory parameter for open session.
 *
 * Returns
 * false : mandatory parameter wasn't found or malformatted
 * true  : paramater found and OK
 */
static TEE_Result get_open_session_meta(size_t num_params,
					struct optee_msg_param *params,
					size_t *num_meta, TEE_UUID *uuid,
					TEE_Identity *clnt_id)
{
	const uint32_t req_attr = OPTEE_MSG_ATTR_META |
				  OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;

	if (num_params < 2)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].attr != req_attr || params[1].attr != req_attr)
		return TEE_ERROR_BAD_PARAMETERS;

	tee_uuid_from_octets(uuid, (void *)&params[0].u.value);
	clnt_id->login = params[1].u.value.c;
	switch (clnt_id->login) {
	case TEE_LOGIN_PUBLIC:
	case TEE_LOGIN_REE_KERNEL:
		memset(&clnt_id->uuid, 0, sizeof(clnt_id->uuid));
		break;
	case TEE_LOGIN_USER:
	case TEE_LOGIN_GROUP:
	case TEE_LOGIN_APPLICATION:
	case TEE_LOGIN_APPLICATION_USER:
	case TEE_LOGIN_APPLICATION_GROUP:
		tee_uuid_from_octets(&clnt_id->uuid,
				     (void *)&params[1].u.value);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	*num_meta = 2;
	return TEE_SUCCESS;
}

static void entry_open_session(struct optee_msg_arg *arg, uint32_t num_params)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ErrorOrigin err_orig = TEE_ORIGIN_TEE;
	struct tee_ta_session *s = NULL;
	TEE_Identity clnt_id = { };
	TEE_UUID uuid = { };
	struct tee_ta_param param = { };
	size_t num_meta = 0;
	uint64_t saved_attr[TEE_NUM_PARAMS] = { 0 };

	res = get_open_session_meta(num_params, arg->params, &num_meta, &uuid,
				    &clnt_id);
	if (res != TEE_SUCCESS)
		goto out;

	res = copy_in_params(arg->params + num_meta, num_params - num_meta,
			     &param, saved_attr);
	if (res != TEE_SUCCESS)
		goto cleanup_shm_refs;

	res = tee_ta_open_session(&err_orig, &s, &tee_open_sessions, &uuid,
				  &clnt_id, TEE_TIMEOUT_INFINITE, &param);
	if (res != TEE_SUCCESS)
		s = NULL;
	copy_out_param(&param, num_params - num_meta, arg->params + num_meta,
		       saved_attr);

	/*
	 * The occurrence of open/close session command is usually
	 * un-predictable, using this property to increase randomness
	 * of prng
	 */
	plat_prng_add_jitter_entropy(CRYPTO_RNG_SRC_JITTER_SESSION,
				     &session_pnum);

cleanup_shm_refs:
	cleanup_shm_refs(saved_attr, &param, num_params - num_meta);

out:
	if (s)
		arg->session = s->id;
	else
		arg->session = 0;
	arg->ret = res;
	arg->ret_origin = err_orig;
}

static void entry_close_session(struct optee_msg_arg *arg, uint32_t num_params)
{
	TEE_Result res;
	struct tee_ta_session *s;

	if (num_params) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	plat_prng_add_jitter_entropy(CRYPTO_RNG_SRC_JITTER_SESSION,
				     &session_pnum);

	s = tee_ta_find_session(arg->session, &tee_open_sessions);
	res = tee_ta_close_session(s, &tee_open_sessions, NSAPP_IDENTITY);
out:
	arg->ret = res;
	arg->ret_origin = TEE_ORIGIN_TEE;
}

static void entry_invoke_command(struct optee_msg_arg *arg, uint32_t num_params)
{
	TEE_Result res;
	TEE_ErrorOrigin err_orig = TEE_ORIGIN_TEE;
	struct tee_ta_session *s;
	struct tee_ta_param param = { 0 };
	uint64_t saved_attr[TEE_NUM_PARAMS] = { 0 };

	res = copy_in_params(arg->params, num_params, &param, saved_attr);
	if (res != TEE_SUCCESS)
		goto out;

	s = tee_ta_get_session(arg->session, true, &tee_open_sessions);
	if (!s) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = tee_ta_invoke_command(&err_orig, s, NSAPP_IDENTITY,
				    TEE_TIMEOUT_INFINITE, arg->func, &param);

	tee_ta_put_session(s);

	copy_out_param(&param, num_params, arg->params, saved_attr);

out:
	cleanup_shm_refs(saved_attr, &param, num_params);

	arg->ret = res;
	arg->ret_origin = err_orig;
}

static void entry_cancel(struct optee_msg_arg *arg, uint32_t num_params)
{
	TEE_Result res;
	TEE_ErrorOrigin err_orig = TEE_ORIGIN_TEE;
	struct tee_ta_session *s;

	if (num_params) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	s = tee_ta_get_session(arg->session, false, &tee_open_sessions);
	if (!s) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = tee_ta_cancel_command(&err_orig, s, NSAPP_IDENTITY);
	tee_ta_put_session(s);

out:
	arg->ret = res;
	arg->ret_origin = err_orig;
}

#ifndef CFG_CORE_FFA
#ifdef CFG_CORE_DYN_SHM
static void register_shm(struct optee_msg_arg *arg, uint32_t num_params)
{
	struct optee_msg_param_tmem *tmem = NULL;
	struct mobj *mobj = NULL;

	arg->ret = TEE_ERROR_BAD_PARAMETERS;

	if (num_params != 1 ||
	    (arg->params[0].attr !=
	     (OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT | OPTEE_MSG_ATTR_NONCONTIG)))
		return;

	tmem = &arg->params[0].u.tmem;
	mobj = msg_param_mobj_from_noncontig(tmem->buf_ptr, tmem->size,
					     tmem->shm_ref, false);

	if (!mobj)
		return;

	mobj_reg_shm_unguard(mobj);
	arg->ret = TEE_SUCCESS;
}

static void unregister_shm(struct optee_msg_arg *arg, uint32_t num_params)
{
	if (num_params == 1) {
		uint64_t cookie = arg->params[0].u.rmem.shm_ref;
		TEE_Result res = mobj_reg_shm_release_by_cookie(cookie);

		if (res)
			EMSG("Can't find mapping with given cookie");
		arg->ret = res;
	} else {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
		arg->ret_origin = TEE_ORIGIN_TEE;
	}
}
#endif /*CFG_CORE_DYN_SHM*/
#endif

void nsec_sessions_list_head(struct tee_ta_session_head **open_sessions)
{
	*open_sessions = &tee_open_sessions;
}

/* Note: this function is weak to let platforms add special handling */
TEE_Result __weak tee_entry_std(struct optee_msg_arg *arg, uint32_t num_params)
{
	return __tee_entry_std(arg, num_params);
}

/*
 * If tee_entry_std() is overridden, it's still supposed to call this
 * function.
 */
TEE_Result __tee_entry_std(struct optee_msg_arg *arg, uint32_t num_params)
{
	TEE_Result res = TEE_SUCCESS;

	/* Enable foreign interrupts for STD calls */
	thread_set_foreign_intr(true);
	switch (arg->cmd) {
	case OPTEE_MSG_CMD_OPEN_SESSION:
		entry_open_session(arg, num_params);
		break;
	case OPTEE_MSG_CMD_CLOSE_SESSION:
		entry_close_session(arg, num_params);
		break;
	case OPTEE_MSG_CMD_INVOKE_COMMAND:
		entry_invoke_command(arg, num_params);
		break;
	case OPTEE_MSG_CMD_CANCEL:
		entry_cancel(arg, num_params);
		break;
#ifndef CFG_CORE_FFA
#ifdef CFG_CORE_DYN_SHM
	case OPTEE_MSG_CMD_REGISTER_SHM:
		register_shm(arg, num_params);
		break;
	case OPTEE_MSG_CMD_UNREGISTER_SHM:
		unregister_shm(arg, num_params);
		break;
#endif
#endif

	case OPTEE_MSG_CMD_DO_BOTTOM_HALF:
		if (IS_ENABLED(CFG_CORE_ASYNC_NOTIF))
			notif_deliver_event(NOTIF_EVENT_DO_BOTTOM_HALF);
		else
			goto err;
		break;
	case OPTEE_MSG_CMD_STOP_ASYNC_NOTIF:
		if (IS_ENABLED(CFG_CORE_ASYNC_NOTIF))
			notif_deliver_event(NOTIF_EVENT_STOPPED);
		else
			goto err;
		break;

	default:
err:
		EMSG("Unknown cmd 0x%x", arg->cmd);
		res = TEE_ERROR_NOT_IMPLEMENTED;
	}

	return res;
}

static TEE_Result default_mobj_init(void)
{
#ifdef CFG_CORE_RESERVED_SHM
	shm_mobj = mobj_phys_alloc(default_nsec_shm_paddr,
				   default_nsec_shm_size, SHM_CACHE_ATTRS,
				   CORE_MEM_NSEC_SHM);
	if (!shm_mobj)
		panic("Failed to register shared memory");
#endif

#ifdef CFG_SECURE_DATA_PATH
	sdp_mem_mobjs = core_sdp_mem_create_mobjs();
	if (!sdp_mem_mobjs)
		panic("Failed to register SDP memory");
#endif

	return TEE_SUCCESS;
}

driver_init_late(default_mobj_init);
