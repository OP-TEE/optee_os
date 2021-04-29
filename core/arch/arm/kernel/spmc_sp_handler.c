// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Arm Limited
 */
#include <assert.h>
#include <bench.h>
#include <kernel/panic.h>
#include <kernel/secure_partition.h>
#include <kernel/spinlock.h>
#include <kernel/spmc_sp_handler.h>
#include <optee_ffa.h>
#include "thread_private.h"

void spmc_sp_start_thread(struct thread_smc_args *args)
{
	thread_sp_alloc_and_run(args);
}

static void ffa_set_error(struct thread_smc_args *args, uint32_t error)
{
	args->a0 = FFA_ERROR;
	args->a2 = error;
}

static TEE_Result ffa_get_dst(struct thread_smc_args *args,
			      struct sp_session *caller,
			      struct sp_session **dst)
{
	struct sp_session *s = NULL;

	if (args->a2 != FFA_PARAM_MBZ)
		return FFA_INVALID_PARAMETERS;

	s = sp_get_session(FFA_DST(args->a1));

	/* Message came from the NW */
	if (!caller) {
		if (!s) {
			EMSG("Neither destination nor source is a SP");
			return FFA_INVALID_PARAMETERS;
		}
	} else {
		/* Check if the source matches the endpoint we came from */
		if (FFA_SRC(args->a1) != caller->endpoint_id) {
			EMSG("Source address doesn't match the endpoint id");
			return FFA_INVALID_PARAMETERS;
		}
	}

	*dst = s;

	return FFA_OK;
}

static struct sp_session *
ffa_handle_sp_direct_req(struct thread_smc_args *args,
			 struct sp_session *caller_sp)
{
	struct sp_session *dst = NULL;
	TEE_Result res = FFA_OK;

	if (args->a2 != FFA_PARAM_MBZ) {
		ffa_set_error(args, FFA_INVALID_PARAMETERS);
		return NULL;
	}

	res = ffa_get_dst(args, caller_sp, &dst);
	if (res) {
		/* Tried to send message to an incorrect endpoint */
		ffa_set_error(args, res);
		return caller_sp;
	}
	if (!dst) {
		EMSG("Request to normal world not supported");
		ffa_set_error(args, FFA_NOT_SUPPORTED);
		return NULL;
	}

	cpu_spin_lock(&dst->spinlock);
	if (dst->state != sp_idle) {
		DMSG("SP is busy");
		ffa_set_error(args, FFA_BUSY);
		cpu_spin_unlock(&dst->spinlock);
		return caller_sp;
	}

	dst->state = sp_busy;
	cpu_spin_unlock(&dst->spinlock);

	/*
	 * Store the calling endpoint id. This will make it possible to check
	 * if the response is sent back to the correct endpoint.
	 */
	dst->caller_id = FFA_SRC(args->a1);

	/* Forward the message to the destination SP */
	res = sp_enter(args, dst);
	if (res) {
		/* The SP Panicked */
		ffa_set_error(args, FFA_ABORTED);
		/* Return error to calling SP */
		return caller_sp;
	}

	return dst;
}

static struct sp_session *
ffa_handle_sp_direct_resp(struct thread_smc_args *args,
			  struct sp_session *caller_sp)
{
	struct sp_session *dst = NULL;
	TEE_Result res = FFA_OK;

	if (!caller_sp) {
		EMSG("Response from normal world not supported");
		ffa_set_error(args, FFA_NOT_SUPPORTED);
		return NULL;
	}

	res = ffa_get_dst(args, caller_sp, &dst);
	if (res) {
		/* Tried to send response to an incorrect endpoint */
		ffa_set_error(args, res);
		return caller_sp;
	}

	if (caller_sp->state != sp_busy) {
		EMSG("SP is not waiting for a request");
		ffa_set_error(args, FFA_INVALID_PARAMETERS);
		return caller_sp;
	}

	if (caller_sp->caller_id != FFA_DST(args->a1)) {
		EMSG("FFA_MSG_SEND_DIRECT_RESP to incorrect SP");
		ffa_set_error(args, FFA_INVALID_PARAMETERS);
		return caller_sp;
	}

	caller_sp->caller_id = 0;

	cpu_spin_lock(&caller_sp->spinlock);
	caller_sp->state = sp_idle;
	cpu_spin_unlock(&caller_sp->spinlock);

	if (!dst) {
		/* Send message back to the NW */
		return NULL;
	}

	/* Forward the message to the destination SP */
	res = sp_enter(args, dst);
	if (res) {
		/* The SP Panicked */
		ffa_set_error(args, FFA_ABORTED);
		/* Return error to calling SP */
		return caller_sp;
	}
	return dst;
}

static struct sp_session *
ffa_handle_sp_error(struct thread_smc_args *args,
		    struct sp_session *caller_sp)
{
	struct sp_session *dst = NULL;

	dst = sp_get_session(FFA_DST(args->a1));

	/* FFA_ERROR Came from Noral World */
	if (caller_sp)
		caller_sp->state = sp_idle;

	/* If dst == NULL send message to Normal World */
	if (dst && sp_enter(args, dst)) {
		/*
		 * We can not return the error. Unwind the call chain with one
		 * link. Set the state of the SP to dead.
		 */
		dst->state = sp_dead;
		/* Create error. */
		ffa_set_error(args, FFA_DENIED);
		return  sp_get_session(dst->caller_id);
	}

	return dst;
}

static void handle_features(struct thread_smc_args *args)
{
	uint32_t ret_fid = 0;
	uint32_t ret_w2 = FFA_PARAM_MBZ;

	switch (args->a1) {
#ifdef ARM64
	case FFA_RXTX_MAP_64:
#endif
	case FFA_RXTX_MAP_32:
		ret_fid = FFA_SUCCESS_32;
		ret_w2 = 0; /* 4kB Minimum buffer size and alignment boundary */
		break;
	case FFA_ERROR:
	case FFA_VERSION:
	case FFA_SUCCESS_32:
#ifdef ARM64
	case FFA_SUCCESS_64:
#endif
	default:
		ret_fid = FFA_ERROR;
		ret_w2 = FFA_NOT_SUPPORTED;
		break;
	}

	spmc_set_args(args, ret_fid, FFA_PARAM_MBZ, ret_w2, FFA_PARAM_MBZ,
		      FFA_PARAM_MBZ, FFA_PARAM_MBZ);
}

/*
 * FF-A messages handler for SP. Every messages for or from a SP is handled
 * here. This is the entry of the sp_spmc kernel thread. The caller_sp is set
 * to NULL when it is the Normal World.
 */
void spmc_sp_msg_handler(struct thread_smc_args *args,
			 struct sp_session *caller_sp)
{
	thread_check_canaries();
	do {
		switch (args->a0) {
		case FFA_MSG_SEND_DIRECT_REQ_32:
			caller_sp = ffa_handle_sp_direct_req(args, caller_sp);
			break;
		case FFA_MSG_SEND_DIRECT_RESP_32:
			caller_sp = ffa_handle_sp_direct_resp(args, caller_sp);
			break;
		case FFA_ERROR:
			caller_sp = ffa_handle_sp_error(args, caller_sp);
			break;
		case FFA_MSG_WAIT:
			/* FFA_WAIT gives control back to NW */
			cpu_spin_lock(&caller_sp->spinlock);
			caller_sp->state = sp_idle;
			cpu_spin_unlock(&caller_sp->spinlock);
			caller_sp = NULL;
			break;
#ifdef ARM64
		case FFA_RXTX_MAP_64:
#endif
		case FFA_RXTX_MAP_32:
			ts_push_current_session(&caller_sp->ts_sess);
			spmc_handle_rxtx_map(args, &caller_sp->rxtx);
			ts_pop_current_session();
			sp_enter(args, caller_sp);
			break;
		case FFA_RXTX_UNMAP:
			ts_push_current_session(&caller_sp->ts_sess);
			spmc_handle_rxtx_unmap(args, &caller_sp->rxtx);
			ts_pop_current_session();
			sp_enter(args, caller_sp);
			break;
		case FFA_RX_RELEASE:
			ts_push_current_session(&caller_sp->ts_sess);
			spmc_handle_rx_release(args, &caller_sp->rxtx);
			ts_pop_current_session();
			sp_enter(args, caller_sp);
			break;
		case FFA_ID_GET:
			args->a0 = FFA_SUCCESS_32;
			args->a2 = caller_sp->endpoint_id;
			sp_enter(args, caller_sp);
			break;
		case FFA_VERSION:
			spmc_handle_version(args);
			sp_enter(args, caller_sp);
			break;
		case FFA_FEATURES:
			handle_features(args);
			sp_enter(args, caller_sp);
			break;
		default:
			EMSG("Unhandled FFA function ID %#"PRIx32,
			     (uint32_t)args->a0);
			ffa_set_error(args, FFA_INVALID_PARAMETERS);
			sp_enter(args, caller_sp);
		}
	} while (caller_sp);
}
