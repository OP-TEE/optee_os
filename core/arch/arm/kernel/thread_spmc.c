// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020-2023, Linaro Limited.
 * Copyright (c) 2019-2024, Arm Limited. All rights reserved.
 */

#include <assert.h>
#include <ffa.h>
#include <initcall.h>
#include <io.h>
#include <kernel/interrupt.h>
#include <kernel/notif.h>
#include <kernel/panic.h>
#include <kernel/secure_partition.h>
#include <kernel/spinlock.h>
#include <kernel/spmc_sp_handler.h>
#include <kernel/tee_misc.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <kernel/thread_spmc.h>
#include <kernel/virtualization.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <optee_ffa.h>
#include <optee_msg.h>
#include <optee_rpc_cmd.h>
#include <sm/optee_smc.h>
#include <string.h>
#include <sys/queue.h>
#include <tee/entry_std.h>
#include <tee/uuid.h>
#include <util.h>

#if defined(CFG_CORE_SEL1_SPMC)
struct mem_share_state {
	struct mobj_ffa *mf;
	unsigned int page_count;
	unsigned int region_count;
	unsigned int current_page_idx;
};

struct mem_frag_state {
	struct mem_share_state share;
	tee_mm_entry_t *mm;
	unsigned int frag_offset;
	SLIST_ENTRY(mem_frag_state) link;
};
#endif

static unsigned int spmc_notif_lock = SPINLOCK_UNLOCK;
static int do_bottom_half_value = -1;
static uint16_t notif_vm_id;
static bool spmc_notif_is_ready;

/* Initialized in spmc_init() below */
uint16_t optee_endpoint_id __nex_bss;
uint16_t spmc_id __nex_bss;
#ifdef CFG_CORE_SEL1_SPMC
uint16_t spmd_id __nex_bss;
static const uint32_t my_part_props = FFA_PART_PROP_DIRECT_REQ_RECV |
				      FFA_PART_PROP_DIRECT_REQ_SEND |
#ifdef CFG_NS_VIRTUALIZATION
				      FFA_PART_PROP_NOTIF_CREATED |
				      FFA_PART_PROP_NOTIF_DESTROYED |
#endif
#ifdef ARM64
				      FFA_PART_PROP_AARCH64_STATE |
#endif
				      FFA_PART_PROP_IS_PE_ID;

static uint32_t my_uuid_words[] = {
	/*
	 * - if the SPMC is in S-EL2 this UUID describes OP-TEE as a S-EL1
	 *   SP, or
	 * - if the SPMC is in S-EL1 then this UUID is for OP-TEE as a
	 *   logical partition, residing in the same exception level as the
	 *   SPMC
	 * UUID 486178e0-e7f8-11e3-bc5e-0002a5d5c51b
	 */
	0xe0786148, 0xe311f8e7, 0x02005ebc, 0x1bc5d5a5,
};

/*
 * If struct ffa_rxtx::size is 0 RX/TX buffers are not mapped or initialized.
 *
 * struct ffa_rxtx::spin_lock protects the variables below from concurrent
 * access this includes the use of content of struct ffa_rxtx::rx and
 * @frag_state_head.
 *
 * struct ffa_rxtx::tx_buf_is_mine is true when we may write to struct
 * ffa_rxtx::tx and false when it is owned by normal world.
 *
 * Note that we can't prevent normal world from updating the content of
 * these buffers so we must always be careful when reading. while we hold
 * the lock.
 */

static struct ffa_rxtx my_rxtx __nex_bss;

static bool is_nw_buf(struct ffa_rxtx *rxtx)
{
	return rxtx == &my_rxtx;
}

static SLIST_HEAD(mem_frag_state_head, mem_frag_state) frag_state_head =
	SLIST_HEAD_INITIALIZER(&frag_state_head);

static uint64_t notif_pending_bitmap;
static uint64_t notif_bound_bitmap;
static bool notif_vm_id_valid;
static int notif_intid = -1;
#else
static uint8_t __rx_buf[SMALL_PAGE_SIZE] __aligned(SMALL_PAGE_SIZE);
static uint8_t __tx_buf[SMALL_PAGE_SIZE] __aligned(SMALL_PAGE_SIZE);
static struct ffa_rxtx my_rxtx = {
	.rx = __rx_buf,
	.tx = __tx_buf,
	.size = sizeof(__rx_buf),
};
#endif

static uint32_t swap_src_dst(uint32_t src_dst)
{
	return (src_dst >> 16) | (src_dst << 16);
}

static uint16_t get_sender_id(uint32_t src_dst)
{
	return src_dst >> 16;
}

void spmc_set_args(struct thread_smc_args *args, uint32_t fid, uint32_t src_dst,
		   uint32_t w2, uint32_t w3, uint32_t w4, uint32_t w5)
{
	*args = (struct thread_smc_args){ .a0 = fid,
					  .a1 = src_dst,
					  .a2 = w2,
					  .a3 = w3,
					  .a4 = w4,
					  .a5 = w5, };
}

static void set_simple_ret_val(struct thread_smc_args *args, int ffa_ret)
{
	if (ffa_ret)
		spmc_set_args(args, FFA_ERROR, 0, ffa_ret, 0, 0, 0);
	else
		spmc_set_args(args, FFA_SUCCESS_32, 0, 0, 0, 0, 0);
}

uint32_t spmc_exchange_version(uint32_t vers, struct ffa_rxtx *rxtx)
{
	/*
	 * No locking, if the caller does concurrent calls to this it's
	 * only making a mess for itself. We must be able to renegotiate
	 * the FF-A version in order to support differing versions between
	 * the loader and the driver.
	 */
	if (vers < FFA_VERSION_1_1)
		rxtx->ffa_vers = FFA_VERSION_1_0;
	else
		rxtx->ffa_vers = FFA_VERSION_1_1;

	return rxtx->ffa_vers;
}

static bool is_ffa_success(uint32_t fid)
{
#ifdef ARM64
	if (fid == FFA_SUCCESS_64)
		return true;
#endif
	return fid == FFA_SUCCESS_32;
}

static int32_t get_ffa_ret_code(const struct thread_smc_args *args)
{
	if (is_ffa_success(args->a0))
		return FFA_OK;
	if (args->a0 == FFA_ERROR && args->a2)
		return args->a2;
	return FFA_NOT_SUPPORTED;
}

static int ffa_simple_call(uint32_t fid, unsigned long a1, unsigned long a2,
			   unsigned long a3, unsigned long a4)
{
	struct thread_smc_args args = {
		.a0 = fid,
		.a1 = a1,
		.a2 = a2,
		.a3 = a3,
		.a4 = a4,
	};

	thread_smccc(&args);

	return get_ffa_ret_code(&args);
}

static int __maybe_unused ffa_features(uint32_t id)
{
	return ffa_simple_call(FFA_FEATURES, id, 0, 0, 0);
}

static int __maybe_unused ffa_set_notification(uint16_t dst, uint16_t src,
					       uint32_t flags, uint64_t bitmap)
{
	return ffa_simple_call(FFA_NOTIFICATION_SET,
			       SHIFT_U32(src, 16) | dst, flags,
			       low32_from_64(bitmap), high32_from_64(bitmap));
}

#if defined(CFG_CORE_SEL1_SPMC)
static void handle_features(struct thread_smc_args *args)
{
	uint32_t ret_fid = FFA_ERROR;
	uint32_t ret_w2 = FFA_NOT_SUPPORTED;

	switch (args->a1) {
	case FFA_FEATURE_SCHEDULE_RECV_INTR:
		if (spmc_notif_is_ready) {
			ret_fid = FFA_SUCCESS_32;
			ret_w2 = notif_intid;
		}
		break;

#ifdef ARM64
	case FFA_RXTX_MAP_64:
#endif
	case FFA_RXTX_MAP_32:
		ret_fid = FFA_SUCCESS_32;
		ret_w2 = 0; /* 4kB Minimum buffer size and alignment boundary */
		break;
#ifdef ARM64
	case FFA_MEM_SHARE_64:
#endif
	case FFA_MEM_SHARE_32:
		ret_fid = FFA_SUCCESS_32;
		/*
		 * Partition manager supports transmission of a memory
		 * transaction descriptor in a buffer dynamically allocated
		 * by the endpoint.
		 */
		ret_w2 = BIT(0);
		break;

	case FFA_ERROR:
	case FFA_VERSION:
	case FFA_SUCCESS_32:
#ifdef ARM64
	case FFA_SUCCESS_64:
#endif
	case FFA_FEATURES:
	case FFA_SPM_ID_GET:
	case FFA_MEM_FRAG_TX:
	case FFA_MEM_RECLAIM:
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_INTERRUPT:
	case FFA_PARTITION_INFO_GET:
	case FFA_RXTX_UNMAP:
	case FFA_RX_RELEASE:
	case FFA_FEATURE_MANAGED_EXIT_INTR:
	case FFA_NOTIFICATION_BITMAP_CREATE:
	case FFA_NOTIFICATION_BITMAP_DESTROY:
	case FFA_NOTIFICATION_BIND:
	case FFA_NOTIFICATION_UNBIND:
	case FFA_NOTIFICATION_SET:
	case FFA_NOTIFICATION_GET:
	case FFA_NOTIFICATION_INFO_GET_32:
#ifdef ARM64
	case FFA_NOTIFICATION_INFO_GET_64:
#endif
		ret_fid = FFA_SUCCESS_32;
		ret_w2 = FFA_PARAM_MBZ;
		break;
	default:
		break;
	}

	spmc_set_args(args, ret_fid, FFA_PARAM_MBZ, ret_w2, FFA_PARAM_MBZ,
		      FFA_PARAM_MBZ, FFA_PARAM_MBZ);
}

static int map_buf(paddr_t pa, unsigned int sz, void **va_ret)
{
	tee_mm_entry_t *mm = NULL;

	if (!core_pbuf_is(CORE_MEM_NON_SEC, pa, sz))
		return FFA_INVALID_PARAMETERS;

	mm = tee_mm_alloc(&tee_mm_shm, sz);
	if (!mm)
		return FFA_NO_MEMORY;

	if (core_mmu_map_contiguous_pages(tee_mm_get_smem(mm), pa,
					  sz / SMALL_PAGE_SIZE,
					  MEM_AREA_NSEC_SHM)) {
		tee_mm_free(mm);
		return FFA_INVALID_PARAMETERS;
	}

	*va_ret = (void *)tee_mm_get_smem(mm);
	return 0;
}

void spmc_handle_spm_id_get(struct thread_smc_args *args)
{
	spmc_set_args(args, FFA_SUCCESS_32, FFA_PARAM_MBZ, spmc_id,
		      FFA_PARAM_MBZ, FFA_PARAM_MBZ, FFA_PARAM_MBZ);
}

static void unmap_buf(void *va, size_t sz)
{
	tee_mm_entry_t *mm = tee_mm_find(&tee_mm_shm, (vaddr_t)va);

	assert(mm);
	core_mmu_unmap_pages(tee_mm_get_smem(mm), sz / SMALL_PAGE_SIZE);
	tee_mm_free(mm);
}

void spmc_handle_rxtx_map(struct thread_smc_args *args, struct ffa_rxtx *rxtx)
{
	int rc = 0;
	unsigned int sz = 0;
	paddr_t rx_pa = 0;
	paddr_t tx_pa = 0;
	void *rx = NULL;
	void *tx = NULL;

	cpu_spin_lock(&rxtx->spinlock);

	if (args->a3 & GENMASK_64(63, 6)) {
		rc = FFA_INVALID_PARAMETERS;
		goto out;
	}

	sz = args->a3 * SMALL_PAGE_SIZE;
	if (!sz) {
		rc = FFA_INVALID_PARAMETERS;
		goto out;
	}
	/* TX/RX are swapped compared to the caller */
	tx_pa = args->a2;
	rx_pa = args->a1;

	if (rxtx->size) {
		rc = FFA_DENIED;
		goto out;
	}

	/*
	 * If the buffer comes from a SP the address is virtual and already
	 * mapped.
	 */
	if (is_nw_buf(rxtx)) {
		if (IS_ENABLED(CFG_NS_VIRTUALIZATION)) {
			enum teecore_memtypes mt = MEM_AREA_NEX_NSEC_SHM;
			bool tx_alloced = false;

			/*
			 * With virtualization we establish this mapping in
			 * the nexus mapping which then is replicated to
			 * each partition.
			 *
			 * This means that this mapping must be done before
			 * any partition is created and then must not be
			 * changed.
			 */

			/*
			 * core_mmu_add_mapping() may reuse previous
			 * mappings. First check if there's any mappings to
			 * reuse so we know how to clean up in case of
			 * failure.
			 */
			tx = phys_to_virt(tx_pa, mt, sz);
			rx = phys_to_virt(rx_pa, mt, sz);
			if (!tx) {
				tx = core_mmu_add_mapping(mt, tx_pa, sz);
				if (!tx) {
					rc = FFA_NO_MEMORY;
					goto out;
				}
				tx_alloced = true;
			}
			if (!rx)
				rx = core_mmu_add_mapping(mt, rx_pa, sz);

			if (!rx) {
				if (tx_alloced && tx)
					core_mmu_remove_mapping(mt, tx, sz);
				rc = FFA_NO_MEMORY;
				goto out;
			}
		} else {
			rc = map_buf(tx_pa, sz, &tx);
			if (rc)
				goto out;
			rc = map_buf(rx_pa, sz, &rx);
			if (rc) {
				unmap_buf(tx, sz);
				goto out;
			}
		}
		rxtx->tx = tx;
		rxtx->rx = rx;
	} else {
		if ((tx_pa & SMALL_PAGE_MASK) || (rx_pa & SMALL_PAGE_MASK)) {
			rc = FFA_INVALID_PARAMETERS;
			goto out;
		}

		if (!virt_to_phys((void *)tx_pa) ||
		    !virt_to_phys((void *)rx_pa)) {
			rc = FFA_INVALID_PARAMETERS;
			goto out;
		}

		rxtx->tx = (void *)tx_pa;
		rxtx->rx = (void *)rx_pa;
	}

	rxtx->size = sz;
	rxtx->tx_is_mine = true;
	DMSG("Mapped tx %#"PRIxPA" size %#x @ %p", tx_pa, sz, tx);
	DMSG("Mapped rx %#"PRIxPA" size %#x @ %p", rx_pa, sz, rx);
out:
	cpu_spin_unlock(&rxtx->spinlock);
	set_simple_ret_val(args, rc);
}

void spmc_handle_rxtx_unmap(struct thread_smc_args *args, struct ffa_rxtx *rxtx)
{
	int rc = FFA_INVALID_PARAMETERS;

	cpu_spin_lock(&rxtx->spinlock);

	if (!rxtx->size)
		goto out;

	/* We don't unmap the SP memory as the SP might still use it */
	if (is_nw_buf(rxtx)) {
		unmap_buf(rxtx->rx, rxtx->size);
		unmap_buf(rxtx->tx, rxtx->size);
	}
	rxtx->size = 0;
	rxtx->rx = NULL;
	rxtx->tx = NULL;
	rc = 0;
out:
	cpu_spin_unlock(&rxtx->spinlock);
	set_simple_ret_val(args, rc);
}

void spmc_handle_rx_release(struct thread_smc_args *args, struct ffa_rxtx *rxtx)
{
	int rc = 0;

	cpu_spin_lock(&rxtx->spinlock);
	/* The senders RX is our TX */
	if (!rxtx->size || rxtx->tx_is_mine) {
		rc = FFA_DENIED;
	} else {
		rc = 0;
		rxtx->tx_is_mine = true;
	}
	cpu_spin_unlock(&rxtx->spinlock);

	set_simple_ret_val(args, rc);
}

static bool is_nil_uuid(uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3)
{
	return !w0 && !w1 && !w2 && !w3;
}

static bool is_my_uuid(uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3)
{
	/*
	 * This depends on which UUID we have been assigned.
	 * TODO add a generic mechanism to obtain our UUID.
	 *
	 * The test below is for the hard coded UUID
	 * 486178e0-e7f8-11e3-bc5e-0002a5d5c51b
	 */
	return w0 == my_uuid_words[0] && w1 == my_uuid_words[1] &&
	       w2 == my_uuid_words[2] && w3 == my_uuid_words[3];
}

TEE_Result spmc_fill_partition_entry(uint32_t ffa_vers, void *buf, size_t blen,
				     size_t idx, uint16_t endpoint_id,
				     uint16_t execution_context,
				     uint32_t part_props,
				     const uint32_t uuid_words[4])
{
	struct ffa_partition_info_x *fpi = NULL;
	size_t fpi_size = sizeof(*fpi);

	if (ffa_vers >= FFA_VERSION_1_1)
		fpi_size += FFA_UUID_SIZE;

	if ((idx + 1) * fpi_size > blen)
		return TEE_ERROR_OUT_OF_MEMORY;

	fpi = (void *)((vaddr_t)buf + idx * fpi_size);
	fpi->id = endpoint_id;
	/* Number of execution contexts implemented by this partition */
	fpi->execution_context = execution_context;

	fpi->partition_properties = part_props;

	if (ffa_vers >= FFA_VERSION_1_1) {
		if (uuid_words)
			memcpy(fpi->uuid, uuid_words, FFA_UUID_SIZE);
		else
			memset(fpi->uuid, 0, FFA_UUID_SIZE);
	}

	return TEE_SUCCESS;
}

static int handle_partition_info_get_all(size_t *elem_count,
					 struct ffa_rxtx *rxtx, bool count_only)
{
	if (!count_only) {
		/* Add OP-TEE SP */
		if (spmc_fill_partition_entry(rxtx->ffa_vers, rxtx->tx,
					      rxtx->size, 0, optee_endpoint_id,
					      CFG_TEE_CORE_NB_CORE,
					      my_part_props, my_uuid_words))
			return FFA_NO_MEMORY;
	}
	*elem_count = 1;

	if (IS_ENABLED(CFG_SECURE_PARTITION)) {
		if (sp_partition_info_get(rxtx->ffa_vers, rxtx->tx, rxtx->size,
					  NULL, elem_count, count_only))
			return FFA_NO_MEMORY;
	}

	return FFA_OK;
}

void spmc_handle_partition_info_get(struct thread_smc_args *args,
				    struct ffa_rxtx *rxtx)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t ret_fid = FFA_ERROR;
	uint32_t fpi_size = 0;
	uint32_t rc = 0;
	bool count_only = args->a5 & FFA_PARTITION_INFO_GET_COUNT_FLAG;

	if (!count_only) {
		cpu_spin_lock(&rxtx->spinlock);

		if (!rxtx->size || !rxtx->tx_is_mine) {
			rc = FFA_BUSY;
			goto out;
		}
	}

	if (is_nil_uuid(args->a1, args->a2, args->a3, args->a4)) {
		size_t elem_count = 0;

		ret_fid = handle_partition_info_get_all(&elem_count, rxtx,
							count_only);

		if (ret_fid) {
			rc = ret_fid;
			ret_fid = FFA_ERROR;
		} else {
			ret_fid = FFA_SUCCESS_32;
			rc = elem_count;
		}

		goto out;
	}

	if (is_my_uuid(args->a1, args->a2, args->a3, args->a4)) {
		if (!count_only) {
			res = spmc_fill_partition_entry(rxtx->ffa_vers,
							rxtx->tx, rxtx->size, 0,
							optee_endpoint_id,
							CFG_TEE_CORE_NB_CORE,
							my_part_props,
							my_uuid_words);
			if (res) {
				ret_fid = FFA_ERROR;
				rc = FFA_INVALID_PARAMETERS;
				goto out;
			}
		}
		rc = 1;
	} else if (IS_ENABLED(CFG_SECURE_PARTITION)) {
		uint32_t uuid_array[4] = { 0 };
		TEE_UUID uuid = { };
		size_t count = 0;

		uuid_array[0] = args->a1;
		uuid_array[1] = args->a2;
		uuid_array[2] = args->a3;
		uuid_array[3] = args->a4;
		tee_uuid_from_octets(&uuid, (uint8_t *)uuid_array);

		res = sp_partition_info_get(rxtx->ffa_vers, rxtx->tx,
					    rxtx->size, &uuid, &count,
					    count_only);
		if (res != TEE_SUCCESS) {
			ret_fid = FFA_ERROR;
			rc = FFA_INVALID_PARAMETERS;
			goto out;
		}
		rc = count;
	} else {
		ret_fid = FFA_ERROR;
		rc = FFA_INVALID_PARAMETERS;
		goto out;
	}

	ret_fid = FFA_SUCCESS_32;

out:
	if (ret_fid == FFA_SUCCESS_32 && !count_only &&
	    rxtx->ffa_vers >= FFA_VERSION_1_1)
		fpi_size = sizeof(struct ffa_partition_info_x) + FFA_UUID_SIZE;

	spmc_set_args(args, ret_fid, FFA_PARAM_MBZ, rc, fpi_size,
		      FFA_PARAM_MBZ, FFA_PARAM_MBZ);
	if (!count_only) {
		rxtx->tx_is_mine = false;
		cpu_spin_unlock(&rxtx->spinlock);
	}
}

static void spmc_handle_run(struct thread_smc_args *args)
{
	uint16_t endpoint = FFA_TARGET_INFO_GET_SP_ID(args->a1);
	uint16_t thread_id = FFA_TARGET_INFO_GET_VCPU_ID(args->a1);
	uint32_t rc = FFA_OK;

	if (endpoint != optee_endpoint_id) {
		/*
		 * The endpoint should be an SP, try to resume the SP from
		 * preempted into busy state.
		 */
		rc = spmc_sp_resume_from_preempted(endpoint);
		if (rc)
			goto out;
	}

	thread_resume_from_rpc(thread_id, 0, 0, 0, 0);

	/* thread_resume_from_rpc return only of the thread_id is invalid */
	rc = FFA_INVALID_PARAMETERS;

out:
	set_simple_ret_val(args, rc);
}
#endif /*CFG_CORE_SEL1_SPMC*/

static uint32_t spmc_enable_async_notif(uint32_t bottom_half_value,
					uint16_t vm_id)
{
	uint32_t old_itr_status = 0;

	if (!spmc_notif_is_ready) {
		/*
		 * This should never happen, not if normal world respects the
		 * exchanged capabilities.
		 */
		EMSG("Asynchronous notifications are not ready");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (bottom_half_value >= OPTEE_FFA_MAX_ASYNC_NOTIF_VALUE) {
		EMSG("Invalid bottom half value %"PRIu32, bottom_half_value);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	old_itr_status = cpu_spin_lock_xsave(&spmc_notif_lock);
	do_bottom_half_value = bottom_half_value;
	if (!IS_ENABLED(CFG_CORE_SEL1_SPMC))
		notif_vm_id = vm_id;
	cpu_spin_unlock_xrestore(&spmc_notif_lock, old_itr_status);

	notif_deliver_atomic_event(NOTIF_EVENT_STARTED);
	return TEE_SUCCESS;
}

static void handle_yielding_call(struct thread_smc_args *args,
				 uint32_t direct_resp_fid)
{
	TEE_Result res = 0;

	thread_check_canaries();

#ifdef ARM64
	/* Saving this for an eventual RPC */
	thread_get_core_local()->direct_resp_fid = direct_resp_fid;
#endif

	if (args->a3 == OPTEE_FFA_YIELDING_CALL_RESUME) {
		/* Note connection to struct thread_rpc_arg::ret */
		thread_resume_from_rpc(args->a7, args->a4, args->a5, args->a6,
				       0);
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		thread_alloc_and_run(args->a1, args->a3, args->a4, args->a5,
				     args->a6, args->a7);
		res = TEE_ERROR_BUSY;
	}
	spmc_set_args(args, direct_resp_fid, swap_src_dst(args->a1),
		      0, res, 0, 0);
}

static uint32_t handle_unregister_shm(uint32_t a4, uint32_t a5)
{
	uint64_t cookie = reg_pair_to_64(a5, a4);
	uint32_t res = 0;

	res = mobj_ffa_unregister_by_cookie(cookie);
	switch (res) {
	case TEE_SUCCESS:
	case TEE_ERROR_ITEM_NOT_FOUND:
		return 0;
	case TEE_ERROR_BUSY:
		EMSG("res %#"PRIx32, res);
		return FFA_BUSY;
	default:
		EMSG("res %#"PRIx32, res);
		return FFA_INVALID_PARAMETERS;
	}
}

static void handle_blocking_call(struct thread_smc_args *args,
				 uint32_t direct_resp_fid)
{
	uint32_t sec_caps = 0;

	switch (args->a3) {
	case OPTEE_FFA_GET_API_VERSION:
		spmc_set_args(args, direct_resp_fid, swap_src_dst(args->a1), 0,
			      OPTEE_FFA_VERSION_MAJOR, OPTEE_FFA_VERSION_MINOR,
			      0);
		break;
	case OPTEE_FFA_GET_OS_VERSION:
		spmc_set_args(args, direct_resp_fid, swap_src_dst(args->a1), 0,
			      CFG_OPTEE_REVISION_MAJOR,
			      CFG_OPTEE_REVISION_MINOR,
			      TEE_IMPL_GIT_SHA1 >> 32);
		break;
	case OPTEE_FFA_EXCHANGE_CAPABILITIES:
		sec_caps = OPTEE_FFA_SEC_CAP_ARG_OFFSET;
		if (spmc_notif_is_ready)
			sec_caps |= OPTEE_FFA_SEC_CAP_ASYNC_NOTIF;
		spmc_set_args(args, direct_resp_fid,
			      swap_src_dst(args->a1), 0, 0,
			      THREAD_RPC_MAX_NUM_PARAMS, sec_caps);
		break;
	case OPTEE_FFA_UNREGISTER_SHM:
		spmc_set_args(args, direct_resp_fid, swap_src_dst(args->a1), 0,
			      handle_unregister_shm(args->a4, args->a5), 0, 0);
		break;
	case OPTEE_FFA_ENABLE_ASYNC_NOTIF:
		spmc_set_args(args, direct_resp_fid,
			      swap_src_dst(args->a1), 0,
			      spmc_enable_async_notif(args->a4,
						      FFA_SRC(args->a1)),
			      0, 0);
		break;
	default:
		EMSG("Unhandled blocking service ID %#"PRIx32,
		     (uint32_t)args->a3);
		spmc_set_args(args, direct_resp_fid, swap_src_dst(args->a1), 0,
			      TEE_ERROR_BAD_PARAMETERS, 0, 0);
	}
}

static void handle_framework_direct_request(struct thread_smc_args *args,
					    struct ffa_rxtx *rxtx,
					    uint32_t direct_resp_fid)
{
	uint32_t w0 = FFA_ERROR;
	uint32_t w1 = FFA_PARAM_MBZ;
	uint32_t w2 = FFA_NOT_SUPPORTED;
	uint32_t w3 = FFA_PARAM_MBZ;

	switch (args->a2 & FFA_MSG_TYPE_MASK) {
	case FFA_MSG_SEND_VM_CREATED:
		if (IS_ENABLED(CFG_NS_VIRTUALIZATION)) {
			uint16_t guest_id = args->a5;
			TEE_Result res = virt_guest_created(guest_id);

			w0 = direct_resp_fid;
			w1 = swap_src_dst(args->a1);
			w2 = FFA_MSG_FLAG_FRAMEWORK | FFA_MSG_RESP_VM_CREATED;
			if (res == TEE_SUCCESS)
				w3 = FFA_OK;
			else if (res == TEE_ERROR_OUT_OF_MEMORY)
				w3 = FFA_DENIED;
			else
				w3 = FFA_INVALID_PARAMETERS;
		}
		break;
	case FFA_MSG_SEND_VM_DESTROYED:
		if (IS_ENABLED(CFG_NS_VIRTUALIZATION)) {
			uint16_t guest_id = args->a5;
			TEE_Result res = virt_guest_destroyed(guest_id);

			w0 = direct_resp_fid;
			w1 = swap_src_dst(args->a1);
			w2 = FFA_MSG_FLAG_FRAMEWORK | FFA_MSG_RESP_VM_DESTROYED;
			if (res == TEE_SUCCESS)
				w3 = FFA_OK;
			else
				w3 = FFA_INVALID_PARAMETERS;
		}
		break;
	case FFA_MSG_VERSION_REQ:
		w0 = direct_resp_fid;
		w1 = swap_src_dst(args->a1);
		w2 = FFA_MSG_FLAG_FRAMEWORK | FFA_MSG_VERSION_RESP;
		w3 = spmc_exchange_version(args->a3, rxtx);
		break;
	default:
		break;
	}
	spmc_set_args(args, w0, w1, w2, w3, FFA_PARAM_MBZ, FFA_PARAM_MBZ);
}

static void handle_direct_request(struct thread_smc_args *args,
				  struct ffa_rxtx *rxtx)
{
	uint32_t direct_resp_fid = 0;

	if (IS_ENABLED(CFG_SECURE_PARTITION) &&
	    FFA_DST(args->a1) != spmc_id &&
	    FFA_DST(args->a1) != optee_endpoint_id) {
		spmc_sp_start_thread(args);
		return;
	}

	if (OPTEE_SMC_IS_64(args->a0))
		direct_resp_fid = FFA_MSG_SEND_DIRECT_RESP_64;
	else
		direct_resp_fid = FFA_MSG_SEND_DIRECT_RESP_32;

	if (args->a2 & FFA_MSG_FLAG_FRAMEWORK) {
		handle_framework_direct_request(args, rxtx, direct_resp_fid);
		return;
	}

	if (IS_ENABLED(CFG_NS_VIRTUALIZATION) &&
	    virt_set_guest(get_sender_id(args->a1))) {
		spmc_set_args(args, direct_resp_fid, swap_src_dst(args->a1), 0,
			      TEE_ERROR_ITEM_NOT_FOUND, 0, 0);
		return;
	}

	if (args->a3 & BIT32(OPTEE_FFA_YIELDING_CALL_BIT))
		handle_yielding_call(args, direct_resp_fid);
	else
		handle_blocking_call(args, direct_resp_fid);

	/*
	 * Note that handle_yielding_call() typically only returns if a
	 * thread cannot be allocated or found. virt_unset_guest() is also
	 * called from thread_state_suspend() and thread_state_free().
	 */
	virt_unset_guest();
}

int spmc_read_mem_transaction(uint32_t ffa_vers, void *buf, size_t blen,
			      struct ffa_mem_transaction_x *trans)
{
	uint16_t mem_reg_attr = 0;
	uint32_t flags = 0;
	uint32_t count = 0;
	uint32_t offs = 0;
	uint32_t size = 0;
	size_t n = 0;

	if (!IS_ALIGNED_WITH_TYPE(buf, uint64_t))
		return FFA_INVALID_PARAMETERS;

	if (ffa_vers >= FFA_VERSION_1_1) {
		struct ffa_mem_transaction_1_1 *descr = NULL;

		if (blen < sizeof(*descr))
			return FFA_INVALID_PARAMETERS;

		descr = buf;
		trans->sender_id = READ_ONCE(descr->sender_id);
		mem_reg_attr = READ_ONCE(descr->mem_reg_attr);
		flags = READ_ONCE(descr->flags);
		trans->global_handle = READ_ONCE(descr->global_handle);
		trans->tag = READ_ONCE(descr->tag);

		count = READ_ONCE(descr->mem_access_count);
		size = READ_ONCE(descr->mem_access_size);
		offs = READ_ONCE(descr->mem_access_offs);
	} else {
		struct ffa_mem_transaction_1_0 *descr = NULL;

		if (blen < sizeof(*descr))
			return FFA_INVALID_PARAMETERS;

		descr = buf;
		trans->sender_id = READ_ONCE(descr->sender_id);
		mem_reg_attr = READ_ONCE(descr->mem_reg_attr);
		flags = READ_ONCE(descr->flags);
		trans->global_handle = READ_ONCE(descr->global_handle);
		trans->tag = READ_ONCE(descr->tag);

		count = READ_ONCE(descr->mem_access_count);
		size = sizeof(struct ffa_mem_access);
		offs = offsetof(struct ffa_mem_transaction_1_0,
				mem_access_array);
	}

	if (mem_reg_attr > UINT8_MAX || flags > UINT8_MAX ||
	    size > UINT8_MAX || count > UINT8_MAX || offs > UINT16_MAX)
		return FFA_INVALID_PARAMETERS;

	/* Check that the endpoint memory access descriptor array fits */
	if (MUL_OVERFLOW(size, count, &n) || ADD_OVERFLOW(offs, n, &n) ||
	    n > blen)
		return FFA_INVALID_PARAMETERS;

	trans->mem_reg_attr = mem_reg_attr;
	trans->flags = flags;
	trans->mem_access_size = size;
	trans->mem_access_count = count;
	trans->mem_access_offs = offs;
	return 0;
}

#if defined(CFG_CORE_SEL1_SPMC)
static int get_acc_perms(vaddr_t mem_acc_base, unsigned int mem_access_size,
			 unsigned int mem_access_count, uint8_t *acc_perms,
			 unsigned int *region_offs)
{
	struct ffa_mem_access_perm *descr = NULL;
	struct ffa_mem_access *mem_acc = NULL;
	unsigned int n = 0;

	for (n = 0; n < mem_access_count; n++) {
		mem_acc = (void *)(mem_acc_base + mem_access_size * n);
		descr = &mem_acc->access_perm;
		if (READ_ONCE(descr->endpoint_id) == optee_endpoint_id) {
			*acc_perms = READ_ONCE(descr->perm);
			*region_offs = READ_ONCE(mem_acc[n].region_offs);
			return 0;
		}
	}

	return FFA_INVALID_PARAMETERS;
}

static int mem_share_init(struct ffa_mem_transaction_x *mem_trans, void *buf,
			  size_t blen, unsigned int *page_count,
			  unsigned int *region_count, size_t *addr_range_offs)
{
	const uint16_t exp_mem_reg_attr = FFA_NORMAL_MEM_REG_ATTR;
	const uint8_t exp_mem_acc_perm = FFA_MEM_ACC_RW;
	struct ffa_mem_region *region_descr = NULL;
	unsigned int region_descr_offs = 0;
	uint8_t mem_acc_perm = 0;
	size_t n = 0;

	if (mem_trans->mem_reg_attr != exp_mem_reg_attr)
		return FFA_INVALID_PARAMETERS;

	/* Check that the access permissions matches what's expected */
	if (get_acc_perms((vaddr_t)buf + mem_trans->mem_access_offs,
			  mem_trans->mem_access_size,
			  mem_trans->mem_access_count,
			  &mem_acc_perm, &region_descr_offs) ||
	    mem_acc_perm != exp_mem_acc_perm)
		return FFA_INVALID_PARAMETERS;

	/* Check that the Composite memory region descriptor fits */
	if (ADD_OVERFLOW(region_descr_offs, sizeof(*region_descr), &n) ||
	    n > blen)
		return FFA_INVALID_PARAMETERS;

	if (!IS_ALIGNED_WITH_TYPE((vaddr_t)buf + region_descr_offs,
				  struct ffa_mem_region))
		return FFA_INVALID_PARAMETERS;

	region_descr = (struct ffa_mem_region *)((vaddr_t)buf +
						 region_descr_offs);
	*page_count = READ_ONCE(region_descr->total_page_count);
	*region_count = READ_ONCE(region_descr->address_range_count);
	*addr_range_offs = n;
	return 0;
}

static int add_mem_share_helper(struct mem_share_state *s, void *buf,
				size_t flen)
{
	unsigned int region_count = flen / sizeof(struct ffa_address_range);
	struct ffa_address_range *arange = NULL;
	unsigned int n = 0;

	if (region_count > s->region_count)
		region_count = s->region_count;

	if (!IS_ALIGNED_WITH_TYPE(buf, struct ffa_address_range))
		return FFA_INVALID_PARAMETERS;
	arange = buf;

	for (n = 0; n < region_count; n++) {
		unsigned int page_count = READ_ONCE(arange[n].page_count);
		uint64_t addr = READ_ONCE(arange[n].address);

		if (mobj_ffa_add_pages_at(s->mf, &s->current_page_idx,
					  addr, page_count))
			return FFA_INVALID_PARAMETERS;
	}

	s->region_count -= region_count;
	if (s->region_count)
		return region_count * sizeof(*arange);

	if (s->current_page_idx != s->page_count)
		return FFA_INVALID_PARAMETERS;

	return 0;
}

static int add_mem_share_frag(struct mem_frag_state *s, void *buf, size_t flen)
{
	int rc = 0;

	rc = add_mem_share_helper(&s->share, buf, flen);
	if (rc >= 0) {
		if (!ADD_OVERFLOW(s->frag_offset, rc, &s->frag_offset)) {
			/* We're not at the end of the descriptor yet */
			if (s->share.region_count)
				return s->frag_offset;

			/* We're done */
			rc = 0;
		} else {
			rc = FFA_INVALID_PARAMETERS;
		}
	}

	SLIST_REMOVE(&frag_state_head, s, mem_frag_state, link);
	if (rc < 0)
		mobj_ffa_sel1_spmc_delete(s->share.mf);
	else
		mobj_ffa_push_to_inactive(s->share.mf);
	free(s);

	return rc;
}

static bool is_sp_share(struct ffa_mem_transaction_x *mem_trans,
			void *buf)
{
	struct ffa_mem_access_perm *perm = NULL;
	struct ffa_mem_access *mem_acc = NULL;

	if (!IS_ENABLED(CFG_SECURE_PARTITION))
		return false;

	if (mem_trans->mem_access_count < 1)
		return false;

	mem_acc = (void *)((vaddr_t)buf + mem_trans->mem_access_offs);
	perm = &mem_acc->access_perm;

	/*
	 * perm->endpoint_id is read here only to check if the endpoint is
	 * OP-TEE. We do read it later on again, but there are some additional
	 * checks there to make sure that the data is correct.
	 */
	return READ_ONCE(perm->endpoint_id) != optee_endpoint_id;
}

static int add_mem_share(struct ffa_mem_transaction_x *mem_trans,
			 tee_mm_entry_t *mm, void *buf, size_t blen,
			 size_t flen, uint64_t *global_handle)
{
	int rc = 0;
	struct mem_share_state share = { };
	size_t addr_range_offs = 0;
	uint64_t cookie = OPTEE_MSG_FMEM_INVALID_GLOBAL_ID;
	size_t n = 0;

	rc = mem_share_init(mem_trans, buf, flen, &share.page_count,
			    &share.region_count, &addr_range_offs);
	if (rc)
		return rc;

	if (MUL_OVERFLOW(share.region_count,
			 sizeof(struct ffa_address_range), &n) ||
	    ADD_OVERFLOW(n, addr_range_offs, &n) || n > blen)
		return FFA_INVALID_PARAMETERS;

	if (mem_trans->global_handle)
		cookie = mem_trans->global_handle;
	share.mf = mobj_ffa_sel1_spmc_new(cookie, share.page_count);
	if (!share.mf)
		return FFA_NO_MEMORY;

	if (flen != blen) {
		struct mem_frag_state *s = calloc(sizeof(*s), 1);

		if (!s) {
			rc = FFA_NO_MEMORY;
			goto err;
		}
		s->share = share;
		s->mm = mm;
		s->frag_offset = addr_range_offs;

		SLIST_INSERT_HEAD(&frag_state_head, s, link);
		rc = add_mem_share_frag(s, (char *)buf + addr_range_offs,
					flen - addr_range_offs);

		if (rc >= 0)
			*global_handle = mobj_ffa_get_cookie(share.mf);

		return rc;
	}

	rc = add_mem_share_helper(&share, (char *)buf + addr_range_offs,
				  flen - addr_range_offs);
	if (rc) {
		/*
		 * Number of consumed bytes may be returned instead of 0 for
		 * done.
		 */
		rc = FFA_INVALID_PARAMETERS;
		goto err;
	}

	*global_handle = mobj_ffa_push_to_inactive(share.mf);

	return 0;
err:
	mobj_ffa_sel1_spmc_delete(share.mf);
	return rc;
}

static int handle_mem_share_tmem(paddr_t pbuf, size_t blen, size_t flen,
				 unsigned int page_count,
				 uint64_t *global_handle, struct ffa_rxtx *rxtx)
{
	struct ffa_mem_transaction_x mem_trans = { };
	int rc = 0;
	size_t len = 0;
	void *buf = NULL;
	tee_mm_entry_t *mm = NULL;
	vaddr_t offs = pbuf & SMALL_PAGE_MASK;

	if (MUL_OVERFLOW(page_count, SMALL_PAGE_SIZE, &len))
		return FFA_INVALID_PARAMETERS;
	if (!core_pbuf_is(CORE_MEM_NON_SEC, pbuf, len))
		return FFA_INVALID_PARAMETERS;

	/*
	 * Check that the length reported in flen is covered by len even
	 * if the offset is taken into account.
	 */
	if (len < flen || len - offs < flen)
		return FFA_INVALID_PARAMETERS;

	mm = tee_mm_alloc(&tee_mm_shm, len);
	if (!mm)
		return FFA_NO_MEMORY;

	if (core_mmu_map_contiguous_pages(tee_mm_get_smem(mm), pbuf,
					  page_count, MEM_AREA_NSEC_SHM)) {
		rc = FFA_INVALID_PARAMETERS;
		goto out;
	}
	buf = (void *)(tee_mm_get_smem(mm) + offs);

	cpu_spin_lock(&rxtx->spinlock);
	rc = spmc_read_mem_transaction(rxtx->ffa_vers, buf, flen, &mem_trans);
	if (!rc && IS_ENABLED(CFG_NS_VIRTUALIZATION) &&
	    virt_set_guest(mem_trans.sender_id))
		rc = FFA_DENIED;
	if (!rc)
		rc = add_mem_share(&mem_trans, mm, buf, blen, flen,
				   global_handle);
	virt_unset_guest();
	cpu_spin_unlock(&rxtx->spinlock);
	if (rc > 0)
		return rc;

	core_mmu_unmap_pages(tee_mm_get_smem(mm), page_count);
out:
	tee_mm_free(mm);
	return rc;
}

static int handle_mem_share_rxbuf(size_t blen, size_t flen,
				  uint64_t *global_handle,
				  struct ffa_rxtx *rxtx)
{
	struct ffa_mem_transaction_x mem_trans = { };
	int rc = FFA_DENIED;

	cpu_spin_lock(&rxtx->spinlock);

	if (!rxtx->rx || flen > rxtx->size)
		goto out;

	rc = spmc_read_mem_transaction(rxtx->ffa_vers, rxtx->rx, flen,
				       &mem_trans);
	if (rc)
		goto out;
	if (is_sp_share(&mem_trans, rxtx->rx)) {
		rc = spmc_sp_add_share(&mem_trans, rxtx, blen,
				       global_handle, NULL);
		goto out;
	}

	if (IS_ENABLED(CFG_NS_VIRTUALIZATION) &&
	    virt_set_guest(mem_trans.sender_id))
		goto out;

	rc = add_mem_share(&mem_trans, NULL, rxtx->rx, blen, flen,
			   global_handle);

	virt_unset_guest();

out:
	cpu_spin_unlock(&rxtx->spinlock);

	return rc;
}

static void handle_mem_share(struct thread_smc_args *args,
			     struct ffa_rxtx *rxtx)
{
	uint32_t tot_len = args->a1;
	uint32_t frag_len = args->a2;
	uint64_t addr = args->a3;
	uint32_t page_count = args->a4;
	uint32_t ret_w1 = 0;
	uint32_t ret_w2 = FFA_INVALID_PARAMETERS;
	uint32_t ret_w3 = 0;
	uint32_t ret_fid = FFA_ERROR;
	uint64_t global_handle = 0;
	int rc = 0;

	/* Check that the MBZs are indeed 0 */
	if (args->a5 || args->a6 || args->a7)
		goto out;

	/* Check that fragment length doesn't exceed total length */
	if (frag_len > tot_len)
		goto out;

	/* Check for 32-bit calling convention */
	if (args->a0 == FFA_MEM_SHARE_32)
		addr &= UINT32_MAX;

	if (!addr) {
		/*
		 * The memory transaction descriptor is passed via our rx
		 * buffer.
		 */
		if (page_count)
			goto out;
		rc = handle_mem_share_rxbuf(tot_len, frag_len, &global_handle,
					    rxtx);
	} else {
		rc = handle_mem_share_tmem(addr, tot_len, frag_len, page_count,
					   &global_handle, rxtx);
	}
	if (rc < 0) {
		ret_w2 = rc;
	} else if (rc > 0) {
		ret_fid = FFA_MEM_FRAG_RX;
		ret_w3 = rc;
		reg_pair_from_64(global_handle, &ret_w2, &ret_w1);
	} else {
		ret_fid = FFA_SUCCESS_32;
		reg_pair_from_64(global_handle, &ret_w3, &ret_w2);
	}
out:
	spmc_set_args(args, ret_fid, ret_w1, ret_w2, ret_w3, 0, 0);
}

static struct mem_frag_state *get_frag_state(uint64_t global_handle)
{
	struct mem_frag_state *s = NULL;

	SLIST_FOREACH(s, &frag_state_head, link)
		if (mobj_ffa_get_cookie(s->share.mf) == global_handle)
			return s;

	return NULL;
}

static void handle_mem_frag_tx(struct thread_smc_args *args,
			       struct ffa_rxtx *rxtx)
{
	uint64_t global_handle = reg_pair_to_64(args->a2, args->a1);
	size_t flen = args->a3;
	uint32_t endpoint_id = args->a4;
	struct mem_frag_state *s = NULL;
	tee_mm_entry_t *mm = NULL;
	unsigned int page_count = 0;
	void *buf = NULL;
	uint32_t ret_w1 = 0;
	uint32_t ret_w2 = 0;
	uint32_t ret_w3 = 0;
	uint32_t ret_fid = 0;
	int rc = 0;

	if (IS_ENABLED(CFG_NS_VIRTUALIZATION)) {
		uint16_t guest_id = endpoint_id >> 16;

		if (!guest_id || virt_set_guest(guest_id)) {
			rc = FFA_INVALID_PARAMETERS;
			goto out_set_rc;
		}
	}

	/*
	 * Currently we're only doing this for fragmented FFA_MEM_SHARE_*
	 * requests.
	 */

	cpu_spin_lock(&rxtx->spinlock);

	s = get_frag_state(global_handle);
	if (!s) {
		rc = FFA_INVALID_PARAMETERS;
		goto out;
	}

	mm = s->mm;
	if (mm) {
		if (flen > tee_mm_get_bytes(mm)) {
			rc = FFA_INVALID_PARAMETERS;
			goto out;
		}
		page_count = s->share.page_count;
		buf = (void *)tee_mm_get_smem(mm);
	} else {
		if (flen > rxtx->size) {
			rc = FFA_INVALID_PARAMETERS;
			goto out;
		}
		buf = rxtx->rx;
	}

	rc = add_mem_share_frag(s, buf, flen);
out:
	virt_unset_guest();
	cpu_spin_unlock(&rxtx->spinlock);

	if (rc <= 0 && mm) {
		core_mmu_unmap_pages(tee_mm_get_smem(mm), page_count);
		tee_mm_free(mm);
	}

out_set_rc:
	if (rc < 0) {
		ret_fid = FFA_ERROR;
		ret_w2 = rc;
	} else if (rc > 0) {
		ret_fid = FFA_MEM_FRAG_RX;
		ret_w3 = rc;
		reg_pair_from_64(global_handle, &ret_w2, &ret_w1);
	} else {
		ret_fid = FFA_SUCCESS_32;
		reg_pair_from_64(global_handle, &ret_w3, &ret_w2);
	}

	spmc_set_args(args, ret_fid, ret_w1, ret_w2, ret_w3, 0, 0);
}

static void handle_mem_reclaim(struct thread_smc_args *args)
{
	int rc = FFA_INVALID_PARAMETERS;
	uint64_t cookie = 0;

	if (args->a3 || args->a4 || args->a5 || args->a6 || args->a7)
		goto out;

	cookie = reg_pair_to_64(args->a2, args->a1);
	if (IS_ENABLED(CFG_NS_VIRTUALIZATION)) {
		uint16_t guest_id = 0;

		if (cookie & FFA_MEMORY_HANDLE_HYPERVISOR_BIT) {
			guest_id = virt_find_guest_by_cookie(cookie);
		} else {
			guest_id = (cookie >> FFA_MEMORY_HANDLE_PRTN_SHIFT) &
				   FFA_MEMORY_HANDLE_PRTN_MASK;
		}
		if (!guest_id)
			goto out;
		if (virt_set_guest(guest_id)) {
			if (!virt_reclaim_cookie_from_destroyed_guest(guest_id,
								      cookie))
				rc = FFA_OK;
			goto out;
		}
	}

	switch (mobj_ffa_sel1_spmc_reclaim(cookie)) {
	case TEE_SUCCESS:
		rc = FFA_OK;
		break;
	case TEE_ERROR_ITEM_NOT_FOUND:
		DMSG("cookie %#"PRIx64" not found", cookie);
		rc = FFA_INVALID_PARAMETERS;
		break;
	default:
		DMSG("cookie %#"PRIx64" busy", cookie);
		rc = FFA_DENIED;
		break;
	}

	virt_unset_guest();

out:
	set_simple_ret_val(args, rc);
}

static void handle_notification_bitmap_create(struct thread_smc_args *args)
{
	uint32_t ret_val = FFA_INVALID_PARAMETERS;
	uint32_t ret_fid = FFA_ERROR;
	uint32_t old_itr_status = 0;

	if (!FFA_TARGET_INFO_GET_SP_ID(args->a1) && !args->a3 && !args->a4 &&
	    !args->a5 && !args->a6 && !args->a7) {
		uint16_t vm_id = args->a1;

		old_itr_status = cpu_spin_lock_xsave(&spmc_notif_lock);

		if (notif_vm_id_valid) {
			if (vm_id == notif_vm_id)
				ret_val = FFA_DENIED;
			else
				ret_val = FFA_NO_MEMORY;
		} else {
			notif_vm_id = vm_id;
			notif_vm_id_valid = true;
			ret_val = FFA_OK;
			ret_fid = FFA_SUCCESS_32;
		}

		cpu_spin_unlock_xrestore(&spmc_notif_lock, old_itr_status);
	}

	spmc_set_args(args, ret_fid, 0, ret_val, 0, 0, 0);
}

static void handle_notification_bitmap_destroy(struct thread_smc_args *args)
{
	uint32_t ret_val = FFA_INVALID_PARAMETERS;
	uint32_t ret_fid = FFA_ERROR;
	uint32_t old_itr_status = 0;

	if (!FFA_TARGET_INFO_GET_SP_ID(args->a1) && !args->a3 && !args->a4 &&
	    !args->a5 && !args->a6 && !args->a7) {
		uint16_t vm_id = args->a1;

		old_itr_status = cpu_spin_lock_xsave(&spmc_notif_lock);

		if (notif_vm_id_valid && vm_id == notif_vm_id) {
			if (notif_pending_bitmap || notif_bound_bitmap) {
				ret_val = FFA_DENIED;
			} else {
				notif_vm_id_valid = false;
				ret_val = FFA_OK;
				ret_fid = FFA_SUCCESS_32;
			}
		}

		cpu_spin_unlock_xrestore(&spmc_notif_lock, old_itr_status);
	}

	spmc_set_args(args, ret_fid, 0, ret_val, 0, 0, 0);
}

static void handle_notification_bind(struct thread_smc_args *args)
{
	uint32_t ret_val = FFA_INVALID_PARAMETERS;
	uint32_t ret_fid = FFA_ERROR;
	uint32_t old_itr_status = 0;
	uint64_t bitmap = 0;
	uint16_t vm_id = 0;

	if (args->a5 || args->a6 || args->a7)
		goto out;
	if (args->a2) {
		/* We only deal with global notifications for now */
		ret_val = FFA_NOT_SUPPORTED;
		goto out;
	}

	/* The destination of the eventual notification */
	vm_id = FFA_DST(args->a1);
	bitmap = reg_pair_to_64(args->a4, args->a3);

	old_itr_status = cpu_spin_lock_xsave(&spmc_notif_lock);

	if (notif_vm_id_valid && vm_id == notif_vm_id) {
		if (bitmap & notif_bound_bitmap) {
			ret_val = FFA_DENIED;
		} else {
			notif_bound_bitmap |= bitmap;
			ret_val = FFA_OK;
			ret_fid = FFA_SUCCESS_32;
		}
	}

	cpu_spin_unlock_xrestore(&spmc_notif_lock, old_itr_status);
out:
	spmc_set_args(args, ret_fid, 0, ret_val, 0, 0, 0);
}

static void handle_notification_unbind(struct thread_smc_args *args)
{
	uint32_t ret_val = FFA_INVALID_PARAMETERS;
	uint32_t ret_fid = FFA_ERROR;
	uint32_t old_itr_status = 0;
	uint64_t bitmap = 0;
	uint16_t vm_id = 0;

	if (args->a2 || args->a5 || args->a6 || args->a7)
		goto out;

	/* The destination of the eventual notification */
	vm_id = FFA_DST(args->a1);
	bitmap = reg_pair_to_64(args->a4, args->a3);

	old_itr_status = cpu_spin_lock_xsave(&spmc_notif_lock);

	if (notif_vm_id_valid && vm_id == notif_vm_id) {
		/*
		 * Spec says:
		 * At least one notification is bound to another Sender or
		 * is currently pending.
		 *
		 * Not sure what the intention is.
		 */
		if (bitmap & notif_pending_bitmap) {
			ret_val = FFA_DENIED;
		} else {
			notif_bound_bitmap &= ~bitmap;
			ret_val = FFA_OK;
			ret_fid = FFA_SUCCESS_32;
		}
	}

	cpu_spin_unlock_xrestore(&spmc_notif_lock, old_itr_status);
out:
	spmc_set_args(args, ret_fid, 0, ret_val, 0, 0, 0);
}

static void handle_notification_get(struct thread_smc_args *args)
{
	uint32_t w2 = FFA_INVALID_PARAMETERS;
	uint32_t ret_fid = FFA_ERROR;
	uint32_t old_itr_status = 0;
	uint16_t vm_id = 0;
	uint32_t w3 = 0;

	if (args->a5 || args->a6 || args->a7)
		goto out;
	if (!(args->a2 & 0x1)) {
		ret_fid = FFA_SUCCESS_32;
		w2 = 0;
		goto out;
	}
	vm_id = FFA_DST(args->a1);

	old_itr_status = cpu_spin_lock_xsave(&spmc_notif_lock);

	if (notif_vm_id_valid && vm_id == notif_vm_id) {
		reg_pair_from_64(notif_pending_bitmap, &w3, &w2);
		notif_pending_bitmap = 0;
		ret_fid = FFA_SUCCESS_32;
	}

	cpu_spin_unlock_xrestore(&spmc_notif_lock, old_itr_status);
out:
	spmc_set_args(args, ret_fid, 0, w2, w3, 0, 0);
}

static void handle_notification_info_get(struct thread_smc_args *args)
{
	uint32_t w2 = FFA_INVALID_PARAMETERS;
	uint32_t ret_fid = FFA_ERROR;

	if (args->a1 || args->a2 || args->a3 || args->a4 || args->a5 ||
	    args->a6 || args->a7)
		goto out;

	if (OPTEE_SMC_IS_64(args->a0))
		ret_fid = FFA_SUCCESS_64;
	else
		ret_fid = FFA_SUCCESS_32;

	/*
	 * Note, we're only supporting physical OS kernel in normal world
	 * with Global Notifications.
	 * So one list of ID list registers (BIT[11:7])
	 * and one count of IDs (BIT[13:12] + 1)
	 * and the VM is always 0.
	 */
	w2 = SHIFT_U32(1, 7);
out:
	spmc_set_args(args, ret_fid, 0, w2, 0, 0, 0);
}

void thread_spmc_set_async_notif_intid(int intid)
{
	assert(interrupt_can_raise_sgi(interrupt_get_main_chip()));
	notif_intid = intid;
	spmc_notif_is_ready = true;
	DMSG("Asynchronous notifications are ready");
}

void notif_send_async(uint32_t value)
{
	uint32_t old_itr_status = 0;

	old_itr_status = cpu_spin_lock_xsave(&spmc_notif_lock);
	assert(value == NOTIF_VALUE_DO_BOTTOM_HALF && spmc_notif_is_ready &&
	       do_bottom_half_value >= 0 && notif_intid >= 0);
	notif_pending_bitmap |= BIT64(do_bottom_half_value);
	interrupt_raise_sgi(interrupt_get_main_chip(), notif_intid,
			    ITR_CPU_MASK_TO_THIS_CPU);
	cpu_spin_unlock_xrestore(&spmc_notif_lock, old_itr_status);
}
#else
void notif_send_async(uint32_t value)
{
	/* global notification, delay notification interrupt */
	uint32_t flags = BIT32(1);
	int res = 0;

	assert(value == NOTIF_VALUE_DO_BOTTOM_HALF && spmc_notif_is_ready &&
	       do_bottom_half_value >= 0);
	res = ffa_set_notification(notif_vm_id, optee_endpoint_id, flags,
				   BIT64(do_bottom_half_value));
	if (res) {
		EMSG("notification set failed with error %d", res);
		panic();
	}
}
#endif

/* Only called from assembly */
void thread_spmc_msg_recv(struct thread_smc_args *args);
void thread_spmc_msg_recv(struct thread_smc_args *args)
{
	assert((thread_get_exceptions() & THREAD_EXCP_ALL) == THREAD_EXCP_ALL);
	switch (args->a0) {
#if defined(CFG_CORE_SEL1_SPMC)
	case FFA_FEATURES:
		handle_features(args);
		break;
	case FFA_SPM_ID_GET:
		spmc_handle_spm_id_get(args);
		break;
#ifdef ARM64
	case FFA_RXTX_MAP_64:
#endif
	case FFA_RXTX_MAP_32:
		spmc_handle_rxtx_map(args, &my_rxtx);
		break;
	case FFA_RXTX_UNMAP:
		spmc_handle_rxtx_unmap(args, &my_rxtx);
		break;
	case FFA_RX_RELEASE:
		spmc_handle_rx_release(args, &my_rxtx);
		break;
	case FFA_PARTITION_INFO_GET:
		spmc_handle_partition_info_get(args, &my_rxtx);
		break;
	case FFA_RUN:
		spmc_handle_run(args);
		break;
#endif /*CFG_CORE_SEL1_SPMC*/
	case FFA_INTERRUPT:
		if (IS_ENABLED(CFG_CORE_SEL1_SPMC))
			spmc_set_args(args, FFA_NORMAL_WORLD_RESUME, 0, 0, 0,
				      0, 0);
		else
			spmc_set_args(args, FFA_MSG_WAIT, 0, 0, 0, 0, 0);
		break;
#ifdef ARM64
	case FFA_MSG_SEND_DIRECT_REQ_64:
#endif
	case FFA_MSG_SEND_DIRECT_REQ_32:
		handle_direct_request(args, &my_rxtx);
		break;
#if defined(CFG_CORE_SEL1_SPMC)
#ifdef ARM64
	case FFA_MEM_SHARE_64:
#endif
	case FFA_MEM_SHARE_32:
		handle_mem_share(args, &my_rxtx);
		break;
	case FFA_MEM_RECLAIM:
		if (!IS_ENABLED(CFG_SECURE_PARTITION) ||
		    !ffa_mem_reclaim(args, NULL))
			handle_mem_reclaim(args);
		break;
	case FFA_MEM_FRAG_TX:
		handle_mem_frag_tx(args, &my_rxtx);
		break;
	case FFA_NOTIFICATION_BITMAP_CREATE:
		handle_notification_bitmap_create(args);
		break;
	case FFA_NOTIFICATION_BITMAP_DESTROY:
		handle_notification_bitmap_destroy(args);
		break;
	case FFA_NOTIFICATION_BIND:
		handle_notification_bind(args);
		break;
	case FFA_NOTIFICATION_UNBIND:
		handle_notification_unbind(args);
		break;
	case FFA_NOTIFICATION_GET:
		handle_notification_get(args);
		break;
#ifdef ARM64
	case FFA_NOTIFICATION_INFO_GET_64:
#endif
	case FFA_NOTIFICATION_INFO_GET_32:
		handle_notification_info_get(args);
		break;
#endif /*CFG_CORE_SEL1_SPMC*/
	case FFA_ERROR:
		EMSG("Cannot handle FFA_ERROR(%d)", (int)args->a2);
		if (!IS_ENABLED(CFG_CORE_SEL1_SPMC)) {
			/*
			 * The SPMC will return an FFA_ERROR back so better
			 * panic() now than flooding the log.
			 */
			panic("FFA_ERROR from SPMC is fatal");
		}
		spmc_set_args(args, FFA_ERROR, FFA_PARAM_MBZ, FFA_NOT_SUPPORTED,
			      FFA_PARAM_MBZ, FFA_PARAM_MBZ, FFA_PARAM_MBZ);
		break;
	default:
		EMSG("Unhandled FFA function ID %#"PRIx32, (uint32_t)args->a0);
		set_simple_ret_val(args, FFA_NOT_SUPPORTED);
	}
}

static TEE_Result yielding_call_with_arg(uint64_t cookie, uint32_t offset)
{
	size_t sz_rpc = OPTEE_MSG_GET_ARG_SIZE(THREAD_RPC_MAX_NUM_PARAMS);
	struct thread_ctx *thr = threads + thread_get_id();
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct optee_msg_arg *arg = NULL;
	struct mobj *mobj = NULL;
	uint32_t num_params = 0;
	size_t sz = 0;

	mobj = mobj_ffa_get_by_cookie(cookie, 0);
	if (!mobj) {
		EMSG("Can't find cookie %#"PRIx64, cookie);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = mobj_inc_map(mobj);
	if (res)
		goto out_put_mobj;

	res = TEE_ERROR_BAD_PARAMETERS;
	arg = mobj_get_va(mobj, offset, sizeof(*arg));
	if (!arg)
		goto out_dec_map;

	num_params = READ_ONCE(arg->num_params);
	if (num_params > OPTEE_MSG_MAX_NUM_PARAMS)
		goto out_dec_map;

	sz = OPTEE_MSG_GET_ARG_SIZE(num_params);

	thr->rpc_arg = mobj_get_va(mobj, offset + sz, sz_rpc);
	if (!thr->rpc_arg)
		goto out_dec_map;

	virt_on_stdcall();
	res = tee_entry_std(arg, num_params);

	thread_rpc_shm_cache_clear(&thr->shm_cache);
	thr->rpc_arg = NULL;

out_dec_map:
	mobj_dec_map(mobj);
out_put_mobj:
	mobj_put(mobj);
	return res;
}

/*
 * Helper routine for the assembly function thread_std_smc_entry()
 *
 * Note: this function is weak just to make link_dummies_paged.c happy.
 */
uint32_t __weak __thread_std_smc_entry(uint32_t a0, uint32_t a1,
				       uint32_t a2, uint32_t a3,
				       uint32_t a4, uint32_t a5 __unused)
{
	/*
	 * Arguments are supplied from handle_yielding_call() as:
	 * a0 <- w1
	 * a1 <- w3
	 * a2 <- w4
	 * a3 <- w5
	 * a4 <- w6
	 * a5 <- w7
	 */
	thread_get_tsd()->rpc_target_info = swap_src_dst(a0);
	if (a1 == OPTEE_FFA_YIELDING_CALL_WITH_ARG)
		return yielding_call_with_arg(reg_pair_to_64(a3, a2), a4);
	return FFA_DENIED;
}

static bool set_fmem(struct optee_msg_param *param, struct thread_param *tpm)
{
	uint64_t offs = tpm->u.memref.offs;

	param->attr = tpm->attr - THREAD_PARAM_ATTR_MEMREF_IN +
		      OPTEE_MSG_ATTR_TYPE_FMEM_INPUT;

	param->u.fmem.offs_low = offs;
	param->u.fmem.offs_high = offs >> 32;
	if (param->u.fmem.offs_high != offs >> 32)
		return false;

	param->u.fmem.size = tpm->u.memref.size;
	if (tpm->u.memref.mobj) {
		uint64_t cookie = mobj_get_cookie(tpm->u.memref.mobj);

		/* If a mobj is passed it better be one with a valid cookie. */
		if (cookie == OPTEE_MSG_FMEM_INVALID_GLOBAL_ID)
			return false;
		param->u.fmem.global_id = cookie;
	} else {
		param->u.fmem.global_id = OPTEE_MSG_FMEM_INVALID_GLOBAL_ID;
	}

	return true;
}

static uint32_t get_rpc_arg(uint32_t cmd, size_t num_params,
			    struct thread_param *params,
			    struct optee_msg_arg **arg_ret)
{
	size_t sz = OPTEE_MSG_GET_ARG_SIZE(THREAD_RPC_MAX_NUM_PARAMS);
	struct thread_ctx *thr = threads + thread_get_id();
	struct optee_msg_arg *arg = thr->rpc_arg;

	if (num_params > THREAD_RPC_MAX_NUM_PARAMS)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!arg) {
		EMSG("rpc_arg not set");
		return TEE_ERROR_GENERIC;
	}

	memset(arg, 0, sz);
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
			if (!set_fmem(arg->params + n, params + n))
				return TEE_ERROR_BAD_PARAMETERS;
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	if (arg_ret)
		*arg_ret = arg;

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
			params[n].u.memref.size = arg->params[n].u.fmem.size;
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
	struct thread_rpc_arg rpc_arg = { .call = {
			.w1 = thread_get_tsd()->rpc_target_info,
			.w4 = OPTEE_FFA_YIELDING_CALL_RETURN_RPC_CMD,
		},
	};
	struct optee_msg_arg *arg = NULL;
	uint32_t ret = 0;

	ret = get_rpc_arg(cmd, num_params, params, &arg);
	if (ret)
		return ret;

	thread_rpc(&rpc_arg);

	return get_rpc_arg_res(arg, num_params, params);
}

static void thread_rpc_free(unsigned int bt, uint64_t cookie, struct mobj *mobj)
{
	struct thread_rpc_arg rpc_arg = { .call = {
			.w1 = thread_get_tsd()->rpc_target_info,
			.w4 = OPTEE_FFA_YIELDING_CALL_RETURN_RPC_CMD,
		},
	};
	struct thread_param param = THREAD_PARAM_VALUE(IN, bt, cookie, 0);
	uint32_t res2 = 0;
	uint32_t res = 0;

	DMSG("freeing cookie %#"PRIx64, cookie);

	res = get_rpc_arg(OPTEE_RPC_CMD_SHM_FREE, 1, &param, NULL);

	mobj_put(mobj);
	res2 = mobj_ffa_unregister_by_cookie(cookie);
	if (res2)
		DMSG("mobj_ffa_unregister_by_cookie(%#"PRIx64"): %#"PRIx32,
		     cookie, res2);
	if (!res)
		thread_rpc(&rpc_arg);
}

static struct mobj *thread_rpc_alloc(size_t size, size_t align, unsigned int bt)
{
	struct thread_rpc_arg rpc_arg = { .call = {
			.w1 = thread_get_tsd()->rpc_target_info,
			.w4 = OPTEE_FFA_YIELDING_CALL_RETURN_RPC_CMD,
		},
	};
	struct thread_param param = THREAD_PARAM_VALUE(IN, bt, size, align);
	struct optee_msg_arg *arg = NULL;
	unsigned int internal_offset = 0;
	struct mobj *mobj = NULL;
	uint64_t cookie = 0;

	if (get_rpc_arg(OPTEE_RPC_CMD_SHM_ALLOC, 1, &param, &arg))
		return NULL;

	thread_rpc(&rpc_arg);

	if (arg->num_params != 1 ||
	    arg->params->attr != OPTEE_MSG_ATTR_TYPE_FMEM_OUTPUT)
		return NULL;

	internal_offset = READ_ONCE(arg->params->u.fmem.internal_offs);
	cookie = READ_ONCE(arg->params->u.fmem.global_id);
	mobj = mobj_ffa_get_by_cookie(cookie, internal_offset);
	if (!mobj) {
		DMSG("mobj_ffa_get_by_cookie(%#"PRIx64", %#x): failed",
		     cookie, internal_offset);
		return NULL;
	}

	assert(mobj_is_nonsec(mobj));

	if (mobj->size < size) {
		DMSG("Mobj %#"PRIx64": wrong size", cookie);
		mobj_put(mobj);
		return NULL;
	}

	if (mobj_inc_map(mobj)) {
		DMSG("mobj_inc_map(%#"PRIx64"): failed", cookie);
		mobj_put(mobj);
		return NULL;
	}

	return mobj;
}

struct mobj *thread_rpc_alloc_payload(size_t size)
{
	return thread_rpc_alloc(size, 8, OPTEE_RPC_SHM_TYPE_APPL);
}

struct mobj *thread_rpc_alloc_kernel_payload(size_t size)
{
	return thread_rpc_alloc(size, 8, OPTEE_RPC_SHM_TYPE_KERNEL);
}

void thread_rpc_free_kernel_payload(struct mobj *mobj)
{
	if (mobj)
		thread_rpc_free(OPTEE_RPC_SHM_TYPE_KERNEL,
				mobj_get_cookie(mobj), mobj);
}

void thread_rpc_free_payload(struct mobj *mobj)
{
	if (mobj)
		thread_rpc_free(OPTEE_RPC_SHM_TYPE_APPL, mobj_get_cookie(mobj),
				mobj);
}

struct mobj *thread_rpc_alloc_global_payload(size_t size)
{
	return thread_rpc_alloc(size, 8, OPTEE_RPC_SHM_TYPE_GLOBAL);
}

void thread_rpc_free_global_payload(struct mobj *mobj)
{
	if (mobj)
		thread_rpc_free(OPTEE_RPC_SHM_TYPE_GLOBAL,
				mobj_get_cookie(mobj), mobj);
}

void thread_spmc_register_secondary_ep(vaddr_t ep)
{
	unsigned long ret = 0;

	/* Let the SPM know the entry point for secondary CPUs */
	ret = thread_smc(FFA_SECONDARY_EP_REGISTER_64, ep, 0, 0);

	if (ret != FFA_SUCCESS_32 && ret != FFA_SUCCESS_64)
		EMSG("FFA_SECONDARY_EP_REGISTER_64 ret %#lx", ret);
}

static uint16_t ffa_id_get(void)
{
	/*
	 * Ask the SPM component running at a higher EL to return our FF-A ID.
	 * This can either be the SPMC ID (if the SPMC is enabled in OP-TEE) or
	 * the partition ID (if not).
	 */
	struct thread_smc_args args = {
		.a0 = FFA_ID_GET,
	};

	thread_smccc(&args);
	if (!is_ffa_success(args.a0)) {
		if (args.a0 == FFA_ERROR)
			EMSG("Get id failed with error %ld", args.a2);
		else
			EMSG("Get id failed");
		panic();
	}

	return args.a2;
}

static uint16_t ffa_spm_id_get(void)
{
	/*
	 * Ask the SPM component running at a higher EL to return its ID.
	 * If OP-TEE implements the S-EL1 SPMC, this will get the SPMD ID.
	 * If not, the ID of the SPMC will be returned.
	 */
	struct thread_smc_args args = {
		.a0 = FFA_SPM_ID_GET,
	};

	thread_smccc(&args);
	if (!is_ffa_success(args.a0)) {
		if (args.a0 == FFA_ERROR)
			EMSG("Get spm id failed with error %ld", args.a2);
		else
			EMSG("Get spm id failed");
		panic();
	}

	return args.a2;
}

#if defined(CFG_CORE_SEL1_SPMC)
static TEE_Result spmc_init(void)
{
	spmd_id = ffa_spm_id_get();
	DMSG("SPMD ID %#"PRIx16, spmd_id);

	spmc_id = ffa_id_get();
	DMSG("SPMC ID %#"PRIx16, spmc_id);

	optee_endpoint_id = FFA_SWD_ID_MIN;
	while (optee_endpoint_id == spmd_id || optee_endpoint_id == spmc_id)
		optee_endpoint_id++;

	DMSG("OP-TEE endpoint ID %#"PRIx16, optee_endpoint_id);

	/*
	 * If SPMD think we are version 1.0 it will report version 1.0 to
	 * normal world regardless of what version we query the SPM with.
	 * However, if SPMD think we are version 1.1 it will forward
	 * queries from normal world to let us negotiate version. So by
	 * setting version 1.0 here we should be compatible.
	 *
	 * Note that disagreement on negotiated version means that we'll
	 * have communication problems with normal world.
	 */
	my_rxtx.ffa_vers = FFA_VERSION_1_0;

	return TEE_SUCCESS;
}
#else /* !defined(CFG_CORE_SEL1_SPMC) */
static void spmc_rxtx_map(struct ffa_rxtx *rxtx)
{
	struct thread_smc_args args = {
#ifdef ARM64
		.a0 = FFA_RXTX_MAP_64,
#else
		.a0 = FFA_RXTX_MAP_32,
#endif
		.a1 = virt_to_phys(rxtx->tx),
		.a2 = virt_to_phys(rxtx->rx),
		.a3 = 1,
	};

	thread_smccc(&args);
	if (!is_ffa_success(args.a0)) {
		if (args.a0 == FFA_ERROR)
			EMSG("rxtx map failed with error %ld", args.a2);
		else
			EMSG("rxtx map failed");
		panic();
	}
}

static uint32_t get_ffa_version(uint32_t my_version)
{
	struct thread_smc_args args = {
		.a0 = FFA_VERSION,
		.a1 = my_version,
	};

	thread_smccc(&args);
	if (args.a0 & BIT(31)) {
		EMSG("FF-A version failed with error %ld", args.a0);
		panic();
	}

	return args.a0;
}

static void *spmc_retrieve_req(uint64_t cookie,
			       struct ffa_mem_transaction_x *trans)
{
	struct ffa_mem_access *acc_descr_array = NULL;
	struct ffa_mem_access_perm *perm_descr = NULL;
	struct thread_smc_args args = {
		.a0 = FFA_MEM_RETRIEVE_REQ_32,
		.a3 =	0,	/* Address, Using TX -> MBZ */
		.a4 =   0,	/* Using TX -> MBZ */
	};
	size_t size = 0;
	int rc = 0;

	if (my_rxtx.ffa_vers == FFA_VERSION_1_0) {
		struct ffa_mem_transaction_1_0 *trans_descr = my_rxtx.tx;

		size = sizeof(*trans_descr) + 1 * sizeof(struct ffa_mem_access);
		memset(trans_descr, 0, size);
		trans_descr->sender_id = thread_get_tsd()->rpc_target_info;
		trans_descr->mem_reg_attr = FFA_NORMAL_MEM_REG_ATTR;
		trans_descr->global_handle = cookie;
		trans_descr->flags = FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE |
				     FFA_MEMORY_REGION_FLAG_ANY_ALIGNMENT;
		trans_descr->mem_access_count = 1;
		acc_descr_array = trans_descr->mem_access_array;
	} else {
		struct ffa_mem_transaction_1_1 *trans_descr = my_rxtx.tx;

		size = sizeof(*trans_descr) + 1 * sizeof(struct ffa_mem_access);
		memset(trans_descr, 0, size);
		trans_descr->sender_id = thread_get_tsd()->rpc_target_info;
		trans_descr->mem_reg_attr = FFA_NORMAL_MEM_REG_ATTR;
		trans_descr->global_handle = cookie;
		trans_descr->flags = FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE |
				     FFA_MEMORY_REGION_FLAG_ANY_ALIGNMENT;
		trans_descr->mem_access_count = 1;
		trans_descr->mem_access_offs = sizeof(*trans_descr);
		trans_descr->mem_access_size = sizeof(struct ffa_mem_access);
		acc_descr_array = (void *)((vaddr_t)my_rxtx.tx +
					   sizeof(*trans_descr));
	}
	acc_descr_array->region_offs = 0;
	acc_descr_array->reserved = 0;
	perm_descr = &acc_descr_array->access_perm;
	perm_descr->endpoint_id = optee_endpoint_id;
	perm_descr->perm = FFA_MEM_ACC_RW;
	perm_descr->flags = 0;

	args.a1 = size; /* Total Length */
	args.a2 = size; /* Frag Length == Total length */
	thread_smccc(&args);
	if (args.a0 != FFA_MEM_RETRIEVE_RESP) {
		if (args.a0 == FFA_ERROR)
			EMSG("Failed to fetch cookie %#"PRIx64" error code %d",
			     cookie, (int)args.a2);
		else
			EMSG("Failed to fetch cookie %#"PRIx64" a0 %#"PRIx64,
			     cookie, args.a0);
		return NULL;
	}
	rc = spmc_read_mem_transaction(my_rxtx.ffa_vers, my_rxtx.rx,
				       my_rxtx.size, trans);
	if (rc) {
		EMSG("Memory transaction failure for cookie %#"PRIx64" rc %d",
		     cookie, rc);
		return NULL;
	}

	return my_rxtx.rx;
}

void thread_spmc_relinquish(uint64_t cookie)
{
	struct ffa_mem_relinquish *relinquish_desc = my_rxtx.tx;
	struct thread_smc_args args = {
		.a0 = FFA_MEM_RELINQUISH,
	};

	memset(relinquish_desc, 0, sizeof(*relinquish_desc));
	relinquish_desc->handle = cookie;
	relinquish_desc->flags = 0;
	relinquish_desc->endpoint_count = 1;
	relinquish_desc->endpoint_id_array[0] = optee_endpoint_id;
	thread_smccc(&args);
	if (!is_ffa_success(args.a0))
		EMSG("Failed to relinquish cookie %#"PRIx64, cookie);
}

static int set_pages(struct ffa_address_range *regions,
		     unsigned int num_regions, unsigned int num_pages,
		     struct mobj_ffa *mf)
{
	unsigned int n = 0;
	unsigned int idx = 0;

	for (n = 0; n < num_regions; n++) {
		unsigned int page_count = READ_ONCE(regions[n].page_count);
		uint64_t addr = READ_ONCE(regions[n].address);

		if (mobj_ffa_add_pages_at(mf, &idx, addr, page_count))
			return FFA_INVALID_PARAMETERS;
	}

	if (idx != num_pages)
		return FFA_INVALID_PARAMETERS;

	return 0;
}

struct mobj_ffa *thread_spmc_populate_mobj_from_rx(uint64_t cookie)
{
	struct mobj_ffa *ret = NULL;
	struct ffa_mem_transaction_x retrieve_desc = { };
	struct ffa_mem_access *descr_array = NULL;
	struct ffa_mem_region *descr = NULL;
	struct mobj_ffa *mf = NULL;
	unsigned int num_pages = 0;
	unsigned int offs = 0;
	void *buf = NULL;
	struct thread_smc_args ffa_rx_release_args = {
		.a0 = FFA_RX_RELEASE
	};

	/*
	 * OP-TEE is only supporting a single mem_region while the
	 * specification allows for more than one.
	 */
	buf = spmc_retrieve_req(cookie, &retrieve_desc);
	if (!buf) {
		EMSG("Failed to retrieve cookie from rx buffer %#"PRIx64,
		     cookie);
		return NULL;
	}

	descr_array = (void *)((vaddr_t)buf + retrieve_desc.mem_access_offs);
	offs = READ_ONCE(descr_array->region_offs);
	descr = (struct ffa_mem_region *)((vaddr_t)buf + offs);

	num_pages = READ_ONCE(descr->total_page_count);
	mf = mobj_ffa_spmc_new(cookie, num_pages);
	if (!mf)
		goto out;

	if (set_pages(descr->address_range_array,
		      READ_ONCE(descr->address_range_count), num_pages, mf)) {
		mobj_ffa_spmc_delete(mf);
		goto out;
	}

	ret = mf;

out:
	/* Release RX buffer after the mem retrieve request. */
	thread_smccc(&ffa_rx_release_args);

	return ret;
}

static TEE_Result spmc_init(void)
{
	unsigned int major = 0;
	unsigned int minor __maybe_unused = 0;
	uint32_t my_vers = 0;
	uint32_t vers = 0;

	my_vers = MAKE_FFA_VERSION(FFA_VERSION_MAJOR, FFA_VERSION_MINOR);
	vers = get_ffa_version(my_vers);
	major = (vers >> FFA_VERSION_MAJOR_SHIFT) & FFA_VERSION_MAJOR_MASK;
	minor = (vers >> FFA_VERSION_MINOR_SHIFT) & FFA_VERSION_MINOR_MASK;
	DMSG("SPMC reported version %u.%u", major, minor);
	if (major != FFA_VERSION_MAJOR) {
		EMSG("Incompatible major version %u, expected %u",
		     major, FFA_VERSION_MAJOR);
		panic();
	}
	if (vers < my_vers)
		my_vers = vers;
	DMSG("Using version %u.%u",
	     (my_vers >> FFA_VERSION_MAJOR_SHIFT) & FFA_VERSION_MAJOR_MASK,
	     (my_vers >> FFA_VERSION_MINOR_SHIFT) & FFA_VERSION_MINOR_MASK);
	my_rxtx.ffa_vers = my_vers;

	spmc_rxtx_map(&my_rxtx);

	spmc_id = ffa_spm_id_get();
	DMSG("SPMC ID %#"PRIx16, spmc_id);

	optee_endpoint_id = ffa_id_get();
	DMSG("OP-TEE endpoint ID %#"PRIx16, optee_endpoint_id);

	if (!ffa_features(FFA_NOTIFICATION_SET)) {
		spmc_notif_is_ready = true;
		DMSG("Asynchronous notifications are ready");
	}

	return TEE_SUCCESS;
}
#endif /* !defined(CFG_CORE_SEL1_SPMC) */

/*
 * boot_final() is always done before exiting at end of boot
 * initialization.  In case of virtualization the init-calls are done only
 * once a OP-TEE partition has been created. So with virtualization we have
 * to initialize via boot_final() to make sure we have a value assigned
 * before it's used the first time.
 */
#ifdef CFG_NS_VIRTUALIZATION
boot_final(spmc_init);
#else
service_init(spmc_init);
#endif
