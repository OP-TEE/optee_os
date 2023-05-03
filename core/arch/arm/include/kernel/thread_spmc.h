/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Arm Limited.
 */
#ifndef __KERNEL_THREAD_SPMC_H
#define __KERNEL_THREAD_SPMC_H

#include <ffa.h>
#include <kernel/thread.h>

/* FF-A endpoint base ID when OP-TEE is used as a S-EL1 endpoint */
#define SPMC_ENDPOINT_ID        0x8001

struct ffa_rxtx {
	void *rx;
	void *tx;
	unsigned int size;
	unsigned int spinlock;
	uint32_t ffa_vers;
	bool tx_is_mine;
};

void spmc_handle_rxtx_map(struct thread_smc_args *args, struct ffa_rxtx *buf);
void spmc_handle_rxtx_unmap(struct thread_smc_args *args, struct ffa_rxtx *buf);
void spmc_handle_rx_release(struct thread_smc_args *args, struct ffa_rxtx *buf);
uint32_t spmc_exchange_version(uint32_t vers, struct ffa_rxtx *rxtx);

void spmc_set_args(struct thread_smc_args *args, uint32_t fid, uint32_t src_dst,
		   uint32_t w2, uint32_t w3, uint32_t w4, uint32_t w5);
void spmc_handle_partition_info_get(struct thread_smc_args *args,
				    struct ffa_rxtx *rxtx);
TEE_Result spmc_fill_partition_entry(uint32_t ffa_vers, void *buf, size_t blen,
				     size_t idx, uint16_t endpoint_id,
				     uint16_t execution_context,
				     uint32_t part_props,
				     const uint32_t uuid_words[4]);
int spmc_read_mem_transaction(uint32_t ffa_vers, void *buf, size_t blen,
			      struct ffa_mem_transaction_x *trans);

#if !defined(CFG_CORE_SEL1_SPMC)
struct mobj_ffa *thread_spmc_populate_mobj_from_rx(uint64_t cookie);
void thread_spmc_relinquish(uint64_t memory_region_handle);
#endif

#endif /* __KERNEL_THREAD_SPMC_H */
