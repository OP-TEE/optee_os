/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Arm Limited.
 */
#ifndef __KERNEL_THREAD_SPMC_H
#define __KERNEL_THREAD_SPMC_H

#include <kernel/thread.h>

/* FF-A endpoint base ID when OP-TEE is used as a S-EL1 endpoint */
#define SPMC_ENDPOINT_ID        0x8001

struct ffa_rxtx {
	void *rx;
	void *tx;
	unsigned int size;
	unsigned int spinlock;
	bool tx_is_mine;
};

void spmc_handle_rxtx_map(struct thread_smc_args *args, struct ffa_rxtx *buf);
void spmc_handle_rxtx_unmap(struct thread_smc_args *args, struct ffa_rxtx *buf);
void spmc_handle_rx_release(struct thread_smc_args *args, struct ffa_rxtx *buf);
void spmc_handle_version(struct thread_smc_args *args);

void spmc_set_args(struct thread_smc_args *args, uint32_t fid, uint32_t src_dst,
		   uint32_t w2, uint32_t w3, uint32_t w4, uint32_t w5);
#endif /* __KERNEL_THREAD_SPMC_H */
