/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021-2024, Arm Limited.
 * Copyright (c) 2023-2025, Linaro Limited
 */
#ifndef __KERNEL_THREAD_SPMC_H
#define __KERNEL_THREAD_SPMC_H

#include <compiler.h>
#include <ffa.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <types_ext.h>

/* The FF-A ID of Secure World components should be between these limits */
#define FFA_SWD_ID_MIN	0x8000
#define FFA_SWD_ID_MAX	UINT16_MAX

#define SPMC_CORE_SEL1_MAX_SHM_COUNT	64

struct ffa_rxtx {
	void *rx;
	void *tx;
	unsigned int size;
	unsigned int spinlock;
	uint32_t ffa_vers;
	bool tx_is_mine;
};

void spmc_handle_spm_id_get(struct thread_smc_1_2_regs *args);
void spmc_handle_rxtx_map(struct thread_smc_1_2_regs *args,
			  struct ffa_rxtx *buf);
void spmc_handle_rxtx_unmap(struct thread_smc_1_2_regs *args,
			    struct ffa_rxtx *buf);
void spmc_handle_rx_release(struct thread_smc_1_2_regs *args,
			    struct ffa_rxtx *buf);
uint32_t spmc_exchange_version(uint32_t vers, struct ffa_rxtx *rxtx);

void spmc_set_args(struct thread_smc_1_2_regs *args, uint32_t fid,
		   uint32_t src_dst, uint32_t w2, uint32_t w3, uint32_t w4,
		   uint32_t w5);
void spmc_handle_partition_info_get(struct thread_smc_1_2_regs *args,
				    struct ffa_rxtx *rxtx);
TEE_Result spmc_fill_partition_entry(uint32_t ffa_vers, void *buf, size_t blen,
				     size_t idx, uint16_t endpoint_id,
				     uint16_t execution_context,
				     uint32_t part_props,
				     const uint32_t uuid_words[4]);
int spmc_read_mem_transaction(uint32_t ffa_vers, void *buf, size_t blen,
			      struct ffa_mem_transaction_x *trans);

bool spmc_is_reserved_id(uint16_t id);

struct spmc_lsp_desc {
	void (*direct_req)(struct thread_smc_1_2_regs *args);
	uint16_t sp_id;
	uint32_t properties;
	uint32_t uuid_words[4];
	const char *name;
	STAILQ_ENTRY(spmc_lsp_desc) link;
};

struct spmc_lsp_desc *spmc_find_lsp_by_sp_id(uint16_t sp_id);

TEE_Result spmc_register_lsp(struct spmc_lsp_desc *desc);

#if defined(CFG_CORE_SEL1_SPMC)
void thread_spmc_set_async_notif_intid(int intid);
#else
static inline void __noreturn
thread_spmc_set_async_notif_intid(int intid __unused)
{
	panic();
}
struct mobj_ffa *thread_spmc_populate_mobj_from_rx(uint64_t cookie);
void thread_spmc_relinquish(uint64_t memory_region_handle);
#endif

#endif /* __KERNEL_THREAD_SPMC_H */
