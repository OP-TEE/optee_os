/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2020, Linaro Limited
 * Copyright (c) 2021-2023, Arm Limited
 */
#ifndef __KERNEL_BOOT_H
#define __KERNEL_BOOT_H

#include <initcall.h>
#include <types_ext.h>

/*
 * struct boot_embdata - Embedded boot data
 * @total_len: Total length of the embedded boot data
 * @num_blobs: Number of blobs in the embedded boot data, always 2 even if
 *	       one blob is empty
 * @hashes_offset: Offset of hashes from start of this struct
 * @hashes_len: Length of hashes
 * @reloc_offset: Offset of reloc from start of this struct
 * @reloc_len: Length of reloc
 *
 * This struct is initialized by scripts/gen_tee_bin.py and must be kept
 * in sync with that script. The struct and the following data is loaded
 * at different addresses at boot depending on CFG_WITH_PAGER.
 *
 * If configured with CFG_WITH_PAGER=y the struct with data is following
 * init part, this is together with the init part moved by the primary CPU
 * so it ends up at __init_end. Whatever need to be saved for later need to
 * be copied to a safe location in init_runtime().
 *
 * If configured with CFG_WITH_PAGER=n following the struct with data is
 * __data_end, this is moved by the primary CPU so it ends up at __end.
 */
struct boot_embdata {
	uint32_t total_len;
	uint32_t num_blobs;
	uint32_t hashes_offset;
	uint32_t hashes_len;
	uint32_t reloc_offset;
	uint32_t reloc_len;
};

extern const struct core_mmu_config boot_mmu_config;

void boot_init_primary_early(void);
void boot_init_primary_late(unsigned long fdt, unsigned long manifest);
void boot_init_memtag(void);
void boot_clear_memtag(void);
void boot_save_args(unsigned long a0, unsigned long a1, unsigned long a2,
		    unsigned long a3, unsigned long a4);

void __panic_at_smc_return(void) __noreturn;

#if defined(CFG_WITH_ARM_TRUSTED_FW)
unsigned long cpu_on_handler(unsigned long a0, unsigned long a1);
unsigned long boot_cpu_on_handler(unsigned long a0, unsigned long a1);
#else
void boot_init_secondary(unsigned long nsec_entry);
#endif

void boot_primary_init_intc(void);
void boot_secondary_init_intc(void);

void init_sec_mon(unsigned long nsec_entry);
void init_tee_runtime(void);

/* weak routines eventually overridden by platform */
void plat_cpu_reset_early(void);
void plat_primary_init_early(void);
unsigned long plat_get_aslr_seed(void);
unsigned long plat_get_freq(void);
#if defined(_CFG_CORE_STACK_PROTECTOR) || defined(CFG_WITH_STACK_CANARIES)
/*
 * plat_get_random_stack_canaries() - Get random values for stack canaries.
 * @buf:	Pointer to the buffer where to store canaries
 * @ncan:	The number of canaries to generate.
 * @size:	The size (in bytes) of each canary.
 *
 * This function has a __weak default implementation.
 */
void plat_get_random_stack_canaries(void *buf, size_t ncan, size_t size);
#endif
void arm_cl2_config(vaddr_t pl310);
void arm_cl2_enable(vaddr_t pl310);

#if defined(CFG_BOOT_SECONDARY_REQUEST)
void boot_set_core_ns_entry(size_t core_idx, uintptr_t entry,
			    uintptr_t context_id);

int boot_core_release(size_t core_idx, paddr_t entry);
struct ns_entry_context *boot_core_hpen(void);
#endif

/* Returns TOS_FW_CONFIG DTB or SP manifest DTB if present, otherwise NULL */
void *get_manifest_dt(void);

/*
 * get_aslr_seed() - return a random seed for core ASLR
 *
 * This function has a __weak default implementation.
 */
unsigned long get_aslr_seed(void);

#endif /* __KERNEL_BOOT_H */
