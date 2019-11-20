/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef KERNEL_GENERIC_BOOT_H
#define KERNEL_GENERIC_BOOT_H

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

extern uint8_t embedded_secure_dtb[];
extern const struct core_mmu_config boot_mmu_config;

#if defined(CFG_WITH_ARM_TRUSTED_FW)
unsigned long cpu_on_handler(unsigned long a0, unsigned long a1);
struct thread_vector_table *
generic_boot_init_primary(unsigned long pageable_part, unsigned long unused,
			  unsigned long fdt);
unsigned long generic_boot_cpu_on_handler(unsigned long a0, unsigned long a1);
#else
void generic_boot_init_primary(unsigned long pageable_part,
			       unsigned long nsec_entry, unsigned long fdt);
void generic_boot_init_secondary(unsigned long nsec_entry);
#endif

void main_init_gic(void);
void main_secondary_init_gic(void);

void init_sec_mon(unsigned long nsec_entry);
void init_tee_runtime(void);

const struct thread_handlers *generic_boot_get_handlers(void);

/* weak routines eventually overridden by platform */
void plat_cpu_reset_early(void);
void plat_primary_init_early(void);
void arm_cl2_config(vaddr_t pl310);
void arm_cl2_enable(vaddr_t pl310);

#if defined(CFG_BOOT_SECONDARY_REQUEST)
void generic_boot_set_core_ns_entry(size_t core_idx, uintptr_t entry,
				    uintptr_t context_id);

int generic_boot_core_release(size_t core_idx, paddr_t entry);
struct ns_entry_context *generic_boot_core_hpen(void);
#endif

/* Returns embedded DTB if present, then external DTB if found, then NULL */
void *get_dt(void);

/* Returns embedded DTB location if present, otherwise NULL */
void *get_embedded_dt(void);

/* Returns external DTB if present, otherwise NULL */
void *get_external_dt(void);

unsigned long get_aslr_seed(void *fdt);

#endif /* KERNEL_GENERIC_BOOT_H */
