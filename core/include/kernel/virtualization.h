/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2018, EPAM Systems. All rights reserved. */

#ifndef __KERNEL_VIRTUALIZATION_H
#define __KERNEL_VIRTUALIZATION_H

#include <bitstring.h>
#include <mm/core_mmu.h>
#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>

#define HYP_CLNT_ID 0

#if defined(CFG_NS_VIRTUALIZATION)
/**
 * virt_guest_created() - create new VM partition
 * @guest_id: VM id provided by hypervisor
 *
 * This function is called by hypervisor (via fast SMC)
 * when hypervisor creates new guest VM, so OP-TEE
 * can prepare partition for that VM
 */
TEE_Result virt_guest_created(uint16_t guest_id);

/**
 * virt_guest_destroyed() - destroy existing VM partition
 * @guest_id: VM id provided by hypervisor
 *
 * This function is called by hypervisor (via fast SMC)
 * when hypervisor is ready to destroy guest VM. Hypervisor
 * must ensure that there are no ongoing calls from this
 * VM right now.
 */
TEE_Result virt_guest_destroyed(uint16_t guest_id);

/**
 * virt_set_guest() - set guest VM context for current core
 * @guest_id: VM id provided by hypervisor
 *
 * This function switches memory partitions, so TEE part of
 * OP-TEE will see memory associated with current guest.
 * It should be called on entry to OP-TEE
 */
TEE_Result virt_set_guest(uint16_t guest_id);

/**
 * virt_unset_guest() - set default memory partition
 *
 * This function should be called upon leaving OP-TEE,
 * to switch to default memory partition, so all TEE-specific
 * memory will be unmapped. This is safety measure to ensure
 * that TEE memory is untouched when there is no active VM.
 */
void virt_unset_guest(void);

/**
 * virt_on_stdcall() - std call hook
 *
 * This hook is called on every std call, but really is needed
 * only once: to initialize TEE runtime for current guest VM
 */
void virt_on_stdcall(void);

/*
 * Next function are needed because virtualization subsystem manages
 * memory in own way. There is no one static memory map, instead
 * every guest gets own memory map.
 */

/**
 * virt_init_memory() - initialize memory for virtualization subsystem
 * @memory_map: current OP-TEE memory map
 * @secmem0_base: base of first secure memory range
 * @secmem0_size: size of first secure memory range
 * @secmem1_base: base of an eventual second secure memory range, 0 if unused
 * @secmem1_size: size of an eventual second secure memory range, 0 if unused
 */
void virt_init_memory(struct tee_mmap_region *memory_map, paddr_t secmem0_base,
		      paddr_size_t secmem0_size, paddr_t secmem1_base,
		      paddr_size_t secmem1_size);

/**
 * virt_get_memory_map() - get current memory map
 */
struct tee_mmap_region *virt_get_memory_map(void);

/**
 * virt_get_ta_ram() - get TA RAM mapping for current VM
 * @start: beginning of TA RAM returned here
 * @end: end of TA RAM returned here
 */
void virt_get_ta_ram(vaddr_t *start, vaddr_t *end);

/**
 * virt_get_current_guest_id() - return current guest ID
 *
 * Returns current guest ID or 0 if none is set.
 */
uint16_t virt_get_current_guest_id(void);

#else
static inline TEE_Result virt_guest_created(uint16_t guest_id __unused)
{ return TEE_ERROR_NOT_SUPPORTED; }

static inline TEE_Result virt_guest_destroyed(uint16_t guest_id __unused)
{ return TEE_ERROR_NOT_SUPPORTED; }

static inline TEE_Result virt_set_guest(uint16_t guest_id __unused)
{ return TEE_ERROR_NOT_SUPPORTED; }

static inline void virt_unset_guest(void) { }
static inline void virt_on_stdcall(void) { }
static inline struct tee_mmap_region *virt_get_memory_map(void) { return NULL; }
static inline void
virt_get_ta_ram(vaddr_t *start __unused, vaddr_t *end __unused) { }
static inline void virt_init_memory(struct tee_mmap_region *memory_map __unused,
				    paddr_t secmem0_base __unused,
				    paddr_size_t secmem0_size __unused,
				    paddr_t secmem1_base __unused,
				    paddr_size_t secmem1_size __unused) { }
static inline uint16_t virt_get_current_guest_id(void) { return 0; }
#endif /*CFG_NS_VIRTUALIZATION*/

#if defined(CFG_CORE_SEL1_SPMC) && defined(CFG_NS_VIRTUALIZATION)
TEE_Result virt_add_cookie_to_current_guest(uint64_t cookie);
void virt_remove_cookie(uint64_t cookie);
uint16_t virt_find_guest_by_cookie(uint64_t cookie);
bitstr_t *virt_get_shm_bits(void);

TEE_Result virt_reclaim_cookie_from_destroyed_guest(uint16_t guest_id,
						    uint64_t cookie);
#else
static inline TEE_Result
virt_add_cookie_to_current_guest(uint64_t cookie __unused)
{ return TEE_ERROR_NOT_SUPPORTED; }
static inline void virt_remove_cookie(uint64_t cookie __unused) { }
static inline uint16_t virt_find_guest_by_cookie(uint64_t cookie __unused)
{ return 0; }
static inline bitstr_t *virt_get_shm_bits(void) { return NULL; }
static inline TEE_Result
virt_reclaim_cookie_from_destroyed_guest(uint16_t guest_id __unused,
					 uint64_t cookie __unused)
{ return TEE_ERROR_NOT_SUPPORTED; }
#endif

#endif	/* __KERNEL_VIRTUALIZATION_H */
