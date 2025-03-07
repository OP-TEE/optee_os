/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, EPAM Systems. All rights reserved.
 * Copyright (c) 2024, Linaro Limited
 */

#ifndef __KERNEL_VIRTUALIZATION_H
#define __KERNEL_VIRTUALIZATION_H

#include <bitstring.h>
#include <mm/core_mmu.h>
#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>

#define HYP_CLNT_ID 0

struct guest_partition;

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
 * @mem_map: current OP-TEE memory map
 * @secmem0_base: base of first secure memory range
 * @secmem0_size: size of first secure memory range
 * @secmem1_base: base of an eventual second secure memory range, 0 if unused
 * @secmem1_size: size of an eventual second secure memory range, 0 if unused
 */
void virt_init_memory(struct memory_map *mem_map, paddr_t secmem0_base,
		      paddr_size_t secmem0_size, paddr_t secmem1_base,
		      paddr_size_t secmem1_size);

/**
 * virt_get_memory_map() - get current memory map
 */
struct memory_map *virt_get_memory_map(void);

/**
 * virt_get_current_guest_id() - return current guest ID
 *
 * Returns current guest ID or 0 if none is set.
 */
uint16_t virt_get_current_guest_id(void);

/**
 * virt_get_guest_id() - return guest ID of a guest partition
 * @prtn:       Guest partition
 *
 * Returns guest ID or 0 if @prtn is NULL
 */
uint16_t virt_get_guest_id(struct guest_partition *prtn);

/*
 * virt_next_guest() - iterate over guest partitions
 * @prtn:       Guest partition to start from
 *
 * Iterates of the guest partitions, if @prtn is NULL the first partition
 * is returned. If there are none or no next partition NULL is returned.
 *
 * The supplied @prtn has its reference counter decreased with
 * virt_put_guest() before returning the next partition. A returned
 * partition has its reference counter increased before being returned.
 *
 * If virt_next_guest() is called in sequence until it returns NULL, all
 * reference counters are restored, but if the sequence is stopped earlier
 * it's the callers responsibility to call virt_put_guest() on the last
 * returned partition.
 */
struct guest_partition *virt_next_guest(struct guest_partition *prtn);

/**
 * virt_get_current_guest() - increase reference to current guest partition
 *
 * Each successful call to this function must be matched by a call to
 * virt_put_guest() in order to decrease the reference counter again.
 *
 * Return a pointer to the guest partition on success or NULL on failure
 */
struct guest_partition *virt_get_current_guest(void);

/**
 * virt_get_guest() - increase reference to a guest partition
 * @guest_id:     ID of the guest partition to find
 *
 * Each successful call to this function must be matched by a call to
 * virt_put_guest() in order to decrease the reference counter again.
 *
 * Return a pointer to the guest partition on success or NULL on failure
 */
struct guest_partition *virt_get_guest(uint16_t guest_id);

/**
 * virt_put_guest() - decrease reference to a guest partition
 * @prtn:       Guest partition
 *
 * Does nothing if @prtn is NULL.
 */
void virt_put_guest(struct guest_partition *prtn);

/**
 * virt_add_guest_spec_data() - add guest specific data
 * @data_id:      assigned id for the guest specific data
 * @data_size:    size of the guest specific data
 * @data_destroy: function to destroy the guest specific data when the
 *                guest is destroyed, does not free the data itself
 *
 * Assigns a new data ID returned in @data_id and records the associated
 * @data_size size and destructor function @data_destroy.
 *
 * To keep things simple, this function is only to be called before exiting
 * to the normal world for the first time, that is, while we're single
 * threaded and only have one partition.
 */
TEE_Result virt_add_guest_spec_data(unsigned int *data_id, size_t data_size,
				    void (*data_destroy)(void *data));

/*
 * virt_get_guest_spec_data() - get guest specific data
 * @prtn: guest partition
 * @data_id:  previously assigned ID for the data
 *
 * Returns the preallocated guest specific data of the partition with the
 * ID of @guest_id, will only return NULL for an unrecognized @data_id or
 * NULL @prtn.
 */
void *virt_get_guest_spec_data(struct guest_partition *prtn,
			       unsigned int data_id);

#else
static inline TEE_Result virt_guest_created(uint16_t guest_id __unused)
{ return TEE_ERROR_NOT_SUPPORTED; }

static inline TEE_Result virt_guest_destroyed(uint16_t guest_id __unused)
{ return TEE_ERROR_NOT_SUPPORTED; }

static inline TEE_Result virt_set_guest(uint16_t guest_id __unused)
{ return TEE_ERROR_NOT_SUPPORTED; }

static inline void virt_unset_guest(void) { }
static inline void virt_on_stdcall(void) { }
static inline struct memory_map *virt_get_memory_map(void) { return NULL; }
static inline void virt_init_memory(struct memory_map *mem_map __unused,
				    paddr_t secmem0_base __unused,
				    paddr_size_t secmem0_size __unused,
				    paddr_t secmem1_base __unused,
				    paddr_size_t secmem1_size __unused) { }
static inline uint16_t virt_get_current_guest_id(void) { return 0; }
static inline uint16_t virt_get_guest_id(struct guest_partition *prtn __unused)
{
	return 0;
}
static inline struct guest_partition *virt_get_current_guest(void)
{
	return NULL;
}
static inline struct guest_partition *virt_get_guest(uint16_t guest_id __unused)
{
	return NULL;
}
static inline struct guest_partition *
virt_next_guest(struct guest_partition *prtn __unused)
{
	return NULL;
}
static inline void virt_put_guest(struct guest_partition *prtn __unused) { }
static inline TEE_Result
virt_add_guest_spec_data(unsigned int *data_id __unused,
			 size_t data_size __unused,
			 void (*data_destroy)(void *data) __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline void *
virt_get_guest_spec_data(struct guest_partition *prtn __unused,
			 unsigned int data_id __unused)
{
	return NULL;
}

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
