/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2018, EPAM Systems. All rights reserved. */

#ifndef KERNEL_VIRTUALIZATION_H
#define KERNEL_VIRTUALIZATION_H

#include <stdbool.h>
#include <stdint.h>
#include <mm/core_mmu.h>

#define HYP_CLNT_ID 0

/**
 * virt_guest_created() - create new VM partition
 * @guest_id: VM id provided by hypervisor
 *
 * This function is called by hypervisor (via fast SMC)
 * when hypervisor creates new guest VM, so OP-TEE
 * can prepare partition for that VM
 *
 * Return: OPTEE_SMC_RETURN_* code
 */
uint32_t virt_guest_created(uint16_t guest_id);

/**
 * virt_guest_destroyed() - destroy existing VM partition
 * @guest_id: VM id provided by hypervisor
 *
 * This function is called by hypervisor (via fast SMC)
 * when hypervisor is ready to destroy guest VM. Hypervisor
 * must ensure that there are no ongoing calls from this
 * VM right now.
 *
 * Return: OPTEE_SMC_RETURN_OK
 */
uint32_t virt_guest_destroyed(uint16_t guest_id);

/**
 * virt_set_guest() - set guest VM context for current core
 * @guest_id: VM id provided by hypervisor
 *
 * This function switches memory partitions, so TEE part of
 * OP-TEE will see memory associated with current guest.
 * It should be called on entry to OP-TEE
 *
 * Return: True if VM partition was found and set
 */
bool virt_set_guest(uint16_t guest_id);

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
 */
void virt_init_memory(struct tee_mmap_region *memory_map);

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

#endif	/* KERNEL_VIRTUALIZATION_H */
