/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, STMicroelectronics - All Rights Reserved
 */

#ifndef __DRIVERS_STM32_REMOTEPROC_H
#define __DRIVERS_STM32_REMOTEPROC_H

#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

/* IDs of the supported remote processors*/
#define STM32_M4_RPROC_ID 0

/*
 * stm32_rproc_get() - get the rproc handle associated to a remote processor ID
 * @rproc_id unique identifier of the remote processor
 * Return a pointer to the rproc firmware handle related to @rproc_id or NULL.
 */
void *stm32_rproc_get(uint32_t rproc_id);

/*
 * stm32_rproc_da_to_pa() - Convert the coprocessor device address to a CPU
 *                          physical address.
 * @rproc_id	unique identifier of the remote processor
 * @da		device memory address from the remote processor space
 *		perspective.
 * @size	size of the memory
 * @pa		Output CPU physical address associated to @da.
 * Return TEE_SUCCESS or appropriate error.
 */
TEE_Result stm32_rproc_da_to_pa(uint32_t rproc_id, paddr_t da, size_t size,
				paddr_t *pa);

/*
 * stm32_rproc_map() - map the physical address if valid
 * @rproc_id	unique identifier of the remote processor
 * @pa		physical address from the CPU space perspective
 * @size	size of the memory
 * @va		Output CPU virtual address associated to @pa.
 * Return TEE_SUCCESS or appropriate error.
 */
TEE_Result stm32_rproc_map(uint32_t rproc_id, paddr_t pa, size_t size,
			   void **va);

/*
 * stm32_rproc_unmap() - ummap the virtual address mapped with stm32_rproc_map
 * @rproc_id	unique identifier of the remote processor
 * @va		virtual address
 * @size	size of the memory
 * Return TEE_SUCCESS or appropriate error.
 */
TEE_Result stm32_rproc_unmap(uint32_t rproc_id, void *va, size_t size);

/*
 * stm32_rproc_start() - start the remote processor core
 * @rproc_id	unique identifier of the remote processor
 * Return TEE_SUCCESS or appropriate error.
 */
TEE_Result stm32_rproc_start(uint32_t rproc_id);

/*
 * stm32_rproc_stop() - stop the remote processor core
 * @rproc_id	unique identifier of the remote processor
 * Return TEE_SUCCESS or appropriate error.
 */
TEE_Result stm32_rproc_stop(uint32_t rproc_id);

#endif /* __DRIVERS_STM32_REMOTEPROC_H */
