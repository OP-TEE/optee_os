/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 Microsoft
 *
 * Definitions for the Broadcom BNXT Nitro hot patch driver.
 */

#ifndef NITRO_HOT_PATCH_H
#define NITRO_HOT_PATCH_H

#include <mm/core_memprot.h>
#include <stdint.h>
#include <tee_api_types.h>

/**
 * nitro_hot_patch_init() - Initialize the staging memory location to hold the
 *			    nitro hot patch until it gets verified and flashed.
 * @paddr:	Physical address of the hot patch staging area.
 * @size:	Size of the hot patch staging area.
 *
 * Return:	TEE_SUCCESS or > 0 on error.
 */
TEE_Result nitro_hot_patch_init(paddr_t paddr, uint32_t size);

/**
 * nitro_hot_patch_deinit() - Resets the driver by setting the staging address
 *			      to NULL.
 *
 * Return:	TEE_SUCCESS.
 */
TEE_Result nitro_hot_patch_deinit(void);

/**
 * update_nitro_hot_patch() - Add data from a given buffer to the nitro hot
 *			      patch staging area.
 * @buffer:	Pointer to the data to copy.
 * @size:	Size of incoming data patch.
 *
 * This function can be called more than once as long as the total size of the
 * hot patch does not exceed the staging memory size set during initialization.
 *
 * Return:	TEE_SUCCESS or > 0 on error.
 */
TEE_Result update_nitro_hot_patch(void *buffer, uint32_t size);

/**
 * verify_nitro_hot_patch() - Verify the nitro hot patch in staging memory and
 *			      update a given pointer with the hot patch address
 *			      if the hot patch has been initialized and has a
 *			      total size of > 0.
 * @staging_mem:	Pointer to potentially return the hot patch info
 *			address with.
 *
 * Return:		TEE_SUCCESS or > 0 on error.
 */
TEE_Result verify_nitro_hot_patch(vaddr_t *staging_mem);

#endif
