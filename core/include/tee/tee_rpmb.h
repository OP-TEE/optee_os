/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef TEE_RPMB_H
#define TEE_RPMB_H

#include "tee_api_types.h"

/*
 * Generate RPMB key and write to eMMC.
 *
 * @dev_id      Device ID of the eMMC device.
 * @commercial  Flag indicating if we should write
 *              commercial key which is bound to
 *              the hard unique key.
 */
TEE_Result tee_rpmb_write_key(uint16_t dev_id, bool commercial);

/*
 * Read RPMB data in bytes.
 *
 * @dev_id     Device ID of the eMMC device.
 * @addr       Byte address of data.
 * @data       Pointer to the data.
 * @len        Size of data in bytes.
 */
TEE_Result tee_rpmb_read(uint16_t dev_id,
			 uint32_t addr, uint8_t *data, uint32_t len);

/*
 * Write RPMB data in bytes.
 *
 * @dev_id     Device ID of the eMMC device.
 * @addr       Byte address of data.
 * @data       Pointer to the data.
 * @len        Size of data in bytes.
 */
TEE_Result tee_rpmb_write(uint16_t dev_id,
			  uint32_t addr, uint8_t *data, uint32_t len);

/*
 * Read the RPMB write counter.
 *
 * @dev_id     Device ID of the eMMC device.
 * @counter    Pointer to the counter.
 */
TEE_Result tee_rpmb_get_write_counter(uint16_t dev_id, uint32_t *counter);

/*
 * Read the RPMB max block.
 *
 * @dev_id     Device ID of the eMMC device.
 * @counter    Pointer to receive the max block.
 */
TEE_Result tee_rpmb_get_max_block(uint16_t dev_id, uint32_t *max_block);

#endif
