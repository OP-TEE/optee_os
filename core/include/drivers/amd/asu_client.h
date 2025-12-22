/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 - 2025 Advanced Micro Devices, Inc. All Rights Reserved.
 *
 */

#ifndef __ASU_CLIENT_H_
#define __ASU_CLIENT_H_

#include <drivers/amd/asu_sharedmem.h>
#include <tee_api_types.h>
#include <util.h>

#define ASU_PRIORITY_LOW		1
#define ASU_PRIORITY_HIGH		0
#define ASU_MODULE_SHA2_ID		1U
#define ASU_MODULE_SHA3_ID		2U

struct asu_client_params {
	TEE_Result (*cbhandler)(void *cbrefptr, struct asu_resp_buf *resp);
	void *cbptr;
	uint8_t priority;
};

static inline uint8_t asu_get_unique_id(uint32_t header)
{
	return (uint8_t)((header & ASU_UNIQUE_REQ_ID_MASK) >>
			 ASU_UNIQUE_REQ_ID_SHIFT);
}

static inline uint32_t asu_create_header(uint8_t cmd_id,
					 uint8_t unique_id,
					 uint8_t module_id,
					 uint8_t command_len)
{
	uint32_t header = 0;

	header = (cmd_id & ASU_COMMAND_ID_MASK) |
		 SHIFT_U32(unique_id, ASU_UNIQUE_REQ_ID_SHIFT) |
		 SHIFT_U32(module_id, ASU_MODULE_ID_SHIFT) |
		 SHIFT_U32(command_len, ASU_COMMAND_LENGTH_SHIFT);

	return header;
}

TEE_Result asu_validate_client_parameters(struct asu_client_params *param_ptr);
TEE_Result asu_update_queue_buffer_n_send_ipi(struct asu_client_params *param,
					      void *req_buffer,
					      uint32_t size,
					      uint32_t header,
					      int *status);
uint8_t asu_reg_callback_n_get_unique_id(struct asu_client_params *param,
					 uint8_t *resp_buffer_ptr,
					 uint32_t size);
void asu_update_callback_details(uint8_t unique_id,
				 uint8_t *resp_buffer_ptr,
				 uint32_t size);
uint8_t asu_alloc_unique_id(void);
void asu_free_unique_id(uint8_t uniqueid);
void *asu_update_n_get_ctx(uint8_t unique_id);
TEE_Result asu_verify_n_get_unique_id_ctx(const void *context,
					  uint8_t *unique_id);
#endif /* __ASU_CLIENT_H_ */
