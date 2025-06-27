// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2025 Marvell.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "ehsm.h"
#include "ehsm-hal.h"
#include "ehsm-security.h"

/** Offset to mailbox registers */
static const uintptr_t ehsm_mailbox_offsets[EHSM_NUM_MAILBOXES] = {
	EHSM_INPUT_ARG0,
	EHSM_CORE2_INPUT_ARG0
};

static const uintptr_t ehsm_host_int_registers[EHSM_NUM_MAILBOXES] = {
	EHSM_CORE1_HOST_INT_RST_REG,
	EHSM_CORE2_HOST_INT_RST_REG
};

static const uint32_t
ehsm_cmd_fifo_status_read_done_mask[EHSM_NUM_MAILBOXES] = {
	EHSM_CMD_FIFO_STATUS_CORE1_CMD_STATUS_READ_DONE,
	EHSM_CMD_FIFO_STATUS_CORE2_CMD_STATUS_READ_DONE,
};

static const uintptr_t ehsm_cmd_ret_status_registers[EHSM_NUM_MAILBOXES] = {
	EHSM_CMD_RET_STATUS,
	EHSM_CORE2_CMD_RET_STATUS
};

static const uint32_t
ehsm_cmd_fifo_status_buffer_full_mask[EHSM_NUM_MAILBOXES] = {
	EHSM_CMD_FIFO_STATUS_CORE1_CMD_STATUS_BUFFER_FULL,
	EHSM_CMD_FIFO_STATUS_CORE2_CMD_STATUS_BUFFER_FULL
};

/**
 * Initializes the handle and prepares the eHSM for access
 *
 * @param[out]  handle  pointer to handle
 * @param       mailbox number to use
 *
 * @return      status
 */
int ehsm_initialize2(struct ehsm_handle *handle, unsigned int mailbox)
{
	ehsm_debug("%s(%p, %u)\n", __func__, handle, mailbox);
	memset(handle, 0, sizeof(*handle));
	ehsm_debug("Preparing CSR access\n");
	if (mailbox >= EHSM_NUM_MAILBOXES) {
		ehsm_debug("%s: Error: mailbox %u out of range 0..%u\n",
			   __func__, mailbox, EHSM_NUM_MAILBOXES - 1);
		return SEC_INVALID_MAILBOX;
	}
	handle->mailbox_offset = ehsm_mailbox_offsets[mailbox];
	handle->cmd_mailbox =
	(struct ehsm_command *)((void *)(handle->mailbox_offset));

	handle->host_int_reg = ehsm_host_int_registers[mailbox];
	handle->core_cmd_status_read_done_mask =
	ehsm_cmd_fifo_status_read_done_mask[mailbox];
	handle->core_cmd_buffer_full_mask =
	ehsm_cmd_fifo_status_buffer_full_mask[mailbox];
	handle->cmd_ret_status_reg =
	ehsm_cmd_ret_status_registers[mailbox];
	handle->mailbox = mailbox;

	ehsm_prepare_csr_access(handle);

	/* Make sure to disable interrupts */
	ehsm_write_csr(handle, handle->host_int_reg,
		       ehsm_read_csr(handle, handle->host_int_reg) |
		       EHSM_CMD_CPL_STS_BIT);
	handle->initialized = TRUE;

	return SEC_NO_ERROR;
}

/**
 * Initializes the handle and prepares the eHSM for access
 *
 * @param[out]  handle  pointer to handle
 *
 * @return      status
 */
int ehsm_initialize(struct ehsm_handle *handle)
{
	ehsm_debug("%s(%p)\n", __func__, handle);
	return ehsm_initialize2(handle, 0);
}

/**
 * Send a command to the eHSM and wait for a response
 *
 * @param       handle  pointer to eHSM handle
 * @param       cmd     pointer to command data structure
 *
 * @return      Return status of command from the hardware
 */
enum ehsm_status ehsm_command(struct ehsm_handle *handle,
			      struct ehsm_command *cmd)
{
	struct ehsm_command *hcmd = handle->cmd_mailbox;
	uint32_t int_status;
	uint32_t fifo_status;
	unsigned int i;

	ehsm_debug("%s: opcode: %u\n", __func__, cmd->opcode);

	if (!handle->ehsm_ready) {
		while (!(ehsm_read_csr(handle, EHSM_CMD_FIFO_STATUS) &
			 EHSM_CMD_FIFO_STATUS_READY))
			;
	ehsm_write_csr(handle, handle->host_int_reg,
		       ehsm_read_csr(handle, handle->host_int_reg) |
		       EHSM_CMD_CPL_STS_BIT);
	handle->ehsm_ready = TRUE;
	}

	/* Wait for command fifo to empty */
	do {
		fifo_status = ehsm_read_csr(handle, EHSM_CMD_FIFO_STATUS);
	} while (fifo_status & handle->core_cmd_buffer_full_mask);

	for (i = 0; i < EHSM_NUM_ARGS; i++)
		ehsm_write_csr(handle, ehsm_ptr_to_reg(&hcmd->args[i]),
			       cmd->args[i]);

	ehsm_write_csr(handle,
		       ehsm_ptr_to_reg(&hcmd->opcode),
		       cmd->opcode);

	do {
		int_status = ehsm_read_csr(handle, handle->host_int_reg);
	} while (!(int_status & EHSM_CMD_CPL_STS_BIT));

	ehsm_write_csr(handle, handle->host_int_reg,
		       int_status | EHSM_CMD_CPL_STS_BIT);

	/* Get status */
	cmd->ret_status = ehsm_read_csr(handle, handle->cmd_ret_status_reg);
	for (i = 0; i < EHSM_NUM_ARGS; i++)
		cmd->ret_parameters[i] = ehsm_read_csr(handle,
						       ehsm_ptr_to_reg(&hcmd
						       ->ret_parameters[i]));

	ehsm_debug("%s: Return status: %" PRIu32 "\n", __func__,
		   cmd->ret_status);
	handle->last_ehsm_status = cmd->ret_status;
	return (enum ehsm_status)cmd->ret_status;
}

/**
 * clear a command to the eHSM
 *
 * @param	cmd	pointer to command data structure
 *
 */
void ehsm_clear_command(struct ehsm_command *cmd)
{
	int i;

	for (i = 0; i < EHSM_NUM_ARGS; i++) {
		cmd->args[i] = 0;
		cmd->ret_parameters[i] = 0;
	}
	cmd->opcode = 0;
	cmd->ret_status = 0;
}
