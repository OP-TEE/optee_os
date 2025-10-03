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
static const size_t ehsm_mailbox_offsets[EHSM_NUM_MAILBOXES] = {
	EHSM_INPUT_ARG0,
	EHSM_CORE1_INPUT_ARG0,
	EHSM_CORE2_INPUT_ARG0,
};

static const size_t ehsm_host_int_reg[EHSM_NUM_MAILBOXES] = {
	EHSM_CORE0_HOST_INT_RST_REG,
	EHSM_CORE1_HOST_INT_RST_REG,
	EHSM_CORE2_HOST_INT_RST_REG,
};

static const size_t ehsm_cmd_status_reg[EHSM_NUM_MAILBOXES] = {
	EHSM_CMD_RET_STATUS,
	EHSM_CORE1_CMD_RET_STATUS,
	EHSM_CORE2_CMD_RET_STATUS,
};

static const uint32_t
ehsm_cmd_fifo_status_buf_full_mask[EHSM_NUM_MAILBOXES] = {
	EHSM_CMD_FIFO_STATUS_CORE0_CMD_STATUS_BUFFER_FULL,
	EHSM_CMD_FIFO_STATUS_CORE1_CMD_STATUS_BUFFER_FULL,
	EHSM_CMD_FIFO_STATUS_CORE2_CMD_STATUS_BUFFER_FULL,
};

int ehsm_initialize(struct ehsm_handle *handle, unsigned int mbox)
{
	ehsm_debug("%s(%p, %u)\n", __func__, handle, mbox);
	memset(handle, 0, sizeof(*handle));
	ehsm_debug("Preparing CSR access\n");

	if (mbox >= EHSM_NUM_MAILBOXES) {
		ehsm_printf("%s: Error: mailbox %u out of range 0..%u\n",
			    __func__, mbox, EHSM_NUM_MAILBOXES - 1);
		return SEC_INVALID_MAILBOX;
	}
	handle->mbox_offset = ehsm_mailbox_offsets[mbox];
	handle->ehsm_cmd = (struct ehsm_command *)(handle->mbox_offset);

	handle->host_int_reg = ehsm_host_int_reg[mbox];
	handle->cmd_buf_full_mask = ehsm_cmd_fifo_status_buf_full_mask[mbox];
	handle->cmd_status_reg = ehsm_cmd_status_reg[mbox];

	handle->mbox = mbox;
	ehsm_prepare_csr_access(handle);

	/* Make sure to disable interrupts */
	ehsm_write_csr(handle, handle->host_int_reg,
		       ehsm_read_csr(handle, handle->host_int_reg) |
		       EHSM_CMD_CPL_STS_BIT);

	handle->initialized = TRUE;

	return SEC_NO_ERROR;
}

enum ehsm_status ehsm_command(struct ehsm_handle *handle,
			      struct ehsm_command *cmd)
{
	struct ehsm_command *hcmd = handle->ehsm_cmd;
	uint32_t int_status = 0;
	uint32_t fifo_status = 0;
	uint32_t rparam = 0;
	unsigned int i = 0;

#if DEBUG_EHSM
	ehsm_debug("%s: opcode: %u\n", __func__, cmd->opcode);
	for (i = 0; i < EHSM_NUM_ARGS; i++)
		ehsm_debug("arg[%d]: 0x%x\n", i, cmd->args[i]);
#endif

	if (!handle->ehsm_ready) {
		while (!(ehsm_read_csr(handle, EHSM_CMD_FIFO_STATUS) &
			 EHSM_CMD_FIFO_STATUS_READY))
			;

		int_status = ehsm_read_csr(handle, handle->host_int_reg);
		ehsm_write_csr(handle, handle->host_int_reg,
			       int_status | EHSM_CMD_CPL_STS_BIT);

		handle->ehsm_ready = TRUE;
	}

	/* Wait for command fifo to empty */
	do {
		fifo_status = ehsm_read_csr(handle, EHSM_CMD_FIFO_STATUS);
	} while (fifo_status & handle->cmd_buf_full_mask);

	for (i = 0; i < EHSM_NUM_ARGS; i++)
		ehsm_write_csr(handle, ehsm_ptr_to_reg(&hcmd->args[i]),
			       cmd->args[i]);

	ehsm_write_csr(handle, ehsm_ptr_to_reg(&hcmd->opcode), cmd->opcode);

	do {
		int_status = ehsm_read_csr(handle, handle->host_int_reg);
	} while (!(int_status & EHSM_CMD_CPL_STS_BIT));

	ehsm_write_csr(handle, handle->host_int_reg,
		       int_status | EHSM_CMD_CPL_STS_BIT);

	/* Get status */
	cmd->ret_status = ehsm_read_csr(handle, handle->cmd_status_reg);
	for (i = 0; i < EHSM_NUM_ARGS; i++) {
		rparam = ehsm_read_csr(handle,
				       ehsm_ptr_to_reg(&hcmd->ret_params[i]));
		cmd->ret_params[i] = rparam;
	}

#if DEBUG_EHSM
	ehsm_debug("%s: Return status: 0x%x\n", __func__, cmd->ret_status);

	for (i = 0; i < EHSM_NUM_ARGS; i++)
		ehsm_debug("ret_params[%u]: 0x%x\n", i, cmd->ret_params[i]);
#endif

	handle->last_ehsm_status = cmd->ret_status;
	return (enum ehsm_status)cmd->ret_status;
}

void ehsm_clear_command(struct ehsm_command *cmd)
{
	int i = 0;

	for (i = 0; i < EHSM_NUM_ARGS; i++) {
		cmd->args[i] = 0;
		cmd->ret_params[i] = 0;
	}
	cmd->opcode = 0;
	cmd->ret_status = 0;
}
