// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#include <assert.h>
#include <drivers/amd/asu_client.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <mm/core_mmu.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "asu_doorbell.h"

#define ASU_QUEUE_BUFFER_FULL		0xFFU
#define ASU_CLIENT_READY		0xFFFFFFFFU
#define ASU_TARGET_IPI_INT_MASK		1U

#define ASU_BASEADDR			0xEBF80000U
#define ASU_GLOBAL_CNTRL		(ASU_BASEADDR + 0x00000000U)

#define ASU_BASEADDR_SIZE		0x10000U
#define ASU_GLOBAL_ADDR_LIMIT		0x1000U

#define ASU_GLOBAL_CNTRL_FW_IS_PRESENT_MASK	0x10U
#define ASU_ASUFW_BIT_CHECK_TIMEOUT_VALUE	0xFFFFFU

#define ASU_CHNL_IPI_BITMASK		GENMASK_32(31, 16)

struct asu_client {
	struct asu_channel_memory *chnl_memptr;
	uint32_t is_ready;
	unsigned int slock;          /* chnl_memptr spin lock */
	void *global_ctrl;
	void *doorbell;
};

struct asu_ids {
	uint8_t ids[ASU_UNIQUE_ID_MAX];
	unsigned int slock;          /* id array spin lock */
};

static struct asu_ids asuid;
static struct asu_client *asu;

/*
 * asu_fwcheck() - Check if ASU firmware is present and ready
 * Polls the ASU global control register to verify if the HSM firmware
 * is present and ready for interaction. Uses a timeout of approximately
 * 1 second for the check.
 *
 * Return: TEE_SUCCESS if firmware is ready, TEE_ERROR_BAD_STATE if not present
 */
static TEE_Result asu_fwcheck(void)
{
	uint64_t timeout = 0;

	/*
	 * Timeout is set to ~1sec.
	 * This is the worst case time within which ASUFW ready for interaction
	 * with components requests.
	 */
	timeout = timeout_init_us(ASU_ASUFW_BIT_CHECK_TIMEOUT_VALUE);

	do {
		if (io_read32((vaddr_t)asu->global_ctrl) &
		    ASU_GLOBAL_CNTRL_FW_IS_PRESENT_MASK) {
			DMSG("ASU FW is ready!");
			return TEE_SUCCESS;
		}
	} while (!timeout_elapsed(timeout));

	EMSG("ASU FW is not present!");

	return TEE_ERROR_BAD_STATE;
}

/*
 * asu_get_channelID() - Determine the ASU channel ID for APU communication
 *
 * Maps the Runtime Configuration Area (RTCA) to find which ASU channel
 * should be used by the APU for communication. Searches through available
 * channels to find one matching the APU's local IPI ID.
 *
 * Return: Channel ID (0 to ASU_MAX_IPI_CHANNELS-1) or ASU_MAX_IPI_CHANNELS on
 *	   failure
 */
static uint32_t asu_get_channelID(void)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	void *comm_chnl_info = NULL;
	uint32_t channel_id = ASU_MAX_IPI_CHANNELS;
	vaddr_t membase = 0;
	uint32_t id = 0;

	/*
	 * RTCA is mapped only to find the ASU Channel ID
	 * to be used by APU.
	 * After reading the information RTCA region is unmapped.
	 */
	comm_chnl_info = core_mmu_add_mapping(MEM_AREA_IO_SEC,
					      ASU_RTCA_BASEADDR,
					      ASU_GLOBAL_ADDR_LIMIT);
	if (!comm_chnl_info) {
		EMSG("Failed to map runtime config area");
		return channel_id;
	}

	for (id = 0; id < ASU_MAX_IPI_CHANNELS; id++) {
		membase = (vaddr_t)comm_chnl_info +
			  ASU_RTCA_CHANNEL_BASE_OFFSET +
			  ASU_RTCA_CHANNEL_INFO_LEN * id;
		if ((io_read32(membase) & ASU_CHNL_IPI_BITMASK) ==
		    (CFG_AMD_APU_LCL_IPI_ID << 16)) {
			channel_id = id;
			DMSG("Use ASU channel ID %"PRIu32, channel_id);
			break;
		}
	}

	if (channel_id == ASU_MAX_IPI_CHANNELS)
		EMSG("Failed to identify ASU channel ID for APU");

	ret = core_mmu_remove_mapping(MEM_AREA_IO_SEC,
				      comm_chnl_info, ASU_GLOBAL_ADDR_LIMIT);
	if (ret)
		EMSG("Failed to unmap RTCA");

	return channel_id;
}

/*
 * asu_alloc_unique_id() - Generate a unique identifier for ASU operations
 *
 * Creates a unique ID by cycling through available IDs in the callback
 * reference array. Ensures no ID collision by checking if the slot is
 * already in use.
 *
 * Return: Unique ID (1 to ASU_UNIQUE_ID_MAX-1) or ASU_UNIQUE_ID_MAX if none
 *	   available
 */
uint8_t asu_alloc_unique_id(void)
{
	uint8_t unqid = 0;
	uint32_t state = 0;

	state = cpu_spin_lock_xsave(&asuid.slock);
	while (unqid < ASU_UNIQUE_ID_MAX) {
		if (asuid.ids[unqid] == ASU_UNIQUE_ID_MAX) {
			asuid.ids[unqid] = unqid;
			DMSG("Got unique ID %"PRIu8, unqid);
			break;
		}
		unqid++;
	};
	cpu_spin_unlock_xrestore(&asuid.slock, state);

	return unqid;
}

/**
 * asu_free_unique_id() - Release a previously allocated unique ID
 * @uniqueid: The unique ID to be freed
 *
 * Marks the specified unique ID as available for reuse.
 * The released ID is set to ASU_UNIQUE_ID_MAX
 * to indicate its availability. Intended to be used in environments where
 * concurrent access to the unique ID pool occurs.
 */
void asu_free_unique_id(uint8_t uniqueid)
{
	uint32_t state = 0;

	state = cpu_spin_lock_xsave(&asuid.slock);
	asuid.ids[uniqueid] = ASU_UNIQUE_ID_MAX;
	cpu_spin_unlock_xrestore(&asuid.slock, state);
}

/*
 * get_free_index() - Find a free buffer index in the specified priority queue
 * @priority: Priority level (ASU_PRIORITY_HIGH or ASU_PRIORITY_LOW)
 *
 * Searches for an available buffer slot in either the high priority (P0) or
 * low priority (P1) channel queue. Updates the next free index pointer.
 *
 * Return: Buffer index (0 to ASU_MAX_BUFFERS-1) or ASU_MAX_BUFFERS if queue
 *	   is full
 */
static uint8_t get_free_index(uint8_t priority)
{
	struct asu_channel_queue *qptr = NULL;
	uint8_t index = 0;
	uint32_t state = 0;

	state = cpu_spin_lock_xsave(&asu->slock);

	if (priority == ASU_PRIORITY_HIGH)
		qptr = &asu->chnl_memptr->p0_chnl_q;
	else
		qptr = &asu->chnl_memptr->p1_chnl_q;

	while (index < ASU_MAX_BUFFERS) {
		if (qptr->queue_bufs[index].reqbufstatus == 0U ||
		    qptr->queue_bufs[index].respbufstatus == 0U)
			break;

		index++;
	}

	if (index < ASU_MAX_BUFFERS)
		qptr->queue_bufs[index].reqbufstatus = ASU_COMMAND_IS_PRESENT;

	cpu_spin_unlock_xrestore(&asu->slock, state);

	return index;
}

static void put_free_index(struct asu_channel_queue_buf *bufptr)
{
	uint32_t state = 0;

	state = cpu_spin_lock_xsave(&asu->slock);
	bufptr->reqbufstatus = 0;
	bufptr->respbufstatus = 0;
	cpu_spin_unlock_xrestore(&asu->slock, state);
}

/*
 * send_doorbell() - Send IPI doorbell interrupt to ASU
 *
 * Triggers an Inter-Processor Interrupt (IPI) to notify the ASU
 * that a new command is available in the shared memory queue.
 *
 * Return: TEE_SUCCESS on successful doorbell trigger
 */
static TEE_Result send_doorbell(void)
{
	io_write32((vaddr_t)asu->doorbell + IPIPSU_TRIG_OFFSET,
		   ASU_TARGET_IPI_INT_MASK);

	return TEE_SUCCESS;
}

/*
 * asu_update_queue_buffer_n_send_ipi() - Queue command and send IPI
 * @param: Client parameters including priority
 * @req_buffer: Request buffer containing command data
 * @size: Size of request data
 * @header: Command header information
 * @status: FW return status
 *
 * Places a command in the appropriate priority queue buffer, updates
 * queue status, and sends an IPI to notify ASU of the pending command.
 *
 * Return: TEE_SUCCESS on success, appropriate error code on failure
 */
TEE_Result asu_update_queue_buffer_n_send_ipi(struct asu_client_params *param,
					      void *req_buffer,
					      uint32_t size,
					      uint32_t header,
					      uint32_t *status)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint8_t freeindex = 0;
	struct asu_channel_queue_buf *bufptr = NULL;
	struct asu_channel_queue *qptr = NULL;

	if (!param || header == 0U) {
		EMSG("Invalid parameters provided");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (asu->is_ready != ASU_CLIENT_READY) {
		EMSG("ASU client is not ready");
		return TEE_ERROR_BAD_STATE;
	}

	freeindex = get_free_index(param->priority);
	if (freeindex == ASU_MAX_BUFFERS) {
		EMSG("ASU buffers full");
		return TEE_ERROR_SHORT_BUFFER;
	}

	if (param->priority == ASU_PRIORITY_HIGH) {
		bufptr = &asu->chnl_memptr->p0_chnl_q.queue_bufs[freeindex];
		qptr = &asu->chnl_memptr->p0_chnl_q;
	} else {
		bufptr = &asu->chnl_memptr->p1_chnl_q.queue_bufs[freeindex];
		qptr = &asu->chnl_memptr->p1_chnl_q;
	}

	bufptr->req.header = header;
	if (req_buffer && size != 0U)
		memcpy(bufptr->req.arg, req_buffer, size);

	bufptr->respbufstatus = 0;

	qptr->cmd_is_present = true;
	qptr->req_sent++;
	ret = send_doorbell();
	if (ret != TEE_SUCCESS) {
		EMSG("Failed to communicate to ASU");
		return TEE_ERROR_COMMUNICATION;
	}
	while (io_read8((vaddr_t)&bufptr->respbufstatus) !=
	       ASU_RESPONSE_IS_PRESENT) {
		/*
		 * WFE will return on SEV generated by the
		 * interrupt handler or by a spin_unlock
		 */
		wfe();
	}

	*status = bufptr->resp.arg[ASU_RESPONSE_STATUS_INDEX];
	if (param->cbhandler && !*status)
		ret = param->cbhandler(param->cbptr, &bufptr->resp);
	put_free_index(bufptr);

	return ret;
}

static void asu_clear_intr(void)
{
	uint32_t status = 0;

	status = io_read32((vaddr_t)asu->doorbell + IPIPSU_ISR_OFFSET);
	io_write32((vaddr_t)asu->doorbell + IPIPSU_ISR_OFFSET,
		   status & IPIPSU_ALL_MASK);
}

/*
 * asu_resp_handler() - Interrupt handler for ASU responses
 * @handler: Interrupt handler structure (unused)
 *
 * Interrupt service routine that processes responses from both high
 * priority (P0) and low priority (P1) queues when ASU completes
 * command processing.
 *
 * Return: ITRR_HANDLED indicating interrupt was handled
 */
static enum itr_return asu_resp_handler(struct itr_handler *handler __unused)
{
	sev();
	asu_clear_intr();

	return ITRR_HANDLED;
}

static struct itr_handler doorbell_handler = {
	.it = PAR_IPIPSU_0_INT_ID,
	.handler = asu_resp_handler,
};

/*
 * setup_doorbell() - Initialize doorbell interrupt handling
 *
 * Maps the doorbell register region, configures interrupt settings,
 * registers the interrupt handler, and enables the interrupt for
 * receiving ASU response notifications.
 *
 * Return: Pointer to mapped doorbell region or NULL on failure
 */
static void *setup_doorbell(void)
{
	void *dbell = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	dbell = core_mmu_add_mapping(MEM_AREA_IO_SEC,
				     asu_configtable.baseaddr,
				     ASU_BASEADDR_SIZE);
	if (!dbell) {
		EMSG("Failed to map doorbell register");
		return dbell;
	}

	io_write32((vaddr_t)dbell + IPIPSU_IER_OFFSET, IPIPSU_ALL_MASK);
	io_write32((vaddr_t)dbell + IPIPSU_ISR_OFFSET, IPIPSU_ALL_MASK);

	doorbell_handler.chip = interrupt_get_main_chip();

	res = interrupt_add_configure_handler(&doorbell_handler,
					      IRQ_TYPE_LEVEL_HIGH, 7);
	if (res)
		panic();

	interrupt_enable(doorbell_handler.chip, doorbell_handler.it);

	return dbell;
}

static void asu_init_unique_id(void)
{
	uint32_t idx = 0;

	asuid.slock = SPINLOCK_UNLOCK;
	for (idx = 0; idx < ARRAY_SIZE(asuid.ids); idx++)
		asuid.ids[idx] = ASU_UNIQUE_ID_MAX;
}

/*
 * asu_init() - Initialize the ASU driver and communication channel
 *
 * Performs complete ASU driver initialization including memory allocation,
 * firmware readiness check, channel ID discovery, shared memory mapping,
 * doorbell setup, and marking the client as ready for operation.
 *
 * Return: TEE_SUCCESS on successful initialization, appropriate error code on
 *	   failure
 */
static TEE_Result asu_init(void)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint32_t channel_id = 0;
	void *asu_shmem = NULL;
	uint64_t membase = 0;

	asu = calloc(1, sizeof(struct asu_client));
	if (!asu) {
		EMSG("Failed to allocate memory for ASU");
		return ret;
	}

	asu->global_ctrl = core_mmu_add_mapping(MEM_AREA_IO_SEC,
						ASU_BASEADDR,
						ASU_BASEADDR_SIZE);
	if (!asu->global_ctrl) {
		EMSG("Failed to initialize ASU");
		goto free;
	}

	if (asu_fwcheck() != TEE_SUCCESS) {
		EMSG("ASU FW check failed");
		goto global_unmap;
	}

	channel_id = asu_get_channelID();

	if (channel_id == ASU_MAX_IPI_CHANNELS) {
		EMSG("ASU channel for APU not configured");
		goto global_unmap;
	}

	membase = ASU_CHANNEL_MEMORY_BASEADDR +
			ASU_GLOBAL_ADDR_LIMIT * channel_id;
	asu_shmem = core_mmu_add_mapping(MEM_AREA_IO_SEC,
					 membase,
					 ASU_GLOBAL_ADDR_LIMIT);
	if (!asu_shmem) {
		EMSG("Failed to map ASU SHM");
		goto global_unmap;
	}
	asu_init_unique_id();
	asu->doorbell = setup_doorbell();
	if (!asu->doorbell) {
		EMSG("Failed to set up ASU doorbell");
		goto sh_unmap;
	}

	asu->chnl_memptr = asu_shmem;
	asu->is_ready = ASU_CLIENT_READY;
	asu->slock = SPINLOCK_UNLOCK;

	IMSG("ASU initialization complete");

	return TEE_SUCCESS;

sh_unmap:
	core_mmu_remove_mapping(MEM_AREA_IO_SEC, asu_shmem,
				ASU_GLOBAL_ADDR_LIMIT);
global_unmap:
	core_mmu_remove_mapping(MEM_AREA_IO_SEC, asu->global_ctrl,
				ASU_BASEADDR_SIZE);
free:
	free(asu);

	EMSG("Failed to initialize ASU");

	return TEE_ERROR_GENERIC;
}

service_init(asu_init);
