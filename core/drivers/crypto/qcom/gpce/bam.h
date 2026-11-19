/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Low-level Qualcomm BAM interface used by GPCE.
 */
#ifndef QCOM_GPCE_BAM_H
#define QCOM_GPCE_BAM_H

#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>

/* Size of one BAM descriptor FIFO entry in bytes. */
#define BAM_DESC_ENTRY_SIZE	U(8)
/* Size of a BAM descriptor FIFO used by GPCE, in bytes. */
#define BAM_DESC_FIFO_SIZE	U(304)
/* Maximum payload represented by one BAM descriptor. */
#define BAM_MAX_XFER_SIZE	(U(64) * U(1024) - U(64))
/* Fixed upper bound for BAM completion polling. */
#define BAM_POLL_MAX		U(100000)

/* Opaque software state for one BAM pipe. */
struct bam_pipe_state;

/*
 * struct bam_config - BAM controller configuration supplied by its client
 * @base: Virtual base address of the mapped BAM registers
 * @pa: Physical base address of the BAM registers
 * @ee: Execution environment that owns the supplied BAM pipes
 */
struct bam_config {
	vaddr_t base;
	paddr_t pa;
	uint32_t ee;
};

/*
 * struct bam_pipe_config - BAM pipe configuration supplied by its client
 * @pipe_num: Hardware pipe number
 * @is_consumer: True when the pipe transfers data from CE to memory
 * @desc_base_va: Virtual address of the descriptor FIFO
 * @desc_base_pa: Physical address of the descriptor FIFO
 */
struct bam_pipe_config {
	uint32_t pipe_num;
	bool is_consumer;
	void *desc_base_va;
	paddr_t desc_base_pa;
};

/*
 * enum bam_iovec_options - BAM descriptor FIFO flags
 * @BAM_IOVEC_FLAG_INT: Request a descriptor-completion interrupt
 * @BAM_IOVEC_FLAG_EOT: Mark the descriptor as the end of a transfer
 * @BAM_IOVEC_FLAG_NWD: Notify when the descriptor has completed; data
 *		       descriptors before a command descriptor require this flag
 * @BAM_IOVEC_FLAG_CMD: Interpret the buffer as CE command descriptors
 * @BAM_IOVEC_FLAG_LCK: Lock BAM to this pipe's lock group
 * @BAM_IOVEC_FLAG_UNLCK: Release the BAM lock held by this pipe's group
 * @BAM_IOVEC_FLAG_IMM_CMD: Interpret the buffer as an immediate command
 * @BAM_IOVEC_FLAG_NO_SUBMIT: Keep the descriptor in the software FIFO for
 *			   later submission; this is not a hardware flag
 */
enum bam_iovec_options {
	BAM_IOVEC_FLAG_INT = 0x80,
	BAM_IOVEC_FLAG_EOT = 0x40,
	BAM_IOVEC_FLAG_NWD = 0x10,
	BAM_IOVEC_FLAG_CMD = 0x08,
	BAM_IOVEC_FLAG_LCK = 0x04,
	BAM_IOVEC_FLAG_UNLCK = 0x02,
	BAM_IOVEC_FLAG_IMM_CMD = 0x01,
	BAM_IOVEC_FLAG_NO_SUBMIT = 0x100,
};

/*
 * bam_init() - Initialize the BAM controller state
 * @config: BAM controller configuration
 *
 * Return: TEE_SUCCESS on success or an error code on failure.
 */
TEE_Result bam_init(const struct bam_config *config);

/*
 * bam_pipe_init() - Configure a BAM pipe and its descriptor FIFO
 * @config: BAM pipe configuration
 *
 * Return: Pipe handle on success or NULL on failure.
 */
struct bam_pipe_state *bam_pipe_init(const struct bam_pipe_config *config);

/*
 * bam_pipe_reinit() - Reset and reconfigure a BAM pipe using saved state
 * @pipe: Pipe handle returned by bam_pipe_init()
 *
 * Return: @pipe on success or NULL on failure.
 */
struct bam_pipe_state *bam_pipe_reinit(struct bam_pipe_state *pipe);

/*
 * bam_pipe_transfer() - Queue a descriptor on a BAM pipe
 * @pipe: Pipe handle returned by bam_pipe_init()
 * @pa: Buffer physical address
 * @size: Buffer size in bytes
 * @flags: ORed enum bam_iovec_options values
 *
 * Return: TEE_SUCCESS on success or an error code on failure.
 */
TEE_Result bam_pipe_transfer(struct bam_pipe_state *pipe, paddr_t pa,
			     uint64_t size, uint16_t flags);

/*
 * bam_pipe_poll() - Poll a pipe for its EOT descriptor
 * @pipe: Pipe handle returned by bam_pipe_init()
 *
 * Return: TEE_SUCCESS when EOT completes, TEE_ERROR_BUSY while pending, or an
 * error code.
 */
TEE_Result bam_pipe_poll(struct bam_pipe_state *pipe);

#endif /* QCOM_GPCE_BAM_H */
