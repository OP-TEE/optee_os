/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Crypto Engine BAM transport interface.
 */
#ifndef QCOM_GPCE_CE_BAM_H
#define QCOM_GPCE_CE_BAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

struct ce_sha_ctx;

/* Descriptor FIFO capacity in bytes. */
#define QCE_BAM_DESC_SIZE		U(304)
/* Size of a BAM descriptor FIFO entry in bytes. */
#define QCE_BAM_DESC_ENTRY_SIZE	U(8)
/* Maximum payload represented by one BAM descriptor. */
#define QCE_BAM_MAX_XFER_SIZE		(U(64) * U(1024) - U(64))
/* Max payload after reserving six FIFO entries for CE command descriptors. */
#define QCE_BAM_MAX_DATA_SIZE		\
	(QCE_BAM_MAX_XFER_SIZE * \
	 ((QCE_BAM_DESC_SIZE / QCE_BAM_DESC_ENTRY_SIZE) - U(6)))

/*
 * ce_bam_init() - Initialize the global BAM state
 * Return: TEE_SUCCESS on success or an error code on failure.
 */
TEE_Result ce_bam_init(void);

/*
 * ce_bam_set_ce_ctx() - Prepare BAM commands for a CE hash transfer
 * @sha_ctx: SHA operation state
 * @auth_sz: Number of authentication bytes in the transfer
 * @seg_sz: Number of bytes in the CE segment
 * @first: True for the first hash segment
 * @last: True for the final hash segment
 *
 * Return: TEE_SUCCESS on success or an error code on failure.
 */
TEE_Result ce_bam_set_ce_ctx(struct ce_sha_ctx *sha_ctx, size_t auth_sz,
			     size_t seg_sz, bool first, bool last);

/*
 * ce_bam_xfer_data() - Queue input data on the BAM transmit pipe
 * @ibuf: Input buffer, or NULL when @isz is zero
 * @isz: Number of input bytes to transfer
 *
 * Return: TEE_SUCCESS on success or an error code on failure.
 */
TEE_Result ce_bam_xfer_data(const uint8_t *ibuf, size_t isz);

/*
 * ce_bam_get_xfer_size() - Get the largest DMA-safe payload prefix
 * @ibuf: Input buffer
 * @isz: Number of input bytes available at @ibuf
 * @xfer_sz: Returned size that fits the BAM descriptor FIFO
 *
 * The returned prefix is represented by descriptors whose physical ranges are
 * contiguous. It is bounded by the BAM descriptor FIFO capacity.
 *
 * Return: TEE_SUCCESS on success or an error code on failure.
 */
TEE_Result ce_bam_get_xfer_size(const uint8_t *ibuf, size_t isz,
				size_t *xfer_sz);

/*
 * ce_bam_get_ce_ctx() - Complete a transfer and save CE hash state
 * @sha_ctx: SHA operation state
 *
 * Return: TEE_SUCCESS on success or an error code on failure.
 */
TEE_Result ce_bam_get_ce_ctx(struct ce_sha_ctx *sha_ctx);

#endif /* QCOM_GPCE_CE_BAM_H */
