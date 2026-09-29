/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 *
 * The defines in this file are based on
 * TCG PC Client Platform TPM Profile (PTP) Specification for
 * TPM 2.0 v1.0.5 Rev 14
 */

#ifndef __DRIVERS_TPM2_PTP_FIFO_H
#define __DRIVERS_TPM2_PTP_FIFO_H

#include <drivers/tpm2_chip.h>
#include <stdint.h>
#include <types_ext.h>
#include <util.h>

#define TPM2_REG_SIZE 0x5000

/* Register Space for FIFO TPM access where v represents locality */
#define TPM2_ACCESS(v)		(0x0000 | SHIFT_U32((v), 12))
#define TPM2_INT_ENABLE(v)	(0x0008 | SHIFT_U32((v), 12))
#define TPM2_INT_VECTOR(v)	(0x000c | SHIFT_U32((v), 12))
#define TPM2_INT_STATUS(v)	(0x0010 | SHIFT_U32((v), 12))
#define TPM2_INT_CAPABILITY(v)	(0x0014 | SHIFT_U32((v), 12))
#define TPM2_STS(v)		(0x0018 | SHIFT_U32((v), 12))
#define TPM2_DATA_FIFO(v)	(0x0024 | SHIFT_U32((v), 12))
#define TPM2_INTERFACE_ID(v)	(0x0030 | SHIFT_U32((v), 12))
#define TPM2_XDATA_FIFO(v)	(0x0080 | SHIFT_U32((v), 12))
#define TPM2_DID_VID(v)		(0x0F00 | SHIFT_U32((v), 12))
#define TPM2_RID(v)		(0x0F04 | SHIFT_U32((v), 12))

/* Access Register */
#define	TPM2_ACCESS_ESTABLISHMENT	BIT(0)
#define	TPM2_ACCESS_REQUEST_USE		BIT(1)
#define	TPM2_ACCESS_REQUEST_PENDING	BIT(2)
#define	TPM2_ACCESS_ACTIVE_LOCALITY	BIT(5)
#define	TPM2_ACCESS_VALID		BIT(7)

/* STS Register */
#define	TPM2_STS_RESPONSE_RETRY		BIT(1)
#define	TPM2_STS_SELF_TEST_DONE		BIT(2)
#define	TPM2_STS_DATA_EXPECT		BIT(3)
#define	TPM2_STS_DATA_AVAIL		BIT(4)
#define	TPM2_STS_GO			BIT(5)
#define	TPM2_STS_COMMAND_READY		BIT(6)
#define	TPM2_STS_VALID			BIT(7)
#define	TPM2_STS_COMMAND_CANCEL		BIT(24)
#define	TPM2_STS_RESET_ESTABLISMENT_BIT	BIT(25)
#define	TPM2_STS_FAMILY_TPM2		BIT(26)
#define	TPM2_STS_FAMILY_MASK		SHIFT_U32(3, 26)
#define	TPM2_STS_BURST_COUNT_MASK	SHIFT_U32(0xFFFF, 8)
#define	TPM2_STS_BURST_COUNT_SHIFT	8
#define	TPM2_STS_READ_ZERO		0x23

/* INT_ENABLE Register */
#define	TPM2_INT_DATA_AVAIL_INT		BIT(0)
#define	TPM2_INT_STS_VALID_INT		BIT(1)
#define	TPM2_INT_LOCALITY_CHANGE_INT	BIT(2)
#define	TPM2_INT_CMD_READY_INT		BIT(7)
#define	TPM2_GLOBAL_INT_ENABLE		BIT(31)

enum tpm2_result tpm2_fifo_init(struct tpm2_chip *chip);
enum tpm2_result tpm2_fifo_end(struct tpm2_chip *chip);
enum tpm2_result tpm2_fifo_send(struct tpm2_chip *chip, uint8_t *buf,
				uint32_t len);
enum tpm2_result tpm2_fifo_recv(struct tpm2_chip *chip, uint8_t *buf,
				uint32_t *len, uint32_t cmd_duration);

#endif	/* __DRIVERS_TPM2_PTP_FIFO_H */

