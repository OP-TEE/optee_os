/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 *
 * The definitions in this file are based on
 * TCG PC Client Platform TPM Profile Specification for TPM 2.0
 * v1.0.5 Revision 14
 */

#ifndef __DRIVERS_TPM2_CHIP_H
#define __DRIVERS_TPM2_CHIP_H

#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

/*
 * TPM2 interface related and generic errors
 */
enum tpm2_result {
	TPM2_OK = 0,

	TPM2_ERR_GENERIC,
	TPM2_ERR_INVALID_ARG,
	TPM2_ERR_ARG_LIST_TOO_LONG,
	TPM2_ERR_BUSY,
	TPM2_ERR_TIMEOUT,
	TPM2_ERR_IO,
	TPM2_ERR_NODEV,
	TPM2_ERR_NO_ACTIVE_LOCALITY,
	TPM2_ERR_SHORT_BUFFER,
	TPM2_ERR_CMD,
};

/* TPM Command Duration in ms as defined in Table 17 of the spec */
enum tpm2_cmd_duration {
	TPM2_CMD_DURATION_SHORT = 20,
	TPM2_CMD_DURATION_MEDIUM = 750,
	TPM2_CMD_DURATION_LONG = 2000,
	/* Picked up from Linux TPM driver */
	TPM2_CMD_DURATION_DEFAULT = 120000,
};

#define TPM2_TIMEOUT_RETRY_MS	5

/* TPM Interface timouts in ms as defined Table 18 of the spec */
enum tpm2_interface_timeouts {
	TPM2_TIMEOUT_A = 750,
	TPM2_TIMEOUT_B = 2000,
	TPM2_TIMEOUT_C = 200,
	TPM2_TIMEOUT_D = 30,
};

enum tpm2_interface {
	TPM2_PTP_FIFO,
	TPM2_PTP_CRB
};

struct tpm2_caps {
	uint32_t num_pcrs;	/* Number of PCRs chip supports */
	uint32_t pcr_select_min; /* Min octets to represent PCR bitmap */
	uint32_t num_banks;	/* Number of banks/algs supported */
	uint32_t num_active_banks; /* Number of active banks/algs */
	uint32_t selection_mask;   /* Bitmap of supported banks/algs */
	uint32_t active_mask;	/* Bitmap of active banks/algs */
};

struct tpm2_chip {
	const struct tpm2_ptp_ops *ops;
	const struct tpm2_ptp_phy_ops *phy_ops;
	enum tpm2_interface ptp_type;
	struct tpm2_caps capability;
	int32_t locality;
	uint32_t timeout_a;
	uint32_t timeout_b;
	uint32_t timeout_c;
	uint32_t timeout_d;
};

struct tpm2_ptp_ops {
	enum tpm2_result (*init)(struct tpm2_chip *chip);
	enum tpm2_result (*end)(struct tpm2_chip *chip);
	enum tpm2_result (*send)(struct tpm2_chip *chip, uint8_t *buf,
				 uint32_t len);
	enum tpm2_result (*recv)(struct tpm2_chip *chip, uint8_t *buf,
				 uint32_t *len, uint32_t cmd_duration);
};

/* Physical interface for PTP */
struct tpm2_ptp_phy_ops {
	enum tpm2_result (*rx32)(struct tpm2_chip *chip, uint32_t adr,
				 uint32_t *buf);
	enum tpm2_result (*tx32)(struct tpm2_chip *chip, uint32_t adr,
				 uint32_t val);
	enum tpm2_result (*rx8)(struct tpm2_chip *chip, uint32_t adr,
				uint16_t len, uint8_t *buf);
	enum tpm2_result (*tx8)(struct tpm2_chip *chip, uint32_t adr,
				uint16_t len, uint8_t *buf);
};

enum tpm2_result tpm2_chip_register(struct tpm2_chip *chip);
enum tpm2_result tpm2_chip_unregister(struct tpm2_chip *chip);

enum tpm2_result tpm2_chip_send(uint8_t *buf, uint32_t len);
enum tpm2_result tpm2_chip_recv(uint8_t *buf, uint32_t *len,
				uint32_t cmd_duration);

enum tpm2_result tpm2_chip_get_caps(struct tpm2_caps *capability);
bool tpm2_chip_is_active_bank(uint16_t alg);

#ifdef CFG_CORE_TCG_PROVIDER
TEE_Result tpm2_tcg_register(void);
#else
static inline TEE_Result tpm2_tcg_register(void)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif

#endif	/* __DRIVERS_TPM2_CHIP_H */
