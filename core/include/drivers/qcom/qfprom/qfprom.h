/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __QFPROM_H__
#define __QFPROM_H__

#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>

enum qfprom_addr_space {
	QFPROM_ADDR_SPACE_RAW = 0,
	QFPROM_ADDR_SPACE_CORR = 1,
};

enum qfprom_error {
	QFPROM_NO_ERR = 0x0,
	QFPROM_ERR_UNKNOWN = 0x1,
	QFPROM_DATA_PTR_NULL_ERR = 0x2,
	QFPROM_ADDRESS_INVALID_ERR = 0x3,
	QFPROM_WRITE_ERR = 0x4,
	QFPROM_REGION_NOT_SUPPORTED_ERR = 0x5,
	QFPROM_REGION_NOT_READABLE_ERR = 0x6,
	QFPROM_REGION_NOT_WRITABLE_ERR = 0x7,
	QFPROM_FEC_ERR = 0x8,
	QFPROM_OPERATION_NOT_ALLOWED_ERR = 0x9,
	QFPROM_FAILED_TO_CHANGE_VOLTAGE_ERR = 0xA,
	QFPROM_ERROR_CLOCK_FAILED = 0x10,
	QFPROM_ERROR_TIMEOUT = 0x11,
};

struct qcom_secboot_device_ids {
	uint32_t oem_id;
	uint32_t model_id;
	uint32_t jtag_id;
	uint32_t serial_num;
};

struct qcom_secboot_mrc_info {
	uint32_t num_roots;
	uint32_t activation_list;
	uint32_t revocation_list;
};

/* Read QFPROM row data */
TEE_Result qfprom_read_row(uint32_t addr,
			   enum qfprom_addr_space type,
			   uint32_t *data);

/*
 * Read QFPROM row data, taking and releasing the hardware mutex around the
 * read. Use this outside a qfprom_hw_init()/qfprom_hw_deinit() batch, where
 * the mutex is not already held.
 */
TEE_Result qfprom_read_row_locked(uint32_t addr,
				  enum qfprom_addr_space type,
				  uint32_t *data);

/* Is secure boot (authentication) enabled on this device? */
TEE_Result qcom_secboot_is_enabled(bool *enabled);

/* Is the serial-number fuse used as part of device binding? */
TEE_Result qcom_secboot_is_use_serial_num_enabled(bool *enabled);

/* Read the OEM root-of-trust anchor hash (PK_HASH0). */
TEE_Result qcom_secboot_get_root_of_trust(uint8_t *hash, size_t len);

/* Read the PIL anti-rollback fuse version (set bits in the ARB row). */
TEE_Result qcom_secboot_get_pil_rollback_version(uint32_t *version);

/* Advance the PIL anti-rollback fuse, saturating at the counter capacity. */
TEE_Result qcom_secboot_blow_pil_rollback_version(uint32_t version);

/* Read the OEM/model/JTAG/serial device-identity fuses. */
TEE_Result qcom_secboot_get_device_ids(struct qcom_secboot_device_ids *ids);

/* Read the SoC family/device word from TCSR_SOC_HW_VERSION. */
TEE_Result qcom_secboot_get_soc_hw_version(uint32_t *fam_dev);

/*
 * Segment/hash-table digest size for @root_cert_sel; unrelated to
 * cert-chain or root-of-trust hashing.
 */
TEE_Result qcom_secboot_get_segment_hash_len(uint32_t root_cert_sel,
					     uint32_t *hash_len);

/* Is code-signing EKU enforcement required for this device? */
TEE_Result qcom_secboot_get_eku_enforcement_en(bool *enabled);

/*
 * Report the number of provisioned roots (1 when the anchor isn't
 * fuse-resident with multiple roots) and, when more than one, the
 * per-index activation/revocation bitmaps.
 */
TEE_Result qcom_secboot_get_mrc_info(struct qcom_secboot_mrc_info *info);

/* Write QFPROM row data */
TEE_Result qfprom_write_row(uint32_t addr, uint32_t *data);

/* Check if row has FEC protection */
TEE_Result qfprom_row_has_fec_bits(uint32_t addr,
				   enum qfprom_addr_space type,
				   uint8_t *has_fec);

/* Calculate FEC bits for 56-bit data */
uint32_t qfprom_fec_63_56_bit(uint32_t lsb_data, uint32_t msb_data);

/*
 * Read whether the OEM secure boot write-permission fuse is blown, which
 * locks further provisioning. Takes and releases the hardware mutex around
 * the read, so call it outside a programming batch. @write_disabled is
 * valid only on success.
 */
TEE_Result qfprom_is_secboot_write_disabled(bool *write_disabled);

/*
 * Hardware init/deinit for batch fuse operations. A successful init holds
 * the hardware mutex until deinit. Deinit releases it even on cleanup error.
 */
TEE_Result qfprom_hw_init(void);
TEE_Result qfprom_hw_deinit(void);

#endif /* __QFPROM_H__ */
