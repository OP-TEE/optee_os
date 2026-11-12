/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __DRIVERS_QCOM_QUP_FW_LOAD_H
#define __DRIVERS_QCOM_QUP_FW_LOAD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

/* Serial protocols as encoded in the SE firmware header (QUPv3 HPG) */
enum qupv3_protocol {
	QUPV3_PROTOCOL_NONE = 0,
	QUPV3_PROTOCOL_SPI = 1,
	QUPV3_PROTOCOL_UART_2W = 2,
	QUPV3_PROTOCOL_I2C = 3,
	QUPV3_PROTOCOL_I3C = 4,
	QUPV3_PROTOCOL_SPI_SLAVE = 5,
	QUPV3_PROTOCOL_AFC = 6,
	QUPV3_PROTOCOL_SPMI = 7,
	QUPV3_PROTOCOL_QSPI_HID = 8,
	QUPV3_PROTOCOL_QSPI = 9,
	QUPV3_PROTOCOL_DB_UART = 0xc,
	QUPV3_PROTOCOL_UFCS = 0xd,
	QUPV3_PROTOCOL_Q2SPI = 0xe,
	QUPV3_PROTOCOL_SPI_3W_4W = 0x10,
	/* Software-only aliases, reduced to the HW value by QUPV3_TO_HW() */
	QUPV3_PROTOCOL_UART_4W = 0x22,
	QUPV3_PROTOCOL_I2C_MM = 0x23,
	QUPV3_PROTOCOL_I3C_IBI = 0x104,
};

#define QUPV3_TO_HW(p)		((uint32_t)(p) & 0x1f)

enum qupv3_mode {
	QUPV3_MODE_FIFO = 0,
	QUPV3_MODE_CPU_DMA = 1,
	QUPV3_MODE_GSI = 2,
};

/* Subset of the TZ access-control IDs used for NS owners */
enum qupv3_ac_id {
	QUPV3_AC_NONE = 0,
	QUPV3_AC_TZ = 1,
	QUPV3_AC_HLOS = 3,
	QUPV3_AC_SOCCP_DCP = 10,
	QUPV3_AC_MSS_MSA = 15,
};

/* Per-SE policy, mirrors QUPv3_se_security_permissions_type in TZ */
struct qupv3_se_perms {
	uint32_t periph_id;		/* Index into the platform SE table */
	enum qupv3_protocol protocol;
	enum qupv3_mode mode;
	enum qupv3_ac_id ns_owner;
	bool allow_fifo;
	bool load;			/* Load FW into this SE */
	bool mod_excl;
};

struct qupv3_se_hw {
	paddr_t base;
	const char *clk_name;
};

struct qupv3_common_hw {
	paddr_t base;
	const char * const *clk_names;
	size_t num_clks;
	/* GSI top of this wrapper, 0 if GSI FW is not loaded by OP-TEE */
	paddr_t gsi_base;
	size_t gsi_size;
};

struct qupv3_fw_platform {
	/* ELF header + program headers describing FW segments in DDR */
	const uint8_t *elf_hdr;
	size_t elf_hdr_size;
	/* DDR window where the FW segments were loaded by the boot chain */
	paddr_t fw_ddr_base;
	size_t fw_ddr_size;

	const struct qupv3_se_hw *se;
	size_t num_se;
	const struct qupv3_common_hw *common;
	size_t num_common;
	const struct qupv3_se_perms *perms;
	size_t num_perms;
};

/* get paltform config */
const struct qupv3_fw_platform *qupv3_fw_get_platform(void);

#endif /* __DRIVERS_QCOM_QUP_FW_LOAD_H */
