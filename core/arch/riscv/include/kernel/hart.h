/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __KERNEL_HART_H
#define __KERNEL_HART_H

#include <stdbool.h>
#include <stdint.h>

/*
 * ISA extensions the core knows about, as named in the device tree
 * "riscv,isa-extensions" property and in the deprecated "riscv,isa" string.
 */
enum riscv_isa_ext {
	/* Base and single-letter extensions */
	RISCV_ISA_EXT_I,
	RISCV_ISA_EXT_M,
	RISCV_ISA_EXT_A,
	RISCV_ISA_EXT_F,
	RISCV_ISA_EXT_D,
	RISCV_ISA_EXT_C,
	RISCV_ISA_EXT_H,
	RISCV_ISA_EXT_V,
	/* Zi*: privileged and misc */
	RISCV_ISA_EXT_ZICBOM,
	RISCV_ISA_EXT_ZICBOP,
	RISCV_ISA_EXT_ZICBOZ,
	RISCV_ISA_EXT_ZICNTR,
	RISCV_ISA_EXT_ZICSR,
	RISCV_ISA_EXT_ZIFENCEI,
	RISCV_ISA_EXT_ZIHINTPAUSE,
	RISCV_ISA_EXT_ZIHPM,
	RISCV_ISA_EXT_ZAWRS,
	/* Bit manipulation */
	RISCV_ISA_EXT_ZBA,
	RISCV_ISA_EXT_ZBB,
	RISCV_ISA_EXT_ZBC,
	RISCV_ISA_EXT_ZBS,
	/* Scalar cryptography */
	RISCV_ISA_EXT_ZBKB,
	RISCV_ISA_EXT_ZBKC,
	RISCV_ISA_EXT_ZBKX,
	RISCV_ISA_EXT_ZKND,
	RISCV_ISA_EXT_ZKNE,
	RISCV_ISA_EXT_ZKNH,
	RISCV_ISA_EXT_ZKR,
	RISCV_ISA_EXT_ZKSED,
	RISCV_ISA_EXT_ZKSH,
	RISCV_ISA_EXT_ZKT,
	/* Vector cryptography */
	RISCV_ISA_EXT_ZVBB,
	RISCV_ISA_EXT_ZVBC,
	RISCV_ISA_EXT_ZVKB,
	RISCV_ISA_EXT_ZVKG,
	RISCV_ISA_EXT_ZVKNED,
	RISCV_ISA_EXT_ZVKNHA,
	RISCV_ISA_EXT_ZVKNHB,
	RISCV_ISA_EXT_ZVKSED,
	RISCV_ISA_EXT_ZVKSH,
	RISCV_ISA_EXT_ZVKT,
	/* Control-flow integrity */
	RISCV_ISA_EXT_ZICFILP,
	RISCV_ISA_EXT_ZICFISS,
	/* Supervisor-level */
	RISCV_ISA_EXT_SSDBLTRP,
	RISCV_ISA_EXT_SSTC,
	RISCV_ISA_EXT_SVADU,
	RISCV_ISA_EXT_SVINVAL,
	RISCV_ISA_EXT_SVNAPOT,
	RISCV_ISA_EXT_SVPBMT,
	RISCV_ISA_EXT_COUNT
};

/*
 * hart_features_init() - Collect what the device tree says about the harts
 *
 * Reads the CPU nodes of the harts listed in hartids[] once
 * boot_primary_init_core_ids() has filled it, and keeps what every one of
 * them supports. On a CFG_RISCV_M_MODE build the base extensions come from
 * the misa CSR of the primary hart instead.
 */
void hart_features_init(void);

/*
 * riscv_isa_ext_available() - Check for an ISA extension
 * @ext: Extension to check for
 *
 * Returns true when the extension is described as available on every hart
 * OP-TEE runs on. When a hart describes no ISA at all nothing is reported
 * available, so this is only as good as the device tree.
 */
bool riscv_isa_ext_available(enum riscv_isa_ext ext);

#endif /*__KERNEL_HART_H*/
