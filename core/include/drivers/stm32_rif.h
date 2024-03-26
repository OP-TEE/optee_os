/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022-2024, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_RIF_H
#define __DRIVERS_STM32_RIF_H

#include <dt-bindings/firewall/stm32mp25-rif.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

/*
 * CIDCFGR register
 */
#define _CIDCFGR_CFEN			BIT(0)
#define _CIDCFGR_SEMEN			BIT(1)
#define _CIDCFGR_SEMWL(x)		BIT(SEMWL_SHIFT + (x))

/*
 * SEMCR register
 */
#define _SEMCR_MUTEX			BIT(0)
#define _SEMCR_SEMCID_SHIFT		U(4)
#define _SEMCR_SEMCID_MASK		GENMASK_32(6, 4)

/*
 * Miscellaneous
 */
#define MAX_CID_SUPPORTED		U(8)

#define SCID_SHIFT			U(4)
#define SEMWL_SHIFT			U(16)
#define RIF_ID_SHIFT			U(24)

#define RIF_ID_MASK			GENMASK_32(31, 24)
#define RIF_CHANNEL_ID(x)		((RIF_ID_MASK & (x)) >> RIF_ID_SHIFT)

#define RIFPROT_SEC			BIT(8)
#define RIFPROT_PRIV			BIT(9)
#define RIFPROT_LOCK			BIT(10)

/**
 * struct rif_conf_data - Structure containing RIF configuration data
 *
 * @access_mask: Array of the masks of the registers which will be configured.
 * @sec_conf: Secure configuration registers.
 * @priv_conf: Privilege configuration registers.
 * @cid_confs: CID filtering configuration register value for a peripheral
 *             resource (e.g: GPIO pins, FMC controllers)
 * @lock_conf: RIF configuration locking registers
 *
 * For a hardware block having 56 channels, there will be 56 cid_confs
 * registers and 2 sec_conf and priv_conf registers
 */
struct rif_conf_data {
	uint32_t *access_mask;
	uint32_t *sec_conf;
	uint32_t *priv_conf;
	uint32_t *cid_confs;
	uint32_t *lock_conf;
};

#ifdef CFG_STM32_RIF
/**
 * stm32_rif_scid_ok() - Check if a given static CID configuration authorizes
 *			 access to a given CID
 *
 * @cidcfgr: Value of the CIDCFGR register
 * @scid_m: Mask of the static CID in the register
 * @cid_to_check: CID of the target compartment
 *
 * Returns true if given CID is authorized, false otherwise.
 */
static inline bool stm32_rif_scid_ok(uint32_t cidcfgr, uint32_t scid_m,
				     uint32_t cid_to_check)
{
	return (cidcfgr & scid_m) == SHIFT_U32(cid_to_check, SCID_SHIFT) &&
	       !(cidcfgr & _CIDCFGR_SEMEN);
}

/**
 * stm32_rif_semaphore_enabled_and_ok() - Check if semaphore mode is enabled and
 *					  that a given CID can request the
 *					  semaphore ownership
 *
 * @cidcfgr: Value of the cidcfgr register
 * @cid_to_check: CID to check
 *
 * Returns true if the requested CID can request the semaphore ownership,
 * false otherwise.
 */
static inline bool stm32_rif_semaphore_enabled_and_ok(uint32_t cidcfgr,
						      uint32_t cid_to_check)
{
	return (cidcfgr & _CIDCFGR_CFEN) && (cidcfgr & _CIDCFGR_SEMEN) &&
	       (cidcfgr & _CIDCFGR_SEMWL(cid_to_check));
}

/**
 * stm32_rifsc_check_tdcid() - Check if the execution context is TDCID or not
 *
 * @tdcid_state: [out] Set to true if TDCID, false otherwise.
 *
 * Returns TEE_ERROR_DEFER_DRIVER_INIT if RIFSC driver isn't probed, TEE_SUCCESS
 * otherwise.
 */
TEE_Result stm32_rifsc_check_tdcid(bool *tdcid_state);

/**
 * stm32_rif_check_access() - Test peripheral access for a given compartment
 *
 * @cidcfgr: CIDCFGR configuration register value
 * @semcr: SEMCR register value
 * @nb_cid_supp: Number of supported CID for the peripheral
 * @cid_to_check: CID of the target compartment
 *
 * Returns TEE_SUCCESS if access is authorized, a TEE_Result error value
 * otherwise.
 */
TEE_Result stm32_rif_check_access(uint32_t cidcfgr,
				  uint32_t semcr,
				  unsigned int nb_cid_supp,
				  unsigned int cid_to_check);

/**
 * stm32_rif_parse_cfg() - Parse RIF config from Device Tree extracted
 *			   information
 *
 * @rif_conf: Configuration read in the device tree
 * @conf_data: Buffer containing the RIF configuration to apply for a peripheral
 * @nb_cid_supp: Number of supported CID for the peripheral
 * @nb_channel: Number of channels for the peripheral
 */
void stm32_rif_parse_cfg(uint32_t rif_conf,
			 struct rif_conf_data *conf_data,
			 unsigned int nb_cid_supp,
			 unsigned int nb_channel);

/**
 * stm32_rif_semaphore_is_available() - Checks if the _SEMCR_MUTEX bit is set
 *
 * @addr: Address of the register to read from
 */
bool stm32_rif_semaphore_is_available(vaddr_t addr);

/**
 * stm32_rif_semaphore_is_available() - Acquires the semaphore by setting the
 *					_SEMCR_MUTEX bit
 *
 * @addr: Address of the register to write to
 * @nb_cid_supp: Number of CID supported
 */
TEE_Result stm32_rif_acquire_semaphore(vaddr_t addr,
				       unsigned int nb_cid_supp);

/**
 * stm32_rif_semaphore_is_available() - Releases the semaphore by clearing the
 *					_SEMCR_MUTEX bit
 *
 * @addr: Address of the register to write to
 * @nb_cid_supp: Number of CID supported
 */
TEE_Result stm32_rif_release_semaphore(vaddr_t addr,
				       unsigned int nb_cid_supp);
#else
static inline bool stm32_rif_scid_ok(uint32_t cidcfgr, uint32_t scid_m,
				     uint32_t cid_to_check)
{
	return true;
}

static inline bool stm32_rif_semaphore_enabled_and_ok(uint32_t cidcfgr,
						      uint32_t cid_to_check)
{
	return true;
}

static inline TEE_Result stm32_rifsc_check_tdcid(bool *tdcid_state)
{
	/* Without CFG_STM32_RIF every CPU can behave as TDCID */
	*tdcid_state = true;

	return TEE_SUCCESS;
}

static inline TEE_Result
stm32_rif_check_access(uint32_t cidcfgr __unused,
		       uint32_t semcr __unused,
		       unsigned int nb_cid_supp __unused,
		       unsigned int cid_to_check __unused)
{
	return TEE_SUCCESS;
}

static inline void
stm32_rif_parse_cfg(uint32_t rif_conf __unused,
		    struct rif_conf_data *conf_data __unused,
		    unsigned int nb_cid_supp __unused,
		    unsigned int nb_channel __unused)
{
}

static inline bool stm32_rif_semaphore_is_available(vaddr_t addr __unused)
{
	return true;
}

static inline TEE_Result
stm32_rif_acquire_semaphore(vaddr_t addr __unused,
			    unsigned int nb_cid_supp __unused)
{
	return TEE_SUCCESS;
}

static inline TEE_Result
stm32_rif_release_semaphore(vaddr_t addr __unused,
			    unsigned int nb_cid_supp __unused)
{
	return TEE_SUCCESS;
}
#endif /* CFG_STM32_RIF */
#endif /* __DRIVERS_STM32_RIF_H */
