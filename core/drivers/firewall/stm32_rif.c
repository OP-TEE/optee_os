// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2024, STMicroelectronics
 */

#include <assert.h>
#include <drivers/stm32_rif.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>

#define MAX_CID_BITFIELD	U(3)

/**
 * get_scid_mask() - Get the static CID mask according to the number of
 *		     supported CIDs
 *
 * @nb_cid_supp: Number of CIDs supported. Cannot be 0.
 */
static uint32_t get_scid_mask(unsigned int nb_cid_supp)
{
	uint32_t msb_nb_cid_supp = 0;

	assert(nb_cid_supp);

	msb_nb_cid_supp = sizeof(nb_cid_supp) * 8 -
			  __builtin_clz((nb_cid_supp - 1) | 1);

	/* SCID bitfield highend can't be > SCID_SHIFT + MAX_CID_BITFIELD */
	assert(msb_nb_cid_supp <= MAX_CID_BITFIELD);

	return GENMASK_32(SCID_SHIFT + msb_nb_cid_supp - 1, SCID_SHIFT);
}

TEE_Result stm32_rif_check_access(uint32_t cidcfgr,
				  uint32_t semcr,
				  unsigned int nb_cid_supp,
				  unsigned int cid_to_check)
{
	uint32_t scid_mask = get_scid_mask(nb_cid_supp);

	if (!(cidcfgr & _CIDCFGR_CFEN))
		return TEE_SUCCESS;

	if (stm32_rif_scid_ok(cidcfgr, scid_mask, cid_to_check))
		return TEE_SUCCESS;

	if (stm32_rif_semaphore_enabled_and_ok(cidcfgr, cid_to_check)) {
		if (!(semcr & _SEMCR_MUTEX) ||
		    ((semcr & scid_mask) >> SCID_SHIFT) == cid_to_check) {
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ACCESS_DENIED;
}

void stm32_rif_parse_cfg(uint32_t rif_conf,
			 struct rif_conf_data *conf_data,
			 unsigned int nb_cid_supp,
			 unsigned int nb_channel)
{
	uint32_t scid_mask = get_scid_mask(nb_cid_supp);
	uint32_t cidcfdg_conf_mask = 0;
	uint32_t channel_id = 0;
	uint32_t semwl_mask = 0;
	unsigned int conf_index = 0;

	semwl_mask = GENMASK_32(SEMWL_SHIFT + nb_cid_supp - 1, SEMWL_SHIFT);

	cidcfdg_conf_mask = scid_mask | semwl_mask | _CIDCFGR_CFEN |
			    _CIDCFGR_SEMEN;

	/* Shift corresponding to the desired resources */
	channel_id = RIF_CHANNEL_ID(rif_conf);
	if (channel_id >= nb_channel)
		panic("Bad RIF controllers number");

	/* Some peripherals have more than 32 RIF channels */
	conf_index = channel_id / 32;

	/* Privilege configuration */
	if (rif_conf & RIFPROT_PRIV)
		conf_data->priv_conf[conf_index] |= BIT(channel_id);

	/* Security RIF configuration */
	if (rif_conf & RIFPROT_SEC)
		conf_data->sec_conf[conf_index] |= BIT(channel_id);

	/* RIF configuration lock */
	if (rif_conf & RIFPROT_LOCK && conf_data->lock_conf)
		conf_data->lock_conf[conf_index] |= BIT(channel_id);

	/* CID configuration */
	conf_data->cid_confs[channel_id] = rif_conf & cidcfdg_conf_mask;

	/* Store that this RIF resource is to be configured */
	conf_data->access_mask[conf_index] |= BIT(channel_id);
}

bool stm32_rif_semaphore_is_available(vaddr_t addr)
{
	return !(io_read32(addr) & _SEMCR_MUTEX);
}

TEE_Result stm32_rif_acquire_semaphore(vaddr_t addr, unsigned int nb_cid_supp)
{
	uint32_t scid_mask = get_scid_mask(nb_cid_supp);

	/* Take the semaphore */
	io_setbits32(addr, _SEMCR_MUTEX);

	/* Check that the Cortex-A has the semaphore */
	if (stm32_rif_semaphore_is_available(addr) ||
	    ((io_read32(addr) & scid_mask) >> SCID_SHIFT) != RIF_CID1)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

TEE_Result stm32_rif_release_semaphore(vaddr_t addr, unsigned int nb_cid_supp)
{
	uint32_t scid_mask = get_scid_mask(nb_cid_supp);

	if (stm32_rif_semaphore_is_available(addr))
		return TEE_SUCCESS;

	/* Release the semaphore */
	io_clrbits32(addr, _SEMCR_MUTEX);

	/* Check that current compartment no more owns the semaphore */
	if (!stm32_rif_semaphore_is_available(addr) &&
	    ((io_read32(addr) & scid_mask) >> SCID_SHIFT) == RIF_CID1)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}
