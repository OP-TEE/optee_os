/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022 Texas Instruments Incorporated - https://www.ti.com/
 *	Manorit Chawdhry <m-chawdhry@ti.com>
 */

#ifndef TI_SCI_H
#define TI_SCI_H

#include <compiler.h>
#include <stdint.h>
#include <util.h>

#include "ti_sci_protocol.h"

/**
 * ti_sci_get_revision() - Get the revision of the SCI entity
 *
 * Updates the SCI information in the internal data structure.
 *
 * Return: 0 if all goes well, else appropriate error message
 */
int ti_sci_get_revision(struct ti_sci_msg_resp_version *rev_info);

/**
 * Device control operations
 *
 * - ti_sci_device_get - Get access to device managed by TISCI
 * - ti_sci_device_put - Release access to device managed by TISCI
 *
 * NOTE: for all these functions, the following are generic in nature:
 * @id:		Device Identifier
 *
 * Returns 0 for successful request, else returns corresponding error message.
 *
 * Request for the device - NOTE: the client MUST maintain integrity of
 * usage count by balancing get_device with put_device. No refcounting is
 * managed by driver for that purpose.
 */
int ti_sci_device_get(uint32_t id);
int ti_sci_device_put(uint32_t id);

/**
 * ti_sci_set_fwl_region() - Request for configuring a firewall region
 *
 * @fwl_id:             Firewall ID in question. fwl_id is defined in the TRM.
 * @region:             Region or channel number to set config info. This field
 *                      is unused in case of a simple firewall and must be
 *                      initialized to zero. In case of a region based
 *                      firewall, this field indicates the region in question
 *                      (index starting from 0). In case of a channel based
 *                      firewall, this field indicates the channel in question
 *                      (index starting from 0).
 * @n_permission_regs:  Number of permission registers to set
 * @control:            Contents of the firewall CONTROL register to set
 * @permissions:        Contents of the firewall PERMISSION register to set
 * @start_address:      Contents of the firewall START_ADDRESS register to set
 * @end_address:        Contents of the firewall END_ADDRESS register to set
 *
 * Return: 0 if all went well, else returns appropriate error value.
 */
int ti_sci_set_fwl_region(uint16_t fwl_id, uint16_t region,
			  uint32_t n_permission_regs, uint32_t control,
			  const uint32_t permissions[FWL_MAX_PRIVID_SLOTS],
			  uint64_t start_address, uint64_t end_address);
/**
 * ti_sci_cmd_get_fwl_region() - Request for getting a firewall region
 *
 * @fwl_id:             Firewall ID in question. fwl_id is defined in the TRM.
 * @region:             Region or channel number to set config info. This field
 *                      is unused in case of a simple firewall and must be
 *                      initialized to zero. In case of a region based
 *                      firewall, this field indicates the region in question
 *                      (index starting from 0). In case of a channel based
 *                      firewall, this field indicates the channel in question
 *                      (index starting from 0).
 * @n_permission_regs:  Region or channel number to set config info
 * @control:            Contents of the firewall CONTROL register
 * @permissions:        Contents of the firewall PERMISSION register
 * @start_address:      Contents of the firewall START_ADDRESS register
 * @end_address:        Contents of the firewall END_ADDRESS register
 *
 * Return: 0 if all went well, else returns appropriate error value.
 */
int ti_sci_get_fwl_region(uint16_t fwl_id, uint16_t region,
			  uint32_t n_permission_regs, uint32_t *control,
			  uint32_t permissions[FWL_MAX_PRIVID_SLOTS],
			  uint64_t *start_address, uint64_t *end_address);
/**
 * ti_sci_change_fwl_owner() - Request for changing a firewall owner
 *
 * @fwl_id:             Firewall ID in question. fwl_id is defined in the TRM.
 * @region:             Region or channel number to set config info. This field
 *                      is unused in case of a simple firewall and must be
 *                      initialized to zero. In case of a region based
 *                      firewall, this field indicates the region in question
 *                      (index starting from 0). In case of a channel based
 *                      firewall, this field indicates the channel in question
 *                      (index starting from 0).
 * @owner_index:        New owner index to transfer ownership to
 * @owner_privid:       New owner priv-ID returned by DMSC. This field is
 *                      currently initialized to zero by DMSC.
 * @owner_permission_bits: New owner permission bits returned by DMSC. This
 *                         field is currently initialized to zero by DMSC.
 *
 * Return: 0 if all went well, else returns appropriate error value.
 */
int ti_sci_change_fwl_owner(uint16_t fwl_id, uint16_t region,
			    uint8_t owner_index, uint8_t *owner_privid,
			    uint16_t *owner_permission_bits);

/**
 * ti_sci_get_dkek() - Get the DKEK
 * @sa2ul_instance:	SA2UL instance to get key
 * @context:		Context string input to KDF
 * @label:		Label string input to KDF
 * @dkek:		Returns with DKEK populated
 *
 * Updates the DKEK the internal data structure.
 *
 * Return: 0 if all goes well, else appropriate error message
 */
int ti_sci_get_dkek(uint8_t sa2ul_instance,
		    const char *context, const char *label,
		    uint8_t dkek[SA2UL_DKEK_KEY_LEN]);

/**
 * ti_sci_init() - Basic initialization
 *
 * Return: 0 if all goes well, else appropriate error message
 */
int ti_sci_init(void);

#endif
