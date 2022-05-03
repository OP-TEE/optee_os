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
