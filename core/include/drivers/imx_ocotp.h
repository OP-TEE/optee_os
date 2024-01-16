/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __DRIVERS_IMX_OCOTP_H
#define __DRIVERS_IMX_OCOTP_H

#include <tee_api_types.h>

/* The i.MX UID is 64 bits long */
#define IMX_UID_SIZE sizeof(uint64_t)

/*
 * Read OCOTP shadow register
 *
 * @bank     Fuse bank number
 * @word     Fuse word number
 * @[out]val Shadow register value
 */
TEE_Result imx_ocotp_read(unsigned int bank, unsigned int word, uint32_t *val);
#endif /* __DRIVERS_IMX_OCOTP_H */
