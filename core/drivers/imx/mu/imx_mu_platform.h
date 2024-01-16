/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __IMX_MU_PLATFORM_H__
#define __IMX_MU_PLATFORM_H__

/*
 * Return the number of reception channels
 */
unsigned int imx_mu_plat_get_rx_channel(vaddr_t base);

/*
 * Return the number of transmission channels
 */
unsigned int imx_mu_plat_get_tx_channel(vaddr_t base);

/*
 * Send a 32bits word via the MU
 *
 * @base: virtual base address of the MU controller
 * @index: MU channel index
 * @[in]msg: word to send
 */
TEE_Result imx_mu_plat_send(vaddr_t base, unsigned int index, uint32_t msg);

/*
 * Get the 32bits word received by the MU
 *
 * @base: virtual base address of the MU controller
 * @index: MU channel index
 * @[out]msg: word received
 */
TEE_Result imx_mu_plat_receive(vaddr_t base, unsigned int index, uint32_t *msg);

/*
 * Initialize the MU interface
 *
 * @base: virtual base address of the MU controller
 */
void imx_mu_plat_init(vaddr_t base);
#endif /* __IMX_MU_PLATFORM_H__ */
