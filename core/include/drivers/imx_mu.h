/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020-2021 NXP
 */
#ifndef __DRIVERS_IMX_MU_H
#define __DRIVERS_IMX_MU_H

#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#define MU_NB_RR 4
#define MU_NB_TR 4

/*
 * Clear GIE, RIE, TIE, GIR and F registers
 *
 * @base   Base address of the MU
 */
void mu_init(vaddr_t base);

/*
 * Send a message through MU
 *
 * @base    Base address of the MU
 * @index   Index of the TR register
 * @msg     Message to send
 */
TEE_Result mu_send_msg(vaddr_t base, unsigned int index, uint32_t msg);

/*
 * Receive a message through MU
 *
 * @base    Base address of the MU
 * @index   Index of the RR register
 * @msg     [out] Received message
 */
TEE_Result mu_receive_msg(vaddr_t base, unsigned int index, uint32_t *msg);
#endif /* __DRIVERS_IMX_MU_H */
