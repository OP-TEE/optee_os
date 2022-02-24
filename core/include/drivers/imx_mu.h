/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020-2022 NXP
 */
#ifndef __DRIVERS_IMX_MU_H
#define __DRIVERS_IMX_MU_H

#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#define IMX_MU_DATA_U32(mesg, idx) ((mesg)->data.u32[(idx)])
#define IMX_MU_DATA_U16(mesg, idx) ((mesg)->data.u16[(idx)])
#define IMX_MU_DATA_U8(mesg, idx)  ((mesg)->data.u8[(idx)])

#define IMX_MU_MSG_SIZE	  7
#define IMX_MU_NB_CHANNEL 4

#if defined(CFG_MX8ULP)
struct imx_mu_msg_header {
	uint8_t version;
	uint8_t size;
	uint8_t command;
	uint8_t tag;
};
#elif defined(CFG_MX8QM) || defined(CFG_MX8QX) || defined(CFG_MX8DXL)
struct imx_mu_msg_header {
	uint8_t version;
	uint8_t size;
	uint8_t tag;
	uint8_t command;
};
#else
#error "Platform not supported"
#endif

/*
 * i.MX MU message format
 * Note: the header format differs depending of the platform.
 */
struct imx_mu_msg {
	struct imx_mu_msg_header header;
	union {
		uint32_t u32[IMX_MU_MSG_SIZE];
		uint16_t u16[IMX_MU_MSG_SIZE * 2];
		uint8_t u8[IMX_MU_MSG_SIZE * 4];
	} data;
};

/*
 * Initialize the MU interface
 *
 * @base: virtual base address of the MU controller
 */
void imx_mu_init(vaddr_t base);

/*
 * Initiate a communication with the external controller. It sends a message
 * and return the answer of the controller.
 *
 * @base: virtual base address of the MU controller
 * @[in/out]msg: message sent and received
 * @wait_for_answer: true if an answer from the controller is expected, false
 * otherwise
 */
TEE_Result imx_mu_call(vaddr_t base, struct imx_mu_msg *msg,
		       bool wait_for_answer);
#endif /* __DRIVERS_IMX_MU_H */
