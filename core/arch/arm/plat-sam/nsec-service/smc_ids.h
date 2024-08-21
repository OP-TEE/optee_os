/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Microchip
 */

#ifndef SMC_IDS_H
#define SMC_IDS_H
#include <optee_msg.h>
#include <sm/optee_smc.h>

#define SAM_SMC_SIP_PL310_ENABLE	1
#define SAM_SMC_SIP_PL310_DISABLE	2
#define SAM_SMC_SIP_PL310_EN_WRITEBACK	3
#define SAM_SMC_SIP_PL310_DIS_WRITEBACK	4

#define SAMA5_SMC_SIP_SCMI_CALL_ID	0x200

#define SAMA5_SMC_SIP_SFR_SET_USB_SUSPEND	0x300

#define SAMA5_SMC_SIP_SET_SUSPEND_MODE	0x400
#define SAMA5_SMC_SIP_GET_SUSPEND_MODE	0x401

/* SAMA5 SMC return codes */
#define SAMA5_SMC_SIP_RETURN_SUCCESS	0x0
#define SAMA5_SMC_SIP_RETURN_EINVAL	0x1

#endif /* SMC_IDS_H */
