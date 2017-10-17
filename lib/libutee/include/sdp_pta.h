/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2017, ARM Limited, All Rights Reserved
 */

#ifndef __SDP_PTA_H
#define __SDP_PTA_H

#define PTA_SDP_PTA_UUID { 0x54c82831, 0x0170, 0x487d, \
		{ 0xb7, 0xe6, 0xe9, 0x30, 0xf4, 0xfd, 0xc5, 0x24 } }

/*
 * PTA_CMD_SDP_VIRT_TO_PHYS - Get physical address for the SDP buffer memref
 *
 * param[0] (in memref) - SDP buffer memory reference
 * param[1] (out value) - Physical address (.a=32bit MSB, .b=32bit LSB)
 * param[2] unused
 * param[3] unused
 */
#define PTA_CMD_SDP_VIRT_TO_PHYS		0x0

#endif /* __SDP_PTA_H */
