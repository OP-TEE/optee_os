/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _CLK_PAS_H_
#define _CLK_PAS_H_

#include <io.h>
#include <mm/core_memprot.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

/* Core VA of a registered or mapped MMIO range, 0 if there is none */
#define QCOM_IO_VA(phys, size) \
	((vaddr_t)phys_to_virt_io((phys), (size)))

#define Q6_HALT_BIT			BIT(0)
#define Q6_HALT_ACK_TIMEOUT_US		1000000

/*
 * Request a halt of a QDSP6 bus master port through its TCSR halt request
 * register @haltreq and wait for @haltack. A QDSP6 in a bad state may never
 * acknowledge; the caller resets it anyway.
 */
static inline TEE_Result qcom_q6_halt(vaddr_t haltreq, vaddr_t haltack)
{
	uint32_t val = 0;

	io_setbits32(haltreq, Q6_HALT_BIT);
	if (IO_READ32_POLL_TIMEOUT(haltack, val, val & Q6_HALT_BIT, 5,
				   Q6_HALT_ACK_TIMEOUT_US))
		return TEE_ERROR_TIMEOUT;

	return TEE_SUCCESS;
}

#endif /* _CLK_PAS_H_ */
