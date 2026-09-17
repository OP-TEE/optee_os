/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2026 Marvell.
 */

#ifndef __EHSM_SECURITY_H__
#define __EHSM_SECURITY_H__

/* Security specific errors. */
enum sec_return {
	SEC_NO_ERROR                        = 0,
	SEC_INVALID_PARAMETER               = 1028,
	SEC_INVALID_MAILBOX                 = 2030,
	SEC_HW_FAILURE                      = 3001,
};
#endif /* __EHSM_SECURITY_H__ */
