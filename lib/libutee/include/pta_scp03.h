/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2020, Foundries Limited
 */

#ifndef __PTA_SCP03_H
#define __PTA_SCP03_H

#define PTA_SCP03_UUID { 0xbe0e5821, 0xe718, 0x4f77, \
			{ 0xab, 0x3e, 0x8e, 0x6c, 0x73, 0xa9, 0xc7, 0x35 } }

/*
 * Enable SCP03 support on the SE
 *
 * [in]     value[0].a    Use session keys PTA_SCP03_SESSION_*
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_NOT_IMPLEMENTED - Invoke command not implemented
 * TEE_ERROR_GENERIC - Invoke command failure
 */
#define PTA_CMD_ENABLE_SCP03		0

/* Enable the session using the current keys in the Secure Element */
#define PTA_SCP03_SESSION_CURRENT_KEYS	0

/* Enable the session after replacing the current keys in the Secure Element */
#define PTA_SCP03_SESSION_ROTATE_KEYS	1

#endif /* __PTA_SCP03_H */
