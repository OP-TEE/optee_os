/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef __TEE_TEEABI_OPTEED_H
#define __TEE_TEEABI_OPTEED_H

/*
 * This file specify ABI function IDs used when returning from TEE to the
 * secure monitor if applicable.
 */

/*
 * Issued when returning from initial entry.
 *
 * Register usage:
 * a0	ABI Function ID, TEEABI_OPTEED_RETURN_ENTRY_DONE
 * a1	Pointer to entry vector
 */
#define TEEABI_OPTEED_FUNCID_RETURN_ENTRY_DONE		0
#define TEEABI_OPTEED_RETURN_ENTRY_DONE \
	TEEABI_OPTEED_RV(TEEABI_OPTEED_FUNCID_RETURN_ENTRY_DONE)

/*
 * Issued when returning from "cpu_on" vector
 *
 * Register usage:
 * a0	ABI Function ID, TEEABI_OPTEED_RETURN_ON_DONE
 * a1	0 on success and anything else to indicate error condition
 */
#define TEEABI_OPTEED_FUNCID_RETURN_ON_DONE		1
#define TEEABI_OPTEED_RETURN_ON_DONE \
	TEEABI_OPTEED_RV(TEEABI_OPTEED_FUNCID_RETURN_ON_DONE)

/*
 * Issued when returning from "cpu_off" vector
 *
 * Register usage:
 * a0	ABI Function ID, TEEABI_OPTEED_RETURN_OFF_DONE
 * a1	0 on success and anything else to indicate error condition
 */
#define TEEABI_OPTEED_FUNCID_RETURN_OFF_DONE		2
#define TEEABI_OPTEED_RETURN_OFF_DONE \
	TEEABI_OPTEED_RV(TEEABI_OPTEED_FUNCID_RETURN_OFF_DONE)

/*
 * Issued when returning from "cpu_suspend" vector
 *
 * Register usage:
 * a0	ABI Function ID, TEEABI_OPTEED_RETURN_SUSPEND_DONE
 * a1	0 on success and anything else to indicate error condition
 */
#define TEEABI_OPTEED_FUNCID_RETURN_SUSPEND_DONE	3
#define TEEABI_OPTEED_RETURN_SUSPEND_DONE \
	TEEABI_OPTEED_RV(TEEABI_OPTEED_FUNCID_RETURN_SUSPEND_DONE)

/*
 * Issued when returning from "cpu_resume" vector
 *
 * Register usage:
 * a0	ABI Function ID, TEEABI_OPTEED_RETURN_RESUME_DONE
 * a1	0 on success and anything else to indicate error condition
 */
#define TEEABI_OPTEED_FUNCID_RETURN_RESUME_DONE		4
#define TEEABI_OPTEED_RETURN_RESUME_DONE \
	TEEABI_OPTEED_RV(TEEABI_OPTEED_FUNCID_RETURN_RESUME_DONE)

/*
 * Issued when returning from "std_abi" or "fast_abi" vector
 *
 * Register usage:
 * a0	ABI Function ID, TEEABI_OPTEED_RETURN_CALL_DONE
 * a1-4	Return value 0-3 which will passed to non-secure domain in a0-3
 */
#define TEEABI_OPTEED_FUNCID_RETURN_CALL_DONE		5
#define TEEABI_OPTEED_RETURN_CALL_DONE \
	TEEABI_OPTEED_RV(TEEABI_OPTEED_FUNCID_RETURN_CALL_DONE)

/*
 * Issued when returning from "fiq" vector
 *
 * Register usage:
 * a0	ABI Function ID, TEEABI_OPTEED_RETURN_FIQ_DONE
 */
#define TEEABI_OPTEED_FUNCID_RETURN_FIQ_DONE		6
#define TEEABI_OPTEED_RETURN_FIQ_DONE \
	TEEABI_OPTEED_RV(TEEABI_OPTEED_FUNCID_RETURN_FIQ_DONE)

/*
 * Issued when returning from "system_off" vector
 *
 * Register usage:
 * a0	ABI Function ID, TEEABI_OPTEED_RETURN_SYSTEM_OFF_DONE
 */
#define TEEABI_OPTEED_FUNCID_RETURN_SYSTEM_OFF_DONE	7
#define TEEABI_OPTEED_RETURN_SYSTEM_OFF_DONE \
	TEEABI_OPTEED_RV(TEEABI_OPTEED_FUNCID_RETURN_SYSTEM_OFF_DONE)

/*
 * Issued when returning from "system_reset" vector
 *
 * Register usage:
 * a0	ABI Function ID, TEEABI_OPTEED_RETURN_SYSTEM_RESET_DONE
 */
#define TEEABI_OPTEED_FUNCID_RETURN_SYSTEM_RESET_DONE	8
#define TEEABI_OPTEED_RETURN_SYSTEM_RESET_DONE \
	TEEABI_OPTEED_RV(TEEABI_OPTEED_FUNCID_RETURN_SYSTEM_RESET_DONE)

#endif /*__TEE_TEEABI_OPTEED_H*/
