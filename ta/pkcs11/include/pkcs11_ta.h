/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#ifndef PKCS11_TA_H
#define PKCS11_TA_H

#include <stdbool.h>
#include <stdint.h>

#define PKCS11_TA_UUID { 0xfd02c9da, 0x306c, 0x48c7, \
			 { 0xa4, 0x9c, 0xbb, 0xd8, 0x27, 0xae, 0x86, 0xee } }

/* PKCS11 trusted application version information */
#define PKCS11_TA_VERSION_MAJOR			0
#define PKCS11_TA_VERSION_MINOR			1
#define PKCS11_TA_VERSION_PATCH			0

/* Attribute specific values */
#define PKCS11_UNAVAILABLE_INFORMATION		UINT32_C(0xFFFFFFFF)
#define PKCS11_UNDEFINED_ID			PKCS11_UNAVAILABLE_INFORMATION
#define PKCS11_FALSE				false
#define PKCS11_TRUE				true

/*
 * Note on PKCS#11 TA commands ABI
 *
 * For evolution of the TA API and to not mess with the GPD TEE 4 parameters
 * constraint, all the PKCS11 TA invocation commands use a subset of available
 * the GPD TEE invocation parameter types.
 *
 * Param#0 is used for the so-called control arguments of the invoked command
 * and for providing a PKCS#11 compliant status code for the request command.
 * Param#0 is an in/out memory reference (aka memref[0]). The input buffer
 * stores the command arguments serialized inside. The output buffer will
 * store the 32bit TA return code for the command. Client shall get this
 * return code and override the GPD TEE Client API legacy TEE_Result value.
 *
 * Param#1 is used for input data arguments of the invoked command.
 * It is unused or is a input memory reference, aka memref[1].
 * Evolution of the API may use memref[1] for output data as well.
 *
 * Param#2 is mostly used for output data arguments of the invoked command
 * and for output handles generated from invoked commands.
 * Few commands uses it for a secondary input data buffer argument.
 * It is unused or is a input/output/in-out memory reference, aka memref[2].
 *
 * Param#3 is currently unused and reserved for evolution of the API.
 */

/*
 * PKCS11_CMD_PING		Acknowledge TA presence and return version info
 *
 * Optinal invocation parameter (if none, command simply returns with success)
 * [out]        memref[2] = [
 *                      32bit version major value,
 *                      32bit version minor value
 *                      32bit version patch value
 *              ]
 */
#define PKCS11_CMD_PING				0
#endif /*PKCS11_TA_H*/
