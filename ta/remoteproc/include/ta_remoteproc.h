/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2023, STMicroelectronics
 */

#ifndef TA_REMOTEPROC_H
#define TA_REMOTEPROC_H

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_REMOTEPROC_UUID { 0x80a4c275, 0x0a47, 0x4905, \
			     { 0x82, 0x85, 0x14, 0x86, 0xa9, 0x77, 0x1a, 0x08} }

/* The command IDs implemented in this TA */

/*
 * Authentication of the firmware and load in the remote processor memory.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [in]  params[1].memref:	buffer containing the image of the firmware
 */
#define TA_RPROC_CMD_LOAD_FW		1

/*
 * Start the remote processor.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 */
#define TA_RPROC_CMD_START_FW		2

/*
 * Stop the remote processor.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 */
#define TA_RPROC_CMD_STOP_FW		3

/*
 * Return the physical address of the resource table, or 0 if not found
 * No check is done to verify that the address returned is accessible by the
 * non-secure world. If the resource table is loaded in a protected memory,
 * then accesses from non-secure world will likely fail.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [out] params[1].value.a:	32bit LSB resource table memory address
 * [out] params[1].value.b:	32bit MSB resource table memory address
 * [out] params[2].value.a:	32bit LSB resource table memory size
 * [out] params[2].value.b:	32bit MSB resource table memory size
 */
#define TA_RPROC_CMD_GET_RSC_TABLE	4

/*
 * Get remote processor firmware core dump. If found, return either
 * TEE_SUCCESS on successful completion or TEE_ERROR_SHORT_BUFFER if output
 * buffer is too short to store the core dump.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [out] params[1].memref:	Core dump, if found
 */
#define TA_RPROC_CMD_GET_COREDUMP	5

#endif /*TA_REMOTEPROC_H*/
