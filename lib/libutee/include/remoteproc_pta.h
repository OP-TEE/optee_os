/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2023, STMicroelectronics
 */

#ifndef __REMOTEPROC_PTA_H
#define __REMOTEPROC_PTA_H

#include <stdint.h>
#include <util.h>

/*
 * Interface to the pseudo TA which provides platform implementation
 * of the remote processor management
 */

#define PTA_RPROC_UUID { 0x54af4a68, 0x19be, 0x40d7, \
		{ 0xbb, 0xe6, 0x89, 0x50, 0x35, 0x0a, 0x87, 0x44 } }

/* Firmware format */
#define PTA_RPROC_PROPRIETARY_FMT	BIT32(0)
#define PTA_RPROC_ELF_FMT		BIT32(1)

/* Firmware image protection */
/* The platform supports copy of the input firmware image in secure memory */
#define PTA_RPROC_FW_SECURE_COPY	BIT32(0)
/* The platform supports load of segment with hash protection */
#define PTA_RPROC_FW_WITH_HASH_TABLE	BIT32(1)
/* The platform is able to change access to secure the firmware input image */
#define PTA_RPROC_FW_MEMORY_PROTECTION	BIT32(2)

/* Platform predefined TLV ID */
/* boot address of secure fw */
#define PTA_RPROC_TLV_SBOOTADDR		U(0x21)
/* boot address of non-secure fw */
#define PTA_RPROC_TLV_NSBOOTADDR	U(0x22)

/* Platform predefined TLV LENGTH (byte) */
#define PTA_RPROC_TLV_SBOOTADDR_LGTH	U(4)
#define PTA_RPROC_TLV_NSBOOTADDR_LGTH	U(4)

/**
 * struct rproc_pta_key_info - public key information
 * @algo:	Algorithm, defined by public key algorithms TEE_ALG_*
 *		from TEE Internal API specification
 * @info_size:	Byte size of the @info
 * @info:	Append key information data
 */
struct rproc_pta_key_info {
	uint32_t algo;
	uint32_t info_size;
	uint8_t info[];
};

static inline size_t rproc_pta_keyinfo_size(struct rproc_pta_key_info *keyinf)
{
	size_t s = 0;

	if (!keyinf || ADD_OVERFLOW(sizeof(*keyinf), keyinf->info_size, &s))
		return 0;

	return s;
}

/*
 * Platform capabilities.
 *
 * Get Platform firmware loader service capabilities.
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 * [out] params[1].value.a:	Firmware format (PTA_RPROC_*_FMT)
 * [out] params[2].value.a:	Image protection method (PTA_RPROC_FW_*)
 */
#define PTA_RPROC_HW_CAPABILITIES	1

/*
 * Firmware loading.
 *
 * Optional service to implement only in case of proprietary format.
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 * [in]  params[1].memref:	Loadable firmware image
 */
#define PTA_RPROC_FIRMWARE_LOAD		2

/*
 * Load a segment with a SHA256 hash.
 *
 * This command is used when the platform secure memory is too expensive to
 * save the whole firmware image. Upon segment load, a successful completion
 * ensures the loaded image complies with the provided hash.
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 * [in]  params[1].memref:	Section data to load
 * [in]  params[2].value.a:	32bit LSB load device segment address
 * [in]  params[2].value.b:	32bit MSB load device segment address
 * [in]  params[3].memref:	Expected hash (SHA256) of the payload
 */
#define PTA_RPROC_LOAD_SEGMENT_SHA256	3

/*
 * Memory set.
 *
 * Fill a remote device memory with requested value. this is use for instance
 * to clear a memory on the remote firmware load.
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 * [in]  params[1].value.a:	32bit LSB device memory address
 * [in]  params[1].value.b:	32bit MSB device memory address
 * [in]  params[2].value.a:	32bit LSB device memory size
 * [in]  params[2].value.b:	32bit MSB device memory size
 * [in]  params[3].value.a:	Byte value to be set
 */
#define PTA_RPROC_SET_MEMORY		4

/*
 * Firmware start.
 *
 * Start up a successfully remote processor firmware.
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 */
#define PTA_RPROC_FIRMWARE_START	5

/*
 * Firmware stop.
 *
 * Stop of the remote processor firmware and release/clean resources.
 * After the command successful completion, remote processor firmware must be
 * reloaded prior being started again.
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 */
#define PTA_RPROC_FIRMWARE_STOP		6

/*
 * Firmware device to physical address conversion.
 *
 * Convert the physical address corresponding to an address got from the
 * firmware address layout.
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 * [in]  params[1].value.a:	32bit LSB Device memory address
 * [in]  params[1].value.b:	32bit MSB Device memory address
 * [in]  params[2].value.a:	32bit LSB Device memory size
 * [in]  params[2].value.b:	32bit MSB Device memory size
 * [out] params[3].value.a:	32bit LSB converted physical address
 * [out] params[3].value.b:	32bit MSB converted physical address
 */
#define PTA_RPROC_FIRMWARE_DA_TO_PA	7

/*
 * Verify the firmware digest against a signature
 *
 * Return TEE_SUCCESS if the signature is verified,
 *        TEE_ERROR_SIGNATURE_INVALID when signature is not valid,
 *        another error code for other error cases.
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 * [in]  params[1].memref:	Key information (refer to @rproc_pta_key_info)
 * [in]  params[2].memref:	Digest of the firmware authenticated data
 * [in]  params[3].memref:	Signature of the firmware authenticated data
 */
#define PTA_RPROC_VERIFY_DIGEST		8

/*
 * Provide platform parameter in Type-Length-Value format
 *
 * Return TEE_SUCCESS if the TLV is valid, else an error
 *
 * [in]  params[0].value.a:     Unique 32bit firmware identifier
 * [in]  params[1].value.a:     16bit Type identifier
 * [in]  params[2].memref:      Value associated to the type ID
 */
#define PTA_RPROC_TLV_PARAM		9

#endif /* __REMOTEPROC_PTA_H */
