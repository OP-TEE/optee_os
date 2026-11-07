/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __OPTEE_RPMI_H
#define __OPTEE_RPMI_H

/*
 * OP-TEE service over RPMI TEE_CALL. All control fields are little-endian.
 * Control status is an unsigned 32-bit TEE result (TEE_SUCCESS or TEE_ERROR_*),
 * separate from the signed RPMI TEE_CALL status and the command's GP result.
 * Shared command arguments use optee_msg.h.
 * Memory identities use a 64-bit global_id: parcel ID in bits 31:0 and nonce
 * in bits 63:32. A zero nonce denotes NULL regardless of the parcel ID.
 * SHM_FREE RPC carries the memory type in value[0].a, global_id in value[0].b,
 * and zero in value[0].c.
 */
#define OPTEE_RPMI_VERSION_MAJOR	1
#define OPTEE_RPMI_VERSION_MINOR	0

/* Yielding-call results shared with the architecture entry code. */
#define OPTEE_RPMI_YIELDING_CALL_RETURN_DONE	0
#define OPTEE_RPMI_YIELDING_CALL_RETURN_RPC_CMD	1
#define OPTEE_RPMI_YIELDING_CALL_RETURN_INTERRUPT	2

#ifndef __ASSEMBLER__

#include <stdint.h>

/*
 * Encode the memory handle: parcel ID in bits 31:0 and nonce in bits 63:32.
 * A zero nonce denotes NULL regardless of the parcel ID. NULL references have
 * a zero buffer offset; their requested size is preserved.
 */
static inline uint64_t optee_rpmi_global_id(uint32_t parcel_id, uint32_t nonce)
{
	return ((uint64_t)nonce << 32) | parcel_id;
}

/* Extract the firmware-assigned parcel ID from a memory identity. */
static inline uint32_t optee_rpmi_parcel_id(uint64_t global_id)
{
	return (uint32_t)global_id;
}

/* Extract the nonce; zero denotes a NULL memory reference. */
static inline uint32_t optee_rpmi_nonce(uint64_t global_id)
{
	return global_id >> 32;
}

struct optee_rpmi_probe_req {
	uint32_t op;
};

struct optee_rpmi_status_resp {
	uint32_t status;
};

/* Query the service ABI revision using optee_rpmi_probe_req. */
#define OPTEE_RPMI_GET_API_VERSION	0

struct optee_rpmi_api_resp {
	uint32_t status;
	uint32_t major;
	uint32_t minor;
};

/* Query the trusted OS revision using optee_rpmi_probe_req. */
#define OPTEE_RPMI_GET_OS_VERSION		1

struct optee_rpmi_os_resp {
	uint32_t status;
	uint32_t major;
	uint32_t minor;
	uint32_t reserved;	/* Zero in version 1. */
	uint64_t build_id;	/* Zero when unspecified. */
};

/* Query capabilities and argument capacities using optee_rpmi_probe_req. */
#define OPTEE_RPMI_EXCHANGE_CAPABILITIES	2

struct optee_rpmi_caps_resp {
	uint32_t status;
	uint32_t secure_caps;		/* Reserved; zero in version 1. */
	uint32_t rpc_param_count;		/* Max RPC parameter count. */
	uint32_t max_notification_key;	/* Inclusive maximum; zero means 255. */
};

/* Retire a parcel from the local cache once it is no longer in use. */
#define OPTEE_RPMI_UNREGISTER_SHM		3

struct optee_rpmi_unregister_req {
	uint32_t op;
	uint32_t reserved;	/* Zero in version 1. */
	uint64_t global_id;	/* Parcel identity with a nonzero nonce. */
};

/* Enable bottom-half doorbells using the caller's allocated signal. */
#define OPTEE_RPMI_ENABLE_ASYNC_NOTIF	4

struct optee_rpmi_enable_notif_req {
	uint32_t op;
	uint32_t signal_id;
};

/* Start a yielding command using parcel-backed command and RPC ranges. */
#define OPTEE_RPMI_YIELDING_CALL_WITH_ARG	5

struct optee_rpmi_call_req {
	uint32_t op;
	uint32_t flags;		/* Zero in version 1. */
	uint64_t global_id;	/* Argument parcel; nonce must be nonzero. */
	uint64_t arg_offset;	/* Offset from the parcel's first byte. */
	uint64_t rpc_offset;	/* Disjoint from the command range. */
	uint32_t arg_size;
	uint32_t rpc_size;	/* Must fit the negotiated RPC buffer size. */
};

struct optee_rpmi_call_resp {
	uint32_t status;
	uint32_t result;		/* RETURN_* on success. */
	uint32_t resume_token;	/* Opaque, may be zero; ignored for DONE. */
};

/* Resume an existing call; rejection must not be reported as TEE_ERROR_BUSY. */
#define OPTEE_RPMI_YIELDING_CALL_RESUME	6

struct optee_rpmi_resume_req {
	uint32_t op;
	uint32_t reserved;	/* Zero in version 1. */
	uint32_t resume_token;	/* Copied unchanged from the last response. */
};

#endif /* __ASSEMBLER__ */

#endif /* __OPTEE_RPMI_H */
