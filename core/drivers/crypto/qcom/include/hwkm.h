/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 */

#ifndef __HWKM_H__
#define __HWKM_H__

#include <kernel/mutex.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <types_ext.h>

#define HWKM_MAX_KEY_SIZE	32	/* bytes */
#define HWKM_MAX_CTX_SIZE	64	/* bytes */
#define HWKM_MAX_BLOB_SIZE	68	/* bytes */

enum hwkm_key_destination {
	HWKM_KEY_DEST_KM_MASTER = 0,
};

enum hwkm_key_security_lvl {
	HWKM_KEY_SECURITY_LVL_SW_KEY = 0,
	HWKM_KEY_SECURITY_LVL_MANAGED_KEY,
	HWKM_KEY_SECURITY_LVL_HW_KEY,
};

enum hwkm_key_type {
	HWKM_KEY_TYPE_KDK = 0,		/* Key derivation key. */
	HWKM_KEY_TYPE_KWK,		/* Key wrapping key. */
	HWKM_KEY_TYPE_KSK,		/* Key swap key. */
	HWKM_KEY_TYPE_TPKEY,		/* Transport protection key. */
	HWKM_KEY_TYPE_GENERIC_KEY,
};

/* Master key slot assignments. */
enum hwkm_master_key_slots {
	/* L1 KDKs - HW-only: */
	HWKM_SLOT_NKDK_L1 = 0,
	HWKM_SLOT_PKDK_L1 = 1,
	HWKM_SLOT_SKDK_L1 = 2,
	HWKM_SLOT_UKDK_L1 = 3,
	/* L2 KDKs. */
	HWKM_SLOT_TZ_NKDK_L2 = 4,
	HWKM_SLOT_TZ_PKDK_L2 = 5,
	HWKM_SLOT_TZ_SKDK_L2 = 6,
	HWKM_SLOT_MODEM_PKDK_L2 = 7,
	HWKM_SLOT_MODEM_SKDK_L2 = 8,
	HWKM_SLOT_TZ_UKDK_L2 = 9,
	/* TPKEY pair. */
	HWKM_SLOT_TPKEY_SLOT = 10,
	HWKM_SLOT_TPKEY_ODD_SLOT = 11,
	/* Swap key pair. */
	HWKM_SLOT_TZ_SWAP_KEY_SLOT = 12,
	HWKM_SLOT_TZ_SWAP_KEY_ODD_SLOT = 13,
	/* Wrap key pair. */
	HWKM_SLOT_TZ_WRAP_KEY_SLOT = 14,
	HWKM_SLOT_TZ_WRAP_KEY_ODD_SLOT = 15,
	/* General purpose scratch. */
	HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1 = 16,
	HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT2 = 17,
	/* Persistent shared pairs. */
	HWKM_SLOT_PERSISTENT_SHARED_SLOT_PAIR1 = 18,
	HWKM_SLOT_PERSISTENT_SHARED_SLOT_PAIR1_ODD = 19,
	HWKM_SLOT_PERSISTENT_SHARED_SLOT_PAIR2 = 20,
	HWKM_SLOT_PERSISTENT_SHARED_SLOT_PAIR2_ODD = 21,
	/* Mixing key. */
	HWKM_SLOT_TZ_MIXING_KEY_SLOT = 22,
};

enum hwkm_algo {
	HWKM_ALGO_AES128_ECB = 0,
	HWKM_ALGO_AES256_ECB = 1,
	HWKM_ALGO_AES128_CBC = 4,
	HWKM_ALGO_AES256_CBC = 5,
	HWKM_ALGO_AES256_SIV = 12,
	HWKM_ALGO_AES128_CTR = 13,
	HWKM_ALGO_AES256_CTR = 14,
	HWKM_ALGO_AES128_XTS = 15,
	HWKM_ALGO_AES256_XTS = 16,
	HWKM_ALGO_AES128_CMAC = 19,
	HWKM_ALGO_AES256_CMAC = 20,
};

struct hwkm_key_policy {
	/* TZ may issue commands against this slot. */
	bool km_by_tz_allowed;
	/* Non-secure world may use this slot. */
	bool km_by_nsec_allowed;
	/* Modem may use this slot. */
	bool km_by_modem_allowed;
	/* SPU may use this slot. */
	bool km_by_spu_allowed;
	/* Only algorithm permitted for this key. */
	enum hwkm_algo alg_allowed;
	/* Key may be used for encryption. */
	bool enc_allowed;
	/* Key may be used for decryption. */
	bool dec_allowed;
	/* Functional role. */
	enum hwkm_key_type key_type;
	/* Remaining KDF derivation hops. */
	uint8_t kdf_depth;
	/* Key may be exported via KEY_WRAP_EXPORT. */
	bool wrap_export_allowed;
	/* Key may be delivered via key-swap. */
	bool swap_export_allowed;
	/* SW_KEY, MANAGED_KEY, or HW_KEY. */
	enum hwkm_key_security_lvl security_lvl;
	/* Hardware destination. */
	enum hwkm_key_destination hw_destination;
	/* Allow wrapping under TPKEY. */
	bool wrap_with_tpkey_allowed;
};

struct hwkm_bsve {
	/* Master enable for all BSVE checks. */
	bool enabled;
	/* Enforce key policy version field. */
	bool km_key_policy_ver_en;
	/* Require apps processor to be in secure state. */
	bool km_apps_secure_en;
	/* Require modem to be in secure state. */
	bool km_msa_secure_en;
	/* Bind derivation to life-cycle fuse state. */
	bool km_lcm_fuse_en;
	/* Bind derivation to boot-stage OTP value. */
	bool km_boot_stage_otp_en;
	/* Enforce software component version check. */
	bool km_swc_en;
	/* Child key policy must be subset of parent. */
	bool km_child_key_policy_en;
	/* Include the mixing-key slot value in the KDF. */
	bool km_mks_en;
	/* Fuse regions hashed into KDF. */
	uint64_t km_fuse_region_sha_digest_en;
};

/* Command and response structs. */

enum hwkm_op {
	/* Generate a key via HW PRNG. */
	HWKM_OP_NIST_KEYGEN = 0,
	/* Derive a child key from a KDK slot. */
	HWKM_OP_SYSTEM_KDF = 1,
	/* Opcode 2 is reserved. */
	/* Wrap a slot under a KWK/KSK. */
	HWKM_OP_KEY_WRAP_EXPORT = 3,
	/* Unwrap a blob into a destination slot. */
	HWKM_OP_KEY_UNWRAP_IMPORT = 4,
	/* Clear a slot and invalidate its policy. */
	HWKM_OP_KEY_SLOT_CLEAR = 5,
	/* Read or write raw key material. */
	HWKM_OP_KEY_SLOT_RDWR = 6,
	/* Install a slot as the active TPKEY. */
	HWKM_OP_SET_TPKEY = 7,
};

struct hwkm_keygen_cmd {
	uint8_t dks;	/* Destination key slot. */
	struct hwkm_key_policy policy;
};

struct hwkm_rdwr_cmd {
	uint8_t slot;
	bool is_write;
	struct hwkm_key_policy policy;
	uint8_t key[HWKM_MAX_KEY_SIZE];
};

struct hwkm_kdf_cmd {
	uint8_t dks;	/* Destination key slot. */
	uint8_t kdk;	/* Parent KDK slot. */
	uint8_t mks;	/* Mixing-key slot selector. */
	struct hwkm_key_policy policy;
	struct hwkm_bsve bsve;
	uint8_t ctx[HWKM_MAX_CTX_SIZE];
	size_t ctx_len;
};

struct hwkm_set_tpkey_cmd {
	uint8_t sks;	/* Source key slot. */
};

struct hwkm_unwrap_cmd {
	uint8_t dks;	/* Destination key slot. */
	uint8_t kwk;	/* Wrapping key slot. */
	uint8_t wkb[HWKM_MAX_BLOB_SIZE];
};

struct hwkm_wrap_cmd {
	uint8_t sks;	/* Source key slot. */
	uint8_t kwk;	/* Wrapping key slot. */
	struct hwkm_bsve bsve;
};

struct hwkm_clear_cmd {
	uint8_t dks;	/* Destination key slot. */
	bool is_double_key;
};

struct hwkm_cmd {
	enum hwkm_op op;
	union {
		struct hwkm_keygen_cmd keygen;
		struct hwkm_rdwr_cmd rdwr;
		struct hwkm_kdf_cmd kdf;
		struct hwkm_set_tpkey_cmd set_tpkey;
		struct hwkm_unwrap_cmd unwrap;
		struct hwkm_wrap_cmd wrap;
		struct hwkm_clear_cmd clear;
	};
};

struct hwkm_rdwr_rsp {
	struct hwkm_key_policy policy;
	uint8_t key[HWKM_MAX_KEY_SIZE];
};

struct hwkm_wrap_rsp {
	uint8_t wkb[HWKM_MAX_BLOB_SIZE];
};

struct hwkm_rsp {
	uint32_t status;
	union {
		struct hwkm_rdwr_rsp rdwr;
		struct hwkm_wrap_rsp wrap;
	};
};

/* PUBLIC API. */

#define HWKM_SUCCESS		0
#define HWKM_ERR_GENERIC	1
#define HWKM_ERR_INVALID_ARG	2
#define HWKM_ERR_INVALID_DEST	3
#define HWKM_ERR_FIFO_NOT_EMPTY	4
#define HWKM_ERR_FIFO_TIMEOUT	5
#define HWKM_ERR_RSP_OVERFLOW	6
#define HWKM_ERR_NOT_SUPPORTED	7

static inline TEE_Result hwkm_to_optee(int rc)
{
	switch (rc) {
	case HWKM_SUCCESS:
		return TEE_SUCCESS;
	case HWKM_ERR_INVALID_ARG:
	case HWKM_ERR_INVALID_DEST:
		return TEE_ERROR_BAD_PARAMETERS;
	case HWKM_ERR_NOT_SUPPORTED:
		return TEE_ERROR_NOT_SUPPORTED;
	default:
		return TEE_ERROR_GENERIC;
	}
}

struct hwkm_handle;

struct hwkm_drv_ctx {
	vaddr_t base;
	struct mutex hwkm_lock; /* Serializes all HWKM operations. */
	bool hwkm_huk_ready;
	uint8_t hwkm_huk[HWKM_MAX_KEY_SIZE];
	bool initialized;
};

struct hwkm_drv_ctx *hwkm_get_context(void);

/*
 * struct hwkm_transaction - queued HWKM command and response.
 * @cmd: Command to submit.
 * @rsp: Response filled by the driver.
 * @hdl: Owning handle when the transaction is queued.
 * @link: Queue link.
 *
 * A transaction contains one HWKM command and its corresponding response.
 * Transactions are queued on a handle and executed in FIFO order by
 * hwkm_run_cmd_queue().
 */
struct hwkm_transaction {
	struct hwkm_cmd cmd;
	struct hwkm_rsp rsp;
	struct hwkm_handle *hdl;

	STAILQ_ENTRY(hwkm_transaction) link;
};

STAILQ_HEAD(hwkm_transaction_queue, hwkm_transaction);

/*
 * struct hwkm_handle - HWKM command queue handle.
 * @dest: Target hardware engine.
 * @queue: Queued transactions.
 *
 * A handle groups one or more HWKM commands targeting the same destination.
 * Initialize it with hwkm_handle_init(), enqueue transactions with
 * hwkm_enqueue() / hwkm_enqueue_many(), then execute them with
 * hwkm_run_cmd_queue().
 *
 * Example:
 *
 *	struct hwkm_transaction t_kdf = {
 *		.cmd = {
 *			.op = HWKM_OP_SYSTEM_KDF,
 *		},
 *	};
 *
 *	struct hwkm_transaction t_clear = {
 *		.cmd = {
 *			.op = HWKM_OP_KEY_SLOT_CLEAR,
 *		},
 *	};
 *
 *	struct hwkm_handle h = { };
 *
 *	hwkm_handle_init(&h, HWKM_KEY_DEST_KM_MASTER);
 *	hwkm_enqueue(&h, &t_kdf);
 *	hwkm_enqueue(&h, &t_clear);
 *	hwkm_run_cmd_queue(&h);
 *
 * The responses are returned in t_kdf.rsp and t_clear.rsp.
 */
struct hwkm_handle {
	enum hwkm_key_destination dest;
	struct hwkm_transaction_queue queue;
};

struct hwkm_transaction *hwkm_transaction_alloc(void);
void hwkm_transaction_free(struct hwkm_transaction *t);

int hwkm_handle_init(struct hwkm_handle *hdl, enum hwkm_key_destination dest);
int hwkm_enqueue(struct hwkm_handle *hdl, struct hwkm_transaction *t);
int hwkm_enqueue_many(struct hwkm_handle *hdl, size_t num_t,
		      struct hwkm_transaction *const trans[]);
int hwkm_run_cmd_queue(struct hwkm_handle *hdl);

/*
 * hwkm_run_transactions() - Init a handle, enqueue @num_t transactions, and
 *                           execute them in one call.
 * @dest: Target hardware engine.
 * @num_t: Number of entries in @trans.
 * @trans: Array of transaction pointers executed in FIFO order.
 *
 * Convenience wrapper around hwkm_handle_init() + hwkm_enqueue_many() +
 * hwkm_run_cmd_queue(). Use when all transactions target the same destination
 * and no handle needs to survive the call.
 *
 * Return: HWKM_SUCCESS on success, or a HWKM_ERR_* code on failure.
 */
static inline int hwkm_run_transactions(enum hwkm_key_destination dest,
					size_t num_t,
					struct hwkm_transaction *const trans[])
{
	struct hwkm_handle hdl = { };
	int rc = HWKM_ERR_GENERIC;

	rc = hwkm_handle_init(&hdl, dest);
	if (rc)
		return rc;

	rc = hwkm_enqueue_many(&hdl, num_t, trans);
	if (rc)
		return rc;

	return hwkm_run_cmd_queue(&hdl);
}

/* Execute a single transaction. */
static inline int hwkm_run_transaction(enum hwkm_key_destination dest,
				       struct hwkm_transaction *t)
{
	return hwkm_run_transactions(dest, 1,
				     (struct hwkm_transaction *const[]){ t });
}

#endif /* __HWKM_H__ */
