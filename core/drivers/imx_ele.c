// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023 NXP
 */
#include <drivers/imx_mu.h>
#include <initcall.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <tee/cache.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <types_ext.h>
#include <utee_types.h>
#include <util.h>

#define ELE_BASE_ADDR MU_BASE
#define ELE_BASE_SIZE MU_SIZE

#define ELE_VERSION_BASELINE 0x06
#define ELE_VERSION_HSM	     0x07
#define ELE_COMMAND_SUCCEED  0xd6
#define ELE_REQUEST_TAG	     0x17
#define ELE_RESPONSE_TAG     0xe1

#define ELE_CMD_SESSION_OPEN	    0x10
#define ELE_CMD_SESSION_CLOSE	    0x11
#define ELE_CMD_SESSION_DEVICE_INFO 0x16
#define ELE_CMD_RNG_GET		    0xCD
#define ELE_CMD_TRNG_STATE	    0xA4
#define ELE_CMD_GET_INFO	    0xDA
#define ELE_CMD_DERIVE_KEY	    0xA9

#define IMX_ELE_TRNG_STATUS_READY 0x3

#define ELE_MU_ID  0x2
#define ELE_MU_IRQ 0x0

#if defined(CFG_MX8ULP)
#define ELE_MU_DID 0x7
#define CACHELINE_SIZE 64
#elif defined(CFG_MX93)
#define ELE_MU_DID 0x3
#define CACHELINE_SIZE 64
#else
#error "Platform DID is not defined"
#endif

#define SIZE_MSG_32(_msg) size_msg_32(sizeof(_msg))

register_phys_mem_pgdir(MEM_AREA_IO_SEC, ELE_BASE_ADDR, ELE_BASE_SIZE);

struct get_info_msg_rsp {
	uint32_t rsp_code;
	uint16_t soc_id;
	uint16_t soc_rev;
	uint16_t lifecycle;
	uint16_t sssm_state;
	uint32_t uid[4];
	uint32_t sha256_rom_patch[8];
	uint32_t sha256_fw[8];
} __packed;

struct session_get_device_info_rsp {
	uint32_t rsp_code;
	uint32_t user_sab_id;
	uint32_t chip_uid[4];
	uint16_t chip_life_cycle;
	uint16_t chip_monotonic_counter;
	uint32_t ele_version;
	uint32_t ele_version_ext;
	uint8_t fips_mode;
	uint8_t reserved[3];
	uint32_t crc;
} __packed;

struct response_code {
	uint8_t status;
	uint8_t rating;
	uint16_t rating_extension;
} __packed;

/*
 * Print ELE response status and rating
 *
 * @rsp response code structure
 */
static void print_rsp_code(struct response_code rsp __maybe_unused)
{
	DMSG("Response status %#"PRIx8", rating %#"PRIx8" (ext %#"PRIx16")",
	     rsp.status, rsp.rating, rsp.rating_extension);
}

/*
 * Print ELE message header
 *
 * @hdr message header
 */
static void print_msg_header(struct imx_mu_msg_header hdr __maybe_unused)
{
	DMSG("Header ver %#"PRIx8", size %"PRId8", tag %#"PRIx8", cmd %#"PRIx8,
	     hdr.version, hdr.size, hdr.tag, hdr.command);
}

/*
 * Print full ELE message content
 *
 * @msg message
 */
static void dump_message(const struct imx_mu_msg *msg __maybe_unused)
{
	size_t i = 0;
	size_t size __maybe_unused = msg->header.size;
	uint32_t *data __maybe_unused = (uint32_t *)msg;

	DMSG("Dump of message %p(%zu)", data, size);
	for (i = 0; i < size; i++)
		DMSG("word %zu: %#"PRIx32, i, data[i]);
}

/*
 * Return the number of 32 bits words of the given message.
 *
 * @cmd command size in byte
 */
static size_t size_msg_32(size_t cmd)
{
	/* Roundup and add header size */
	return ROUNDUP_DIV(cmd, sizeof(uint32_t)) + 1;
}

/*
 * The CRC for the message is computed xor-ing all the words of the message:
 * the header and all the words except the word storing the CRC.
 *
 * @msg MU message to hash
 */
static uint32_t compute_crc(const struct imx_mu_msg *msg)
{
	uint32_t crc = 0;
	uint8_t i = 0;
	uint32_t *payload = (uint32_t *)msg;

	assert(msg);

	for (i = 0; i < msg->header.size - 1; i++)
		crc ^= payload[i];

	return crc;
}

/*
 * Compute message CRC and update CRC in message header.
 *
 * @msg MU message to hash
 */
static void update_crc(struct imx_mu_msg *msg)
{
	assert(msg);
	/*
	 * The CRC field is the last element of array. The size of the header
	 * is also subtracted from CRC computation.
	 */
	msg->data.u32[msg->header.size - 2] = compute_crc(msg);
}

/*
 * Return the given MU base address, depending on the MMU state.
 *
 * @pa MU physical base address
 * @sz MU size
 */
static vaddr_t imx_ele_init(paddr_t pa, size_t sz)
{
	static bool is_initialized;
	vaddr_t va = 0;

	assert(pa && sz);

	if (cpu_mmu_enabled())
		va = core_mmu_get_va(pa, MEM_AREA_IO_SEC, sz);
	else
		va = (vaddr_t)pa;

	if (!is_initialized) {
		imx_mu_init(va);
		is_initialized = true;
	}

	return va;
}

/*
 * Extract response codes from the given word
 *
 * @word 32 bits word MU response
 */
static struct response_code get_response_code(uint32_t word)
{
	struct response_code rsp = {
		.rating_extension = (word & GENMASK_32(31, 16)) >> 16,
		.rating = (word & GENMASK_32(15, 8)) >> 8,
		.status = (word & GENMASK_32(7, 0)) >> 0,
	};

	return rsp;
}

/*
 * Initiate a communication with the EdgeLock Enclave. It sends a message
 * and expects an answer.
 *
 * @msg MU message
 */
static TEE_Result imx_ele_call(struct imx_mu_msg *msg)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct response_code rsp = { };
	vaddr_t va = 0;

	assert(msg);

	if (msg->header.tag != ELE_REQUEST_TAG) {
		EMSG("Request has invalid tag: %#"PRIx8" instead of %#"PRIx8,
		     msg->header.tag, ELE_REQUEST_TAG);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	va = imx_ele_init(ELE_BASE_ADDR, ELE_BASE_SIZE);
	if (!va) {
		EMSG("Fail to get base address");
		return TEE_ERROR_GENERIC;
	}

	res = imx_mu_call(va, msg, true);
	if (res) {
		EMSG("Failed to transmit message: %#"PRIx32, res);
		print_msg_header(msg->header);
		dump_message(msg);
		return res;
	}

	rsp = get_response_code(msg->data.u32[0]);

	if (msg->header.tag != ELE_RESPONSE_TAG) {
		EMSG("Response has invalid tag: %#"PRIx8" instead of %#"PRIx8,
		     msg->header.tag, ELE_RESPONSE_TAG);
		print_msg_header(msg->header);
		return TEE_ERROR_GENERIC;
	}

	if (rsp.status != ELE_COMMAND_SUCCEED) {
		EMSG("Command has failed");
		print_rsp_code(rsp);
		return TEE_ERROR_GENERIC;
	}

	/* The rating can be different in success and failing cases */
	if (rsp.rating != 0) {
		EMSG("Command has invalid rating: %#"PRIx8, rsp.rating);
		print_rsp_code(rsp);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

/*
 * Get device information from EdgeLock Enclave
 *
 * @session_handle EdgeLock Enclave session handle
 * @rsp Device info
 */
static TEE_Result
imx_ele_session_get_device_info(uint32_t session_handle,
				struct session_get_device_info_rsp *rsp)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct session_get_device_info_cmd {
		uint32_t session_handle;
	} cmd = {
		.session_handle = session_handle,
	};
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SESSION_DEVICE_INFO,
	};

	assert(rsp);

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	res = imx_ele_call(&msg);
	if (res)
		return res;

	memcpy(rsp, msg.data.u32, sizeof(*rsp));

	if (compute_crc(&msg) != rsp->crc)
		return TEE_ERROR_CORRUPT_OBJECT;

	return TEE_SUCCESS;
}

/*
 * Open a session with EdgeLock Enclave. It returns a session handle.
 *
 * @session_handle EdgeLock Enclave session handle
 */
static TEE_Result imx_ele_session_open(uint32_t *session_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct open_session_cmd {
		uint8_t mu_id;
		uint8_t interrupt_num;
		uint8_t tz;
		uint8_t did;
		uint8_t priority;
		uint8_t op_mode;
		uint16_t reserved;
	} __packed cmd = {
		.mu_id = ELE_MU_ID,
		.interrupt_num = ELE_MU_IRQ,
		.tz = 0,
		.did = ELE_MU_DID,
		.priority = 0,
		.op_mode = 0,
		.reserved = 0,
	};
	struct open_session_rsp {
		uint32_t rsp_code;
		uint32_t session_handle;
	} rsp = { };
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SESSION_OPEN,
	};

	assert(session_handle);

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	res = imx_ele_call(&msg);
	if (res)
		return res;

	memcpy(&rsp, msg.data.u8, sizeof(rsp));

	*session_handle = rsp.session_handle;

	return TEE_SUCCESS;
}

/*
 * Close a session with EdgeLock Enclave.
 *
 * @session_handle EdgeLock Enclave session handle
 */
static TEE_Result imx_ele_session_close(uint32_t session_handle)
{
	struct close_session_cmd {
		uint32_t session_handle;
	} cmd = {
		.session_handle = session_handle,
	};
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SESSION_CLOSE,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	return imx_ele_call(&msg);
}

/*
 * Get the current state of the ELE TRNG
 */
static TEE_Result imx_ele_rng_get_trng_state(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rng_get_trng_state_msg_rsp {
		uint32_t rsp_code;
		uint8_t trng_state;
		uint8_t csal_state;
	} __packed rsp = { };
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_BASELINE,
		.header.size = 1,
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_TRNG_STATE,
	};

	res = imx_ele_call(&msg);
	if (res)
		return res;

	memcpy(&rsp, msg.data.u8, sizeof(rsp));

	if (rsp.trng_state != IMX_ELE_TRNG_STATUS_READY)
		return TEE_ERROR_BUSY;
	else
		return TEE_SUCCESS;
}

unsigned long plat_get_aslr_seed(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint64_t timeout = timeout_init_us(10 * 1000);
	struct rng_get_random_cmd {
		uint32_t addr_msb;
		uint32_t addr_lsb;
		uint32_t size;
		uint32_t crc;
	} cmd = { };
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_RNG_GET,
	};
	unsigned long aslr __aligned(CACHELINE_SIZE) = 0;

	/*
	 * This function can only be called when the MMU is off. No
	 * virtual/physical address translation is performed, nor cache
	 * maintenance.
	 */
	assert(!cpu_mmu_enabled());

	reg_pair_from_64((uint64_t)&aslr, &cmd.addr_msb, &cmd.addr_lsb);
	cmd.size = sizeof(aslr);

	/*
	 * Check the current TRNG state of the ELE. The TRNG must be
	 * started with a command earlier in the boot to allow the TRNG
	 * to generate enough entropy.
	 */
	while (imx_ele_rng_get_trng_state() == TEE_ERROR_BUSY)
		if (timeout_elapsed(timeout))
			panic("ELE RNG is busy");

	memcpy(msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&msg);

	res = imx_ele_call(&msg);
	if (res)
		panic("Cannot retrieve random data from ELE");

	return aslr;
}

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	uint32_t session_handle = 0;
	/*
	 * The die ID must be cached because some board configuration prevents
	 * the MU to be used by OPTEE at runtime.
	 */
	static struct session_get_device_info_rsp rsp;

	if (rsp.rsp_code)
		goto out;

	if (imx_ele_session_open(&session_handle))
		goto err;

	if (imx_ele_session_get_device_info(session_handle, &rsp))
		goto err;

	if (imx_ele_session_close(session_handle))
		goto err;

out:
	/*
	 * In the device info array return by the ELE, the words 2, 3, 4 and 5
	 * are the device UID.
	 */
	memcpy(buffer, rsp.chip_uid, MIN(sizeof(rsp.chip_uid), len));

	return 0;
err:
	panic("Fail to get the device UID");
}

#if defined(CFG_MX93)
TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const char pattern[16] __aligned(CACHELINE_SIZE) = "TEE_for_HUK_ELE";
	static uint8_t key[CACHELINE_SIZE] __aligned(CACHELINE_SIZE);
	static bool is_fetched;
	uint32_t msb = 0;
	uint32_t lsb = 0;
	struct key_derive_cmd {
		uint32_t key_addr_msb;
		uint32_t key_addr_lsb;
		uint32_t ctx_addr_msb;
		uint32_t ctx_addr_lsb;
		uint16_t key_size;
		uint16_t ctx_size;
		uint32_t crc;
	} __packed cmd = { };
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_BASELINE,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_DERIVE_KEY,
	};

	if (is_fetched)
		goto out;

	/*
	 * Intermediate msb and lsb values are needed. Directly using
	 * key_addr_msb and key_addr_lsb might be unaligned because of the
	 * __packed attribute of key_derive_cmd {}
	 */
	reg_pair_from_64((uint64_t)virt_to_phys(key), &msb, &lsb);

	cmd.key_addr_lsb = lsb;
	cmd.key_addr_msb = msb;
	cmd.key_size = HW_UNIQUE_KEY_LENGTH;

	reg_pair_from_64((uint64_t)virt_to_phys((void *)pattern), &msb, &lsb);

	cmd.ctx_addr_lsb = lsb;
	cmd.ctx_addr_msb = msb;
	cmd.ctx_size = sizeof(pattern);

	memcpy(msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&msg);

	cache_operation(TEE_CACHEFLUSH, key, HW_UNIQUE_KEY_LENGTH);
	cache_operation(TEE_CACHECLEAN, (void *)pattern, sizeof(pattern));

	res = imx_ele_call(&msg);
	if (res)
		panic("failed to get the huk");

	cache_operation(TEE_CACHEINVALIDATE, key, HW_UNIQUE_KEY_LENGTH);
	is_fetched = true;
out:
	memcpy(hwkey->data, key,
	       MIN(sizeof(key), (size_t)HW_UNIQUE_KEY_LENGTH));

	return TEE_SUCCESS;
}
#endif /* CFG_MX93 */
