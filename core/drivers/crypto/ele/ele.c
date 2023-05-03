// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023, 2025 NXP
 */
#include <drivers/imx_mu.h>
#include <ele.h>
#include <initcall.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <memutils.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <rng_support.h>
#include <stdint.h>
#include <string_ext.h>
#include <tee/cache.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <types_ext.h>
#include <utee_types.h>
#include <util.h>

#define ELE_BASE_ADDR MU_BASE
#define ELE_BASE_SIZE MU_SIZE

#define ELE_VERSION_BASELINE 0x06
#define ELE_COMMAND_SUCCEED 0xd6
#define ELE_COMMAND_FAILED  0x29
#define ELE_RESPONSE_TAG    0xe1

#define ELE_CMD_SESSION_OPEN	    0x10
#define ELE_CMD_SESSION_CLOSE	    0x11
#define ELE_CMD_RNG_GET		    0xCD
#define ELE_CMD_TRNG_STATE	    0xA4
#define ELE_CMD_GET_INFO	    0xDA
#define ELE_CMD_DERIVE_KEY	    0xA9
#define ELE_CMD_SAB_INIT	    0x17

#define IMX_ELE_TRNG_STATUS_READY 0x3

#define ELE_MU_IRQ 0x0

#define CACHELINE_SIZE 64

register_phys_mem_pgdir(MEM_AREA_IO_SEC, MU_BASE, MU_SIZE);

struct get_info_rsp {
	uint32_t rsp_code;
	uint16_t soc_id;
	uint16_t soc_rev;
	uint16_t lifecycle;
	uint8_t sssm_state;
	uint8_t unused_1;
	uint32_t uid[4];
	uint32_t sha256_rom_patch[8];
	uint32_t sha256_firmware[8];
	uint32_t oem_srkh[16];
	uint8_t trng_state;
	uint8_t csal_state;
	uint8_t imem_state;
	uint8_t unused_2;
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

void update_crc(struct imx_mu_msg *msg)
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

TEE_Result imx_ele_call(struct imx_mu_msg *msg)
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
 * Open a session with EdgeLock Enclave. It returns a session handle.
 *
 * @session_handle EdgeLock Enclave session handle
 */
static TEE_Result __maybe_unused imx_ele_session_open(uint32_t *session_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct open_session_cmd {
		uint8_t rsvd1;
		uint8_t interrupt_num;
		uint16_t rsvd2;
		uint8_t priority;
		uint8_t op_mode;
		uint16_t rsvd3;
	} __packed cmd = {
		.rsvd1 = 0,
		.interrupt_num = ELE_MU_IRQ,
		.rsvd2 = 0,
		.priority = 0,
		.op_mode = 0,
		.rsvd3 = 0,
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
static TEE_Result __maybe_unused imx_ele_session_close(uint32_t session_handle)
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

static TEE_Result imx_ele_get_device_info(struct get_info_rsp *rsp)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct imx_ele_buf output = { };
	struct {
		uint32_t addr_msb;
		uint32_t addr_lsb;
		uint16_t size;
	} __packed cmd = { };
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_BASELINE,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_GET_INFO,
	};

	if (!rsp)
		return TEE_ERROR_BAD_PARAMETERS;

	res = imx_ele_buf_alloc(&output, NULL, sizeof(*rsp));
	if (res)
		goto out;

	cmd.addr_msb = output.paddr_msb;
	cmd.addr_lsb = output.paddr_lsb;
	cmd.size = sizeof(*rsp);

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	res = imx_ele_call(&msg);
	if (res)
		goto out;

	res = imx_ele_buf_copy(&output, (uint8_t *)rsp, sizeof(*rsp));
out:
	imx_ele_buf_free(&output);

	return res;
}

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	static uint32_t uid[4];
	static bool is_fetched;
	struct get_info_rsp rsp = { };

	assert(buffer && len);

	if (!is_fetched) {
		if (imx_ele_get_device_info(&rsp))
			panic("Fail to get the device UID");

		memcpy(uid, rsp.uid, MIN(sizeof(rsp.uid), len));
		is_fetched = true;
	}

	memcpy(buffer, uid, MIN(sizeof(uid), len));

	return 0;
}

/*
 * Initialize EdgeLock Enclave services
 */
static TEE_Result imx_ele_sab_init(void)
{
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = 1,
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SAB_INIT,
	};

	return imx_ele_call(&msg);
}

driver_init(imx_ele_sab_init);

#if defined(CFG_MX93) || defined(CFG_MX91)
static TEE_Result imx_ele_derive_key(const uint8_t *ctx, size_t ctx_size,
				     uint8_t *key, size_t key_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
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
	struct imx_ele_buf ele_ctx = { };
	struct imx_ele_buf ele_key = { };

	assert(ctx && key);

	if (key_size != 16 && key_size != 32)
		return TEE_ERROR_BAD_PARAMETERS;

	res = imx_ele_buf_alloc(&ele_ctx, ctx, ctx_size);
	if (res)
		goto out;

	res = imx_ele_buf_alloc(&ele_key, key, key_size);
	if (res)
		goto out;

	cmd.key_addr_lsb = ele_key.paddr_lsb;
	cmd.key_addr_msb = ele_key.paddr_msb;
	cmd.key_size = key_size;

	cmd.ctx_addr_lsb = ele_ctx.paddr_lsb;
	cmd.ctx_addr_msb = ele_ctx.paddr_msb;
	cmd.ctx_size = ctx_size;

	memcpy(msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&msg);

	res = imx_ele_call(&msg);
	if (res)
		goto out;

	res = imx_ele_buf_copy(&ele_key, key, key_size);
out:
	imx_ele_buf_free(&ele_key);
	imx_ele_buf_free(&ele_ctx);

	return res;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	static const char pattern[] = "TEE_for_HUK_ELE";
	static uint8_t key[HW_UNIQUE_KEY_LENGTH];
	static bool is_fetched;

	if (is_fetched)
		goto out;

	if (imx_ele_derive_key((const uint8_t *)pattern, sizeof(pattern), key,
			       sizeof(key)))
		panic("Fail to get HUK from ELE");

	is_fetched = true;
out:
	memcpy(hwkey->data, key,
	       MIN(sizeof(key), (size_t)HW_UNIQUE_KEY_LENGTH));

	return TEE_SUCCESS;
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

/*
 * Get random data from the EdgeLock Enclave.
 *
 * This function can be called when the MMU is off or on.
 * virtual/physical address translation and cache maintenance
 * is performed if needed.
 *
 * @buffer: data output
 * @size: RNG data size
 */
static TEE_Result imx_ele_rng_get_random(uint8_t *buffer, size_t size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct imx_ele_buf rng = { };
	struct rng_get_random_cmd {
		uint32_t addr_msb;
		uint32_t addr_lsb;
		uint32_t size;
	} cmd = { };
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_RNG_GET,
	};

	if (!buffer || !size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (cpu_mmu_enabled()) {
		res = imx_ele_buf_alloc(&rng, NULL, size);
		if (res != TEE_SUCCESS)
			return res;

		cmd.addr_msb = rng.paddr_msb;
		cmd.addr_lsb = rng.paddr_lsb;
	} else {
		paddr_t pa = (paddr_t)buffer;

		if (!IS_ALIGNED_WITH_TYPE(pa, uint32_t))
			return TEE_ERROR_BAD_PARAMETERS;

		reg_pair_from_64((uint64_t)pa, &cmd.addr_msb, &cmd.addr_lsb);
	}

	cmd.size = (uint32_t)size;

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	res = imx_ele_call(&msg);
	if (res)
		goto out;

	if (cpu_mmu_enabled())
		res = imx_ele_buf_copy(&rng, buffer, size);
out:
	imx_ele_buf_free(&rng);

	return res;
}

unsigned long plat_get_aslr_seed(void)
{
	uint64_t timeout = timeout_init_us(10 * 1000);
	unsigned long __aligned(CACHELINE_SIZE) aslr = 0;

	/*
	 * Check the current TRNG state of the ELE. The TRNG must be
	 * started with a command earlier in the boot to allow the TRNG
	 * to generate enough entropy.
	 */
	while (imx_ele_rng_get_trng_state() == TEE_ERROR_BUSY)
		if (timeout_elapsed(timeout))
			panic("ELE RNG is busy");

	if (imx_ele_rng_get_random((uint8_t *)&aslr, sizeof(aslr)))
		panic("Cannot retrieve random data from ELE");

	return aslr;
}

#ifndef CFG_WITH_SOFTWARE_PRNG
TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	return imx_ele_rng_get_random((uint8_t *)buf, len);
}
#endif /* CFG_WITH_SOFTWARE_PRNG */
#endif /* CFG_MX93 || CFG_MX91 */
