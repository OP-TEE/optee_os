// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022, 2025 NXP
 */

#include <riscv.h>
#include <sbi.h>
#include <kernel/misc.h>
#include <mm/core_memprot.h>
#include <string.h>

struct sbiret {
	long error;
	long value;
};

#define _sbi_ecall(ext, fid, arg0, arg1, arg2, arg3, arg4, arg5, ...) ({  \
	register unsigned long a0 asm("a0") = (unsigned long)arg0; \
	register unsigned long a1 asm("a1") = (unsigned long)arg1; \
	register unsigned long a2 asm("a2") = (unsigned long)arg2; \
	register unsigned long a3 asm("a3") = (unsigned long)arg3; \
	register unsigned long a4 asm("a4") = (unsigned long)arg4; \
	register unsigned long a5 asm("a5") = (unsigned long)arg5; \
	register unsigned long a6 asm("a6") = (unsigned long)fid;  \
	register unsigned long a7 asm("a7") = (unsigned long)ext;  \
	asm volatile ("ecall" \
		: "+r" (a0), "+r" (a1) \
		: "r" (a2), "r" (a3), "r" (a4), "r" (a5), "r"(a6), "r"(a7) \
		: "memory"); \
	(struct sbiret){ .error = a0, .value = a1 }; \
})

#define sbi_ecall(...) _sbi_ecall(__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0)

/**
 * sbi_probe_extension() - Check if an SBI extension ID is supported or not.
 * @extid: The extension ID to be probed.
 *
 * Return: 1 or an extension specific nonzero value if yes, 0 otherwise.
 */
int sbi_probe_extension(int extid)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE_EXT, extid);
	if (!ret.error)
		return ret.value;

	return 0;
}

/**
 * sbi_console_putchar() - Writes given character to the console device.
 * @ch: The data to be written to the console.
 */
void sbi_console_putchar(int ch)
{
	sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, ch);
}

/**
 * sbi_dbcn_write_byte() - Write byte to debug console
 * @ch:         Byte to be written
 *
 * Return:      SBI error code (SBI_SUCCESS = 0 on success)
 */
int sbi_dbcn_write_byte(unsigned char ch)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_WRITE_BYTE, ch);
	return ret.error;
}

/**
 * sbi_hsm_hart_start() - Start target hart at OP-TEE entry in S-mode
 * @hartid:     Target hart ID
 * @start_addr: Physical address of OP-TEE entry
 * @arg:        opaque parameter, typically used as the physical
 *              address of device-tree passed via @arg->a1
 *
 * Return:      SBI error code (SBI_SUCCESS = 0 on success)
 */
int sbi_hsm_hart_start(uint32_t hartid, paddr_t start_addr, unsigned long arg)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_START, hartid, start_addr,
			arg);

	return ret.error;
}

/**
 * sbi_hsm_hart_get_status() - Get the current HSM state of given hart
 * @hartid:         Target hart ID
 * @status:         Pointer to store HSM state
 *
 * Return:          SBI error code (SBI_SUCCESS = 0 on success)
 */
int sbi_hsm_hart_get_status(uint32_t hartid, enum sbi_hsm_hart_state *status)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_GET_STATUS, hartid);

	if (ret.error)
		return ret.error;

	*status = ret.value;
	return SBI_SUCCESS;
}

/* MPXY Per-HART or local context */
struct mpxy_core_local {
	/* Shared memory base address */
	void *shmem;
	/* Shared memory physical address */
	paddr_t shmem_pa;
	/* Flag representing whether shared memory is active or not */
	bool shmem_active;
};

static struct mpxy_core_local mpxy_core_local_array[CFG_TEE_CORE_NB_CORE];

static struct mpxy_core_local *mpxy_get_core_local(void)
{
	struct mpxy_core_local *mpxy = NULL;
	size_t pos = get_core_pos();
	uint32_t hart_id = thread_get_hartid_by_hartindex(pos);

	mpxy = &mpxy_core_local_array[hart_id];

	return mpxy;
}

/**
 * sbi_mpxy_get_shmem_size - Retrieve the MPXY shared memory size
 * @shmem_size: Pointer to store the shared memory size in bytes
 *
 * Makes an SBI call to query the shared memory size used for
 * sending and receiving messages via the MPXY extension.
 *
 * Return: 0 on success, negative SBI error code on failure.
 */
int sbi_mpxy_get_shmem_size(unsigned long *shmem_size)
{
	struct sbiret ret = {};

	ret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_SHMEM_SIZE, 0, 0, 0, 0,
			0, 0);
	if (ret.error) {
		EMSG("MPXY SBI call failed: error=%ld value=%ld", ret.error,
		     ret.value);
		return ret.error;
	}

	if (shmem_size)
		*shmem_size = ret.value;

	return SBI_SUCCESS;
}

/**
 * sbi_mpxy_set_shmem - Set up MPXY shared memory on the current hart
 *
 * Allocates and registers a 4 KiB shared memory region, aligned to 4 KiB,
 * as required by the MPXY extension. This memory is used for sending and
 * receiving messages. Registers the shared memory with the SBI MPXY extension.
 *
 * Return: SBI_SUCCESS on success, negative SBI error code on failure.
 */
int sbi_mpxy_set_shmem(void)
{
	struct mpxy_core_local *mpxy = mpxy_get_core_local();
	struct sbiret ret = {};
	void *shmem = NULL;

	if (mpxy->shmem_active)
		return SBI_ERR_FAILURE;

	shmem = memalign(SMALL_PAGE_SIZE, SMALL_PAGE_SIZE);
	if (!shmem)
		return SBI_ERR_FAILURE;

	mpxy->shmem = shmem;
	mpxy->shmem_pa = virt_to_phys(shmem);

	ret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SET_SHMEM, mpxy->shmem_pa, 0,
			0);
	if (ret.error) {
		EMSG("MPXY SBI call failed: error=%ld value=%ld", ret.error,
		     ret.value);
		free(shmem);
		return SBI_ERR_FAILURE;
	}

	mpxy->shmem_active = true;

	return SBI_SUCCESS;
}

/**
 * sbi_mpxy_get_channel_ids - Retrieve MPXY channel IDs
 * @channel_count: Number of channels expected
 * @channel_ids: Buffer to store the retrieved channel IDs
 *
 * Uses the SBI MPXY extension to query the list of available channel IDs
 * into the provided buffer.
 *
 * Return: SBI_SUCCESS on success, negative SBI error code on failure.
 */
int sbi_mpxy_get_channel_ids(uint32_t channel_count, uint32_t *channel_ids)
{
	struct mpxy_core_local *mpxy = mpxy_get_core_local();
	struct sbi_mpxy_channel_ids_data *sdata = mpxy->shmem;
	uint32_t remaining = 0;
	uint32_t returned = 0;
	uint32_t count = 0;
	uint32_t start_index = 0;
	struct sbiret ret = {};
	uint32_t exceptions = 0;

	if (!mpxy->shmem_active)
		return SBI_ERR_INVALID_PARAM;

	if (!channel_count || !channel_ids)
		return SBI_ERR_INVALID_PARAM;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	do {
		ret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_CHANNEL_IDS,
				start_index, 0, 0, 0, 0, 0);
		if (ret.error) {
			EMSG("MPXY SBI call failed: error=%ld value=%ld",
			     ret.error, ret.value);
			goto out;
		}

		remaining = sdata->remaining;
		returned = sdata->returned;

		count = returned < (channel_count - start_index) ?
				returned :
				(channel_count - start_index);
		memcpy(&channel_ids[start_index], sdata->channel_array,
		       count * sizeof(uint32_t));
		start_index += count;
	} while (remaining && start_index < channel_count);

out:
	thread_unmask_exceptions(exceptions);
	return ret.error;
}

/**
 * sbi_mpxy_read_attributes - Read attributes from an MPXY channel
 * @channel_id: ID of the channel
 * @base_attribute_id: Starting attribute ID
 * @attribute_count: Number of attributes to read
 * @attribute_buf: Buffer to store the read attribute values
 *
 * Makes an SBI call to read attributes from the specified channel and copies
 * the values from shared memory into the provided buffer.
 *
 * Return: SBI_SUCCESS on success, negative SBI error code on failure.
 */
int sbi_mpxy_read_attributes(uint32_t channel_id, uint32_t base_attribute_id,
			     uint32_t attribute_count, void *attribute_buf)
{
	struct mpxy_core_local *mpxy = mpxy_get_core_local();
	struct sbiret ret = {};
	uint32_t exceptions = 0;

	if (!attribute_count || !attribute_buf)
		return SBI_ERR_INVALID_PARAM;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	ret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_READ_ATTRS, channel_id,
			base_attribute_id, attribute_count, 0, 0, 0);
	if (!ret.error)
		memcpy(attribute_buf, (void *)mpxy->shmem,
		       attribute_count * sizeof(uint32_t));
	else
		EMSG("MPXY SBI call failed: error=%ld value=%ld", ret.error,
		     ret.value);

	thread_unmask_exceptions(exceptions);
	return ret.error;
}

/**
 * sbi_mpxy_write_attributes - Write attributes to an MPXY channel
 * @channel_id: ID of the channel to write attributes to
 * @base_attribute_id: Starting attribute ID
 * @attribute_count: Number of attributes to write
 * @attributes_buf: Buffer containing the attribute values
 *
 * Copies the attribute values into shared memory and makes an SBI call to
 * write them to the specified channel.
 *
 * Return: SBI_SUCCESS on success, negative SBI error code on failure.
 */
int sbi_mpxy_write_attributes(uint32_t channel_id, uint32_t base_attribute_id,
			      uint32_t attribute_count,
			      uint32_t *attributes_buf)
{
	struct mpxy_core_local *mpxy = mpxy_get_core_local();
	struct sbiret ret = {};
	uint32_t exceptions = 0;

	if (!mpxy->shmem_active)
		return SBI_ERR_NO_SHMEM;

	if (!attribute_count || !attributes_buf)
		return SBI_ERR_INVALID_PARAM;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	memcpy(mpxy->shmem, attributes_buf, attribute_count * sizeof(uint32_t));

	ret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_WRITE_ATTRS, channel_id,
			base_attribute_id, attribute_count, 0, 0, 0);

	if (ret.error)
		EMSG("MPXY SBI call failed: error=%ld value=%ld", ret.error,
		     ret.value);

	thread_unmask_exceptions(exceptions);
	return ret.error;
}

/**
 * sbi_mpxy_send_message_with_response - Send a message and receive response
 * via MPXY
 * @channel_id: ID of the channel
 * @message_id: ID of the message
 * @message: Pointer to transmit buffer (can be NULL if message_len is 0)
 * @message_len: Length of transmit buffer in bytes
 * @response: Pointer to receive buffer
 * @max_response_len: Maximum size of receive buffer in bytes
 * @response_len: Pointer to store length of received data
 *
 * Copies transmit data into shared memory and makes an SBI call to send
 * the message and receive a response. Copies the received response into
 * the provided receive buffer.
 *
 * Return: SBI_SUCCESS on success, negative SBI error code on failure.
 */
int sbi_mpxy_send_message_with_response(uint32_t channel_id,
					uint32_t message_id, void *message,
					unsigned long message_len,
					void *response,
					unsigned long max_response_len,
					unsigned long *response_len)
{
	struct mpxy_core_local *mpxy = mpxy_get_core_local();
	unsigned long response_bytes = 0;
	struct sbiret ret = {};
	uint32_t exceptions = 0;

	if (!mpxy->shmem_active)
		return SBI_ERR_NO_SHMEM;

	if (!message && message_len)
		return SBI_ERR_INVALID_PARAM;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	if (message_len)
		memcpy(mpxy->shmem, message, message_len);

	ret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SEND_MSG_WITH_RESP,
			channel_id, message_id, message_len, 0, 0, 0);
	if (response && !ret.error) {
		response_bytes = ret.value;
		if (response_bytes > max_response_len) {
			thread_unmask_exceptions(exceptions);
			return SBI_ERR_INVALID_PARAM;
		}

		memcpy(response, mpxy->shmem, response_bytes);
		if (response_len)
			*response_len = response_bytes;
	}

	if (ret.error)
		EMSG("MPXY SBI call failed: error=%ld value=%ld", ret.error,
		     ret.value);

	thread_unmask_exceptions(exceptions);
	return ret.error;
}

/**
 * sbi_mpxy_send_message_without_response - Send a message via MPXY without
 * expecting a response
 * @channel_id: ID of the channel
 * @message_id: Message ID
 * @message: Pointer to transmit buffer (may be NULL if message_len is 0)
 * @message_len: Number of bytes to send
 *
 * Copies transmit data into shared memory and makes an SBI call to send the
 * message without waiting for a response.
 *
 * Return: SBI_SUCCESS on success, negative SBI error code on failure.
 */
int sbi_mpxy_send_message_without_response(uint32_t channel_id,
					   uint32_t message_id, void *message,
					   unsigned long message_len)
{
	struct mpxy_core_local *mpxy = mpxy_get_core_local();
	struct sbiret ret = {};
	uint32_t exceptions = 0;

	if (!mpxy->shmem_active)
		return SBI_ERR_NO_SHMEM;

	if (!message && message_len)
		return SBI_ERR_INVALID_PARAM;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	if (message_len)
		memcpy(mpxy->shmem, message, message_len);

	ret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SEND_MSG_WITHOUT_RESP,
			channel_id, message_id, message_len, 0, 0, 0);

	if (ret.error)
		EMSG("MPXY SBI call failed: error=%ld value=%ld", ret.error,
		     ret.value);

	thread_unmask_exceptions(exceptions);
	return ret.error;
}

/**
 * sbi_mpxy_get_channel_count - Get the total number of MPXY channels
 * @channel_count: Pointer to store the total number of channels
 *
 * Makes an SBI call to retrieve the number of channels by reading
 * the remaining and returned fields from the shared memory structure.
 *
 * Return: SBI_SUCCESS on success, negative SBI error code on failure.
 */
int sbi_mpxy_get_channel_count(uint32_t *channel_count)
{
	struct mpxy_core_local *mpxy = mpxy_get_core_local();
	struct sbi_mpxy_channel_ids_data *sdata = mpxy->shmem;
	uint32_t remaining = 0;
	uint32_t returned = 0;
	struct sbiret ret = {};
	uint32_t exceptions = 0;

	if (!mpxy->shmem_active)
		return SBI_ERR_NO_SHMEM;

	if (!channel_count)
		return SBI_ERR_INVALID_PARAM;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	ret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_CHANNEL_IDS, 0, 0, 0, 0,
			0, 0);
	if (ret.error) {
		EMSG("MPXY SBI call failed: error=%ld value=%ld", ret.error,
		     ret.value);
		goto out;
	}

	remaining = sdata->remaining;
	returned = sdata->returned;
	*channel_count = remaining + returned;

out:
	thread_unmask_exceptions(exceptions);
	return ret.error;
}

/**
 * sbi_mpxy_get_notification_events - Retrieve notification events from an
 * MPXY channel
 * @channel_id: ID of the channel
 * @notif_data: Pointer to buffer to store notification data
 * @events_data_len: Pointer to store length of events data in bytes
 *
 * Makes an SBI call to fetch notification events from the specified channel
 * and copies them from shared memory into the provided buffer.
 *
 * Return: SBI_SUCCESS on success, negative SBI error code on failure.
 */
int
sbi_mpxy_get_notification_events(uint32_t channel_id,
				 struct sbi_mpxy_notification_data *notif_data,
				 unsigned long *events_data_len)
{
	struct mpxy_core_local *mpxy = mpxy_get_core_local();
	struct sbiret ret = {};
	uint32_t exceptions = 0;

	if (!mpxy->shmem_active)
		return SBI_ERR_NO_SHMEM;

	if (!notif_data || !events_data_len)
		return SBI_ERR_INVALID_PARAM;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	ret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_NOTIFICATION_EVENTS,
			channel_id, 0, 0, 0, 0, 0);
	if (ret.error) {
		EMSG("MPXY SBI call failed: error=%ld value=%ld", ret.error,
		     ret.value);
		goto out;
	}

	memcpy(notif_data, mpxy->shmem, ret.value + 16);
	*events_data_len = ret.value;

out:
	thread_unmask_exceptions(exceptions);
	return ret.error;
}
