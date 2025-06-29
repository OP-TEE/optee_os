// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2025 NXP
 */

#include <kernel/misc.h>
#include <mm/core_memprot.h>
#include <sbi.h>
#include <sbi_mpxy.h>
#include <string.h>

/*
 * struct mpxy_core_local - MPXY per-hart local context
 * @shmem:       Virtual base address of MPXY shared memory
 * @shmem_pa:    Physical base address of MPXY shared memory
 * @shmem_active:Indicates whether shared memory is active for this hart
 *
 * Holds MPXY-related per-hart data required for message exchange via
 * the SBI MPXY extension.
 */
struct mpxy_core_local {
	void *shmem;
	paddr_t shmem_pa;
	bool shmem_active;
};

static struct mpxy_core_local mpxy_core_local_array[CFG_TEE_CORE_NB_CORE];

static struct mpxy_core_local *mpxy_get_core_local(void)
{
	struct mpxy_core_local *mpxy = NULL;
	size_t pos = 0;
	uint32_t hart_id = 0;

	assert((thread_get_exceptions() & THREAD_EXCP_ALL) == THREAD_EXCP_ALL);

	pos = get_core_pos();
	hart_id = thread_get_hartid_by_hartindex(pos);

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
	struct sbiret sbiret = {};

	sbiret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_SHMEM_SIZE, 0, 0, 0,
			   0, 0, 0);
	if (sbiret.error) {
		EMSG("MPXY SBI call failed: error=%ld value=%ld", sbiret.error,
		     sbiret.value);
		return sbiret.error;
	}

	if (shmem_size)
		*shmem_size = sbiret.value;

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
	struct mpxy_core_local *mpxy = NULL;
	struct sbiret sbiret = {};
	void *shmem = NULL;
	uint32_t exceptions = 0;
	int ret = SBI_ERR_FAILURE;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	mpxy = mpxy_get_core_local();
	if (mpxy->shmem_active)
		goto out;

	shmem = memalign(SMALL_PAGE_SIZE, SMALL_PAGE_SIZE);
	if (!shmem)
		goto out;

	mpxy->shmem = shmem;
	mpxy->shmem_pa = virt_to_phys(shmem);

	sbiret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SET_SHMEM, mpxy->shmem_pa,
			   0, 0);
	if (sbiret.error) {
		EMSG("MPXY SBI call failed: error=%ld", sbiret.error);
		free(shmem);
		ret = sbiret.error;
		goto out;
	}

	mpxy->shmem_active = true;

	ret = SBI_SUCCESS;

out:
	thread_unmask_exceptions(exceptions);
	return ret;
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
	struct mpxy_core_local *mpxy = NULL;
	struct sbi_mpxy_channel_ids_data *data = NULL;
	uint32_t remaining = 0;
	uint32_t returned = 0;
	uint32_t count = 0;
	uint32_t start_index = 0;
	struct sbiret sbiret = {};
	uint32_t exceptions = 0;

	if (!channel_count || !channel_ids)
		return SBI_ERR_INVALID_PARAM;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	mpxy = mpxy_get_core_local();

	if (!mpxy->shmem_active) {
		sbiret.error = SBI_ERR_NO_SHMEM;
		goto out;
	}

	data = mpxy->shmem;

	do {
		sbiret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_CHANNEL_IDS,
				   start_index, 0, 0, 0, 0, 0);
		if (sbiret.error) {
			EMSG("MPXY SBI call failed: error=%ld", sbiret.error);
			goto out;
		}

		remaining = data->remaining;
		returned = data->returned;

		count = returned < (channel_count - start_index) ?
				returned :
				(channel_count - start_index);
		memcpy(&channel_ids[start_index], data->channel_array,
		       count * sizeof(uint32_t));
		start_index += count;
	} while (remaining && start_index < channel_count);

out:
	thread_unmask_exceptions(exceptions);
	return sbiret.error;
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
	struct mpxy_core_local *mpxy = NULL;
	struct sbiret sbiret = {};
	uint32_t exceptions = 0;
	int ret = SBI_ERR_FAILURE;

	if (!attribute_count || !attribute_buf)
		return SBI_ERR_INVALID_PARAM;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	mpxy = mpxy_get_core_local();

	if (!mpxy->shmem_active) {
		ret = SBI_ERR_NO_SHMEM;
		goto out;
	}

	sbiret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_READ_ATTRS, channel_id,
			   base_attribute_id, attribute_count, 0, 0, 0);
	if (!sbiret.error)
		memcpy(attribute_buf, (void *)mpxy->shmem,
		       attribute_count * sizeof(uint32_t));
	else
		EMSG("MPXY SBI call failed: error=%ld", sbiret.error);

	ret = sbiret.error;
out:
	thread_unmask_exceptions(exceptions);
	return ret;
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
	struct mpxy_core_local *mpxy = NULL;
	struct sbiret sbiret = {};
	uint32_t exceptions = 0;
	int ret = SBI_ERR_FAILURE;

	if (!attribute_count || !attributes_buf)
		return SBI_ERR_INVALID_PARAM;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	mpxy = mpxy_get_core_local();

	if (!mpxy->shmem_active) {
		ret = SBI_ERR_NO_SHMEM;
		goto out;
	}

	memcpy(mpxy->shmem, attributes_buf, attribute_count * sizeof(uint32_t));

	sbiret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_WRITE_ATTRS, channel_id,
			   base_attribute_id, attribute_count, 0, 0, 0);

	if (sbiret.error)
		EMSG("MPXY SBI call failed: error=%ld", sbiret.error);

	ret = sbiret.error;
out:
	thread_unmask_exceptions(exceptions);
	return ret;
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
	struct mpxy_core_local *mpxy = NULL;
	unsigned long response_bytes = 0;
	struct sbiret sbiret = {};
	uint32_t exceptions = 0;
	int ret = SBI_ERR_FAILURE;

	if (!message && message_len)
		return SBI_ERR_INVALID_PARAM;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	mpxy = mpxy_get_core_local();

	if (!mpxy->shmem_active) {
		ret = SBI_ERR_NO_SHMEM;
		goto out;
	}

	if (message_len)
		memcpy(mpxy->shmem, message, message_len);

	sbiret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SEND_MSG_WITH_RESP,
			   channel_id, message_id, message_len, 0, 0, 0);
	if (response && !sbiret.error) {
		response_bytes = sbiret.value;
		if (response_bytes > max_response_len) {
			ret = SBI_ERR_INVALID_PARAM;
			goto out;
		}

		memcpy(response, mpxy->shmem, response_bytes);
		if (response_len)
			*response_len = response_bytes;
	}

	if (sbiret.error)
		EMSG("MPXY SBI call failed: error=%ld", sbiret.error);

	ret = sbiret.error;
out:
	thread_unmask_exceptions(exceptions);
	return ret;
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
	struct mpxy_core_local *mpxy = NULL;
	struct sbiret sbiret = {};
	uint32_t exceptions = 0;
	int ret = SBI_ERR_FAILURE;

	if (!message && message_len)
		return SBI_ERR_INVALID_PARAM;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	mpxy = mpxy_get_core_local();

	if (!mpxy->shmem_active) {
		ret = SBI_ERR_NO_SHMEM;
		goto out;
	}

	if (message_len)
		memcpy(mpxy->shmem, message, message_len);

	sbiret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SEND_MSG_WITHOUT_RESP,
			   channel_id, message_id, message_len, 0, 0, 0);

	if (sbiret.error)
		EMSG("MPXY SBI call failed: error=%ld", sbiret.error);

	ret = sbiret.error;
out:
	thread_unmask_exceptions(exceptions);
	return ret;
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
	struct mpxy_core_local *mpxy = NULL;
	struct sbi_mpxy_channel_ids_data *data = NULL;
	uint32_t remaining = 0;
	uint32_t returned = 0;
	struct sbiret sbiret = {};
	uint32_t exceptions = 0;
	int ret = SBI_ERR_FAILURE;

	if (!channel_count)
		return SBI_ERR_INVALID_PARAM;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	mpxy = mpxy_get_core_local();

	if (!mpxy->shmem_active) {
		ret = SBI_ERR_NO_SHMEM;
		goto out;
	}

	data = mpxy->shmem;

	sbiret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_CHANNEL_IDS, 0, 0, 0,
			   0, 0, 0);
	if (sbiret.error) {
		EMSG("MPXY SBI call failed: error=%ld", sbiret.error);
		goto out;
	}

	remaining = data->remaining;
	returned = data->returned;
	*channel_count = remaining + returned;

	ret = sbiret.error;

out:
	thread_unmask_exceptions(exceptions);
	return ret;
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
	struct mpxy_core_local *mpxy = NULL;
	struct sbiret sbiret = {};
	uint32_t exceptions = 0;
	int ret = SBI_ERR_FAILURE;

	if (!notif_data || !events_data_len)
		return SBI_ERR_INVALID_PARAM;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	mpxy = mpxy_get_core_local();

	if (!mpxy->shmem_active) {
		ret = SBI_ERR_NO_SHMEM;
		goto out;
	}

	sbiret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_NOTIFICATION_EVENTS,
			   channel_id, 0, 0, 0, 0, 0);
	if (sbiret.error) {
		EMSG("MPXY SBI call failed: error=%ld", sbiret.error);
		ret = sbiret.error;
		goto out;
	}

	memcpy(notif_data, mpxy->shmem, sbiret.value + 16);
	*events_data_len = sbiret.value;

	ret = sbiret.error;

out:
	thread_unmask_exceptions(exceptions);
	return ret;
}
