// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include <config.h>
#include <kernel/misc.h>
#include <mm/core_memprot.h>
#include <sbi.h>
#include <sbi_mpxy.h>
#include <string.h>
#include <tee_api_types.h>
#include <util.h>

/*
 * struct mpxy_core_local - MPXY per-hart local context
 * @shmem:       Virtual base address of MPXY shared memory
 * @shmem_pa:    Physical base address of MPXY shared memory
 * @shmem_size:  Size in bytes of MPXY shared memory
 * @shmem_active:Indicates whether shared memory is active for this hart
 *
 * Holds MPXY-related per-hart data required for message exchange via
 * the SBI MPXY extension.
 */
struct mpxy_core_local {
	void *shmem;
	paddr_t shmem_pa;
	unsigned long shmem_size;
	bool shmem_active;
};

static struct mpxy_core_local mpxy_core_local_array[CFG_TEE_CORE_NB_CORE];
static bool mpxy_available;

static struct mpxy_core_local *mpxy_get_core_local(void)
{
	struct mpxy_core_local *mpxy = NULL;
	uint32_t hart_id = 0;

	assert((thread_get_exceptions() & THREAD_EXCP_ALL) == THREAD_EXCP_ALL);

	hart_id = thread_get_hartid();

	mpxy = &mpxy_core_local_array[hart_id];

	return mpxy;
}

/**
 * sbi_mpxy_is_available - Check whether the SBI MPXY extension was probed
 *
 * Return: true if sbi_mpxy_init() found the extension, false otherwise.
 */
bool sbi_mpxy_is_available(void)
{
	return mpxy_available;
}

/**
 * sbi_mpxy_init - Probe the MPXY extension and set up shared memory
 *
 * Must be called once on every hart, after the heap is usable. The first
 * caller probes the SBI implementation for the MPXY extension; every caller
 * then registers per-hart shared memory. Safe to call again on a hart that
 * already has shared memory registered.
 *
 * Return: SBI_SUCCESS on success, SBI_ERR_NOT_SUPPORTED if the extension is
 * absent, other negative SBI error code on failure.
 */
int sbi_mpxy_init(void)
{
	static bool probed;
	int ret = SBI_SUCCESS;

	if (!probed) {
		mpxy_available = sbi_probe_extension(SBI_EXT_MPXY) > 0;
		probed = true;
		if (!mpxy_available)
			IMSG("SBI MPXY extension not available");
	}

	if (!mpxy_available)
		return SBI_ERR_NOT_SUPPORTED;

	ret = sbi_mpxy_set_shmem();
	if (ret)
		EMSG("MPXY shared memory setup failed on core %zu: %d",
		     get_core_pos(), ret);

	return ret;
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

	if (!mpxy_available)
		return SBI_ERR_NOT_SUPPORTED;

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
 * Queries the shared memory size required by the SBI implementation,
 * allocates a region of that size aligned to its own size, and registers
 * it with the SBI MPXY extension for the calling hart. This memory is used
 * for sending and receiving messages.
 *
 * Return: SBI_SUCCESS on success, negative SBI error code on failure.
 */
int sbi_mpxy_set_shmem(void)
{
	struct mpxy_core_local *mpxy = NULL;
	struct sbiret sbiret = {};
	unsigned long shmem_size = 0;
	unsigned long shmem_phys_lo = 0;
	unsigned long shmem_phys_hi = 0;
	void *shmem = NULL;
	uint32_t exceptions = 0;
	int ret = SBI_ERR_FAILURE;

	ret = sbi_mpxy_get_shmem_size(&shmem_size);
	if (ret)
		return ret;

	/*
	 * The SBI spec requires shmem_size to be a multiple of 4 KiB and
	 * the region to be aligned to shmem_size.
	 */
	if (!shmem_size || shmem_size < SMALL_PAGE_SIZE ||
	    !IS_POWER_OF_TWO(shmem_size))
		return SBI_ERR_INVALID_PARAM;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	mpxy = mpxy_get_core_local();

	if (mpxy->shmem_active) {
		ret = SBI_SUCCESS;
		goto out;
	}

	shmem = memalign(shmem_size, shmem_size);
	if (!shmem) {
		ret = SBI_ERR_FAILURE;
		goto out;
	}
	memset(shmem, 0, shmem_size);

	mpxy->shmem = shmem;
	mpxy->shmem_pa = virt_to_phys(shmem);
	mpxy->shmem_size = shmem_size;

	/*
	 * On RV64 the whole physical address goes in shmem_phys_lo and
	 * shmem_phys_hi is unused. On RV32 the address is split.
	 */
	if (IS_ENABLED(CFG_RV32_core)) {
		shmem_phys_lo = low32_from_64(mpxy->shmem_pa);
		shmem_phys_hi = high32_from_64(mpxy->shmem_pa);
	} else {
		shmem_phys_lo = mpxy->shmem_pa;
	}

	sbiret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SET_SHMEM,
			   shmem_phys_lo, shmem_phys_hi,
			   SBI_MPXY_SHMEM_FLAG_OVERWRITE);
	if (sbiret.error) {
		EMSG("MPXY SET_SHMEM failed: error=%ld", sbiret.error);
		free(shmem);
		memset(mpxy, 0, sizeof(*mpxy));
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
 * sbi_mpxy_disable_shmem - Disable MPXY shared memory on the current hart
 *
 * Tells the SBI implementation to stop using the shared memory registered
 * for this hart and releases the memory.
 *
 * Return: SBI_SUCCESS on success, negative SBI error code on failure.
 */
int sbi_mpxy_disable_shmem(void)
{
	struct mpxy_core_local *mpxy = NULL;
	struct sbiret sbiret = {};
	uint32_t exceptions = 0;
	int ret = SBI_SUCCESS;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	mpxy = mpxy_get_core_local();
	if (!mpxy->shmem_active)
		goto out;

	sbiret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SET_SHMEM,
			   SBI_MPXY_SHMEM_DISABLE, SBI_MPXY_SHMEM_DISABLE,
			   SBI_MPXY_SHMEM_FLAG_OVERWRITE);
	if (sbiret.error) {
		EMSG("MPXY SET_SHMEM (disable) failed: error=%ld",
		     sbiret.error);
		ret = sbiret.error;
		goto out;
	}

	free(mpxy->shmem);
	memset(mpxy, 0, sizeof(*mpxy));

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

	if (attribute_count > mpxy->shmem_size / sizeof(uint32_t)) {
		ret = SBI_ERR_INVALID_PARAM;
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

	if (attribute_count > mpxy->shmem_size / sizeof(uint32_t)) {
		ret = SBI_ERR_INVALID_PARAM;
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
	if (!response && max_response_len)
		return SBI_ERR_INVALID_PARAM;
	if (response_len)
		*response_len = 0;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	mpxy = mpxy_get_core_local();

	if (!mpxy->shmem_active) {
		ret = SBI_ERR_NO_SHMEM;
		goto out;
	}

	if (message_len > mpxy->shmem_size) {
		ret = SBI_ERR_INVALID_PARAM;
		goto out;
	}

	if (message_len)
		memcpy(mpxy->shmem, message, message_len);

	sbiret = sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SEND_MSG_WITH_RESP,
			   channel_id, message_id, message_len, 0, 0, 0);
	if (sbiret.error) {
		EMSG("MPXY SBI call failed: error=%ld", sbiret.error);
		ret = sbiret.error;
		goto out;
	}

	/* Never trust a returned length larger than our own shared memory */
	response_bytes = sbiret.value;
	if (response_bytes > mpxy->shmem_size) {
		ret = SBI_ERR_FAILURE;
		goto out;
	}

	if (response) {
		if (response_bytes > max_response_len) {
			ret = SBI_ERR_INVALID_PARAM;
			goto out;
		}

		memcpy(response, mpxy->shmem, response_bytes);
		if (response_len)
			*response_len = response_bytes;
	}

	ret = SBI_SUCCESS;

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

	if (message_len > mpxy->shmem_size) {
		ret = SBI_ERR_INVALID_PARAM;
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
 * @max_events_data_len: Size in bytes of the events_data area of @notif_data
 * @events_data_len: Pointer to store length of events data in bytes
 *
 * Makes an SBI call to fetch notification events from the specified channel
 * and copies the notification header and events data from shared memory
 * into the provided buffer. @notif_data must have room for the header plus
 * @max_events_data_len bytes.
 *
 * Return: SBI_SUCCESS on success, negative SBI error code on failure.
 */
int
sbi_mpxy_get_notification_events(uint32_t channel_id,
				 struct sbi_mpxy_notification_data *notif_data,
				 unsigned long max_events_data_len,
				 unsigned long *events_data_len)
{
	struct mpxy_core_local *mpxy = NULL;
	unsigned long events_bytes = 0;
	struct sbiret sbiret = {};
	uint32_t exceptions = 0;
	int ret = SBI_ERR_FAILURE;

	if (!notif_data || !events_data_len)
		return SBI_ERR_INVALID_PARAM;

	*events_data_len = 0;

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

	events_bytes = sbiret.value;
	if (events_bytes > max_events_data_len ||
	    events_bytes > mpxy->shmem_size - sizeof(*notif_data)) {
		ret = SBI_ERR_INVALID_PARAM;
		goto out;
	}

	memcpy(notif_data, mpxy->shmem, sizeof(*notif_data) + events_bytes);
	*events_data_len = events_bytes;
	ret = SBI_SUCCESS;

out:
	thread_unmask_exceptions(exceptions);
	return ret;
}

/**
 * sbi_mpxy_to_tee_result - Convert an SBI error code to a TEE_Result
 * @sbi_err: Return value from one of the sbi_mpxy_* functions
 *
 * Return: The closest matching TEE_Result.
 */
TEE_Result sbi_mpxy_to_tee_result(int sbi_err)
{
	switch (sbi_err) {
	case SBI_SUCCESS:
		return TEE_SUCCESS;
	case SBI_ERR_NOT_SUPPORTED:
		return TEE_ERROR_NOT_SUPPORTED;
	case SBI_ERR_INVALID_PARAM:
	case SBI_ERR_INVALID_ADDRESS:
	case SBI_ERR_BAD_RANGE:
		return TEE_ERROR_BAD_PARAMETERS;
	case SBI_ERR_DENIED:
	case SBI_ERR_DENIED_LOCKED:
		return TEE_ERROR_ACCESS_DENIED;
	case SBI_ERR_NO_SHMEM:
	case SBI_ERR_INVALID_STATE:
	case SBI_ERR_ALREADY_AVAILABLE:
	case SBI_ERR_ALREADY_STARTED:
	case SBI_ERR_ALREADY_STOPPED:
		return TEE_ERROR_BAD_STATE;
	case SBI_ERR_TIMEOUT:
		return TEE_ERROR_TIMEOUT;
	case SBI_ERR_IO:
		return TEE_ERROR_COMMUNICATION;
	default:
		return TEE_ERROR_GENERIC;
	}
}
