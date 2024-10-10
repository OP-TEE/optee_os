/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>

#include <TpmProfile.h>
#include <trace.h>
#include <TpmProfile.h>
#include <TpmAlgorithmDefines.h>
#include <GpMacros.h>
#include <fTPM.h>
#include <Capabilities.h>
#include <fTPM_helpers.h>
#include <fTPM_event_log.h>
#include <fTPM_event_log_private.h>


#ifdef EVENT_LOG_LEVEL
#undef EVENT_LOG_LEVEL
#endif

#ifdef LOG_LEVEL
#undef LOG_LEVEL
#endif

#define EVENT_LOG_LEVEL 1
#define LOG_LEVEL 1

#if LOG_LEVEL >= EVENT_LOG_LEVEL

/*
 * Print TCG_EfiSpecIDEventStruct
 *
 * @param[in/out] log_addr	Pointer to Event Log
 * @param[in/out] log_size	Pointer to Event Log size
 */
static void id_event_print(uint8_t **log_addr, size_t *log_size)
{
	unsigned int i;
	uint8_t info_size, *info_size_ptr;
	void *ptr = *log_addr;
	id_event_headers_t *event = (id_event_headers_t *)ptr;
	id_event_algorithm_size_t *alg_ptr;
	uint32_t event_size, number_of_algorithms;
	size_t digest_len;
	const uint8_t *end_ptr = *log_addr + *log_size;
	char str_buf[1024];

	assert(*log_size >= sizeof(id_event_headers_t));

	/* The fields of the event log header are defined to be PCRIndex of 0,
	 * EventType of EV_NO_ACTION, Digest of 20 bytes of 0, and
	 * Event content defined as TCG_EfiSpecIDEventStruct.
	 */
	MSG("TCG_EfiSpecIDEvent:\n");
	MSG("  PCRIndex           : %u\n", event->header.pcr_index);
	MSG("  EventType          : %u\n", event->header.event_type);
	str_buf[0] = 0;
	snprintf(str_buf, 1024, "  Digest             :");
	for (i = 0U; i < sizeof(event->header.digest); ++i) {
		uint8_t val = event->header.digest[i];

		snprintf(str_buf, 1024, "%s %02x", str_buf, val);
		if ((i & U(0xF)) == 0U) {
			MSG("%s\n", str_buf);
			str_buf[0] = 0;
			snprintf(str_buf, 1024, "\t\t\t   :");
		}
	}
	MSG("%s\n", str_buf);
	str_buf[0] = 0;

	/* EventSize */
	event_size = event->header.event_size;
	MSG("  EventSize          : %u\n", event_size);

	MSG("  Signature          : %s\n",
			event->struct_header.signature);
	MSG("  PlatformClass      : %u\n",
			event->struct_header.platform_class);
	MSG("  SpecVersion        : %u.%u.%u\n",
			event->struct_header.spec_version_major,
			event->struct_header.spec_version_minor,
			event->struct_header.spec_errata);
	MSG("  UintnSize          : %u\n",
			event->struct_header.uintn_size);

	/* NumberOfAlgorithms */
	number_of_algorithms = event->struct_header.number_of_algorithms;
	MSG("  NumberOfAlgorithms : %u\n", number_of_algorithms);

	/* Address of DigestSizes[] */
	alg_ptr = event->struct_header.digest_size;

	/* Size of DigestSizes[] */
	digest_len = number_of_algorithms * sizeof(id_event_algorithm_size_t);

	assert(((uint8_t *)alg_ptr + digest_len) <= end_ptr);

	MSG("  DigestSizes        :\n");
	for (i = 0U; i < number_of_algorithms; ++i) {
		snprintf(str_buf, 1024, "    #%u AlgorithmId   : SHA", i);
		uint16_t algorithm_id = alg_ptr[i].algorithm_id;

		switch (algorithm_id) {
		case TPM_ALG_SHA256:
			snprintf(str_buf, 1024, "%s256\n", str_buf);
			break;
		case TPM_ALG_SHA384:
			snprintf(str_buf, 1024, "%s384\n", str_buf);
			break;
		case TPM_ALG_SHA512:
			snprintf(str_buf, 1024, "%s512\n", str_buf);
			break;
		default:
			snprintf(str_buf, 1024, "%s?\n", str_buf);
			EMSG("Algorithm 0x%x not found\n", algorithm_id);
			assert(false);
		}

		MSG("%s", str_buf);
		MSG("       DigestSize    : %u\n",
					alg_ptr[i].digest_size);
		str_buf[0] = 0;
	}

	/* Address of VendorInfoSize */
	info_size_ptr = (uint8_t *)alg_ptr + digest_len;
	assert(info_size_ptr <= end_ptr);

	info_size = *info_size_ptr++;
	MSG("  VendorInfoSize     : %u\n", info_size);

	/* Check VendorInfo end address */
	assert((info_size_ptr + info_size) <= end_ptr);

	/* Check EventSize */
	assert(event_size == (sizeof(id_event_struct_t) +
				digest_len + info_size));
	if (info_size != 0U) {
		snprintf(str_buf, 1024, "  VendorInfo         :");
		for (i = 0U; i < info_size; ++i) {
			snprintf(str_buf, 1024, "%s %02x", str_buf,
							*info_size_ptr++);
		}
		MSG("%s\n", str_buf);
		str_buf[0] = 0;
	}

	*log_size -= (uintptr_t)info_size_ptr - (uintptr_t)*log_addr;
	*log_addr = info_size_ptr;
}

/*
 * Print TCG_PCR_EVENT2
 *
 * @param[in/out] log_addr	Pointer to Event Log
 * @param[in/out] log_size	Pointer to Event Log size
 */
static void event2_print(uint8_t **log_addr, size_t *log_size)
{
	uint32_t event_size, count;
	size_t sha_size, digests_size = 0U;
	void *ptr = *log_addr;
	char str_buf[1024];

	const uint8_t *end_ptr = *log_addr + *log_size;

	assert(*log_size >= sizeof(event2_header_t));

	MSG("PCR_Event2:\n");
	MSG("  PCRIndex           : %u\n",
			((event2_header_t *)ptr)->pcr_index);
	MSG("  EventType          : %u\n",
			((event2_header_t *)ptr)->event_type);

	count = ((event2_header_t *)ptr)->digests.count;
	MSG("  Digests Count      : %u\n", count);

	/* Address of TCG_PCR_EVENT2.Digests[] */
	ptr = (uint8_t *)ptr + sizeof(event2_header_t);
	assert(((uintptr_t)ptr <= (uintptr_t)end_ptr) && (count != 0U));

	str_buf[0] = 0;
	for (unsigned int i = 0U; i < count; ++i) {
		/* Check AlgorithmId address */
		assert(((uint8_t *)ptr + offsetof(tpmt_ha, digest)) <= end_ptr);

		snprintf(str_buf, 1024, "    #%u AlgorithmId   : SHA", i);
		switch (((tpmt_ha *)ptr)->algorithm_id) {
		case TPM_ALG_SHA256:
			sha_size = SHA256_DIGEST_SIZE;
			snprintf(str_buf, 1024, "%s256\n", str_buf);
			break;
		case TPM_ALG_SHA384:
			sha_size = SHA384_DIGEST_SIZE;
			snprintf(str_buf, 1024, "%s384\n", str_buf);
			break;
		case TPM_ALG_SHA512:
			sha_size = SHA512_DIGEST_SIZE;
			snprintf(str_buf, 1024, "%s512\n", str_buf);
			break;
		default:
			snprintf(str_buf, 1024, "%s?\n", str_buf);
			EMSG("Algorithm 0x%x not found\n",
				((tpmt_ha *)ptr)->algorithm_id);
			assert(true);
		}
		MSG("%s", str_buf);
		str_buf[0] = 0;

		/* End of Digest[] */
		ptr = (uint8_t *)ptr + offsetof(tpmt_ha, digest);
		assert(((uint8_t *)ptr + sha_size) <= end_ptr);

		/* Total size of all digests */
		digests_size += sha_size;

		snprintf(str_buf, 1024, "       Digest        :");
		for (unsigned int j = 0U; j < sha_size; ++j) {
			snprintf(str_buf, 1024, "%s %02x", str_buf,
							*(uint8_t *)ptr++);
			if ((j & U(0xF)) == U(0xF)) {
				MSG("%s\n", str_buf);
				str_buf[0] = 0;
				if (j < (sha_size - 1U)) {
					snprintf(str_buf, 1024, "\t\t\t   :");
				}
			}
		}
	}

	/* TCG_PCR_EVENT2.EventSize */
	assert(((uint8_t *)ptr + offsetof(event2_data_t, event)) <= end_ptr);

	event_size = ((event2_data_t *)ptr)->event_size;
	MSG("  EventSize          : %u\n", event_size);

	/* Address of TCG_PCR_EVENT2.Event[EventSize] */
	ptr = (uint8_t *)ptr + offsetof(event2_data_t, event);

	/* End of TCG_PCR_EVENT2.Event[EventSize] */
	assert(((uint8_t *)ptr + event_size) <= end_ptr);

	if ((event_size == sizeof(startup_locality_event_t)) &&
	     (strcmp((const char *)ptr, TCG_STARTUP_LOCALITY_SIGNATURE) == 0)) {
		MSG("  Signature          : %s\n",
			((startup_locality_event_t *)ptr)->signature);
		MSG("  StartupLocality    : %u\n",
			((startup_locality_event_t *)ptr)->startup_locality);
	} else {
		MSG("  Event              : %s\n", (uint8_t *)ptr);
	}

	*log_size -= (uintptr_t)ptr + event_size - (uintptr_t)*log_addr;
	*log_addr = (uint8_t *)ptr + event_size;
}
#endif	/* LOG_LEVEL >= EVENT_LOG_LEVEL */

/*
 * Print Event Log
 *
 * @param[in]	log_addr	Pointer to Event Log
 * @param[in]	log_size	Event Log size
 */
void dump_event_log(uint8_t *log_addr, size_t log_size)
{
#if LOG_LEVEL >= EVENT_LOG_LEVEL
	assert(log_addr != NULL);

	/* Print TCG_EfiSpecIDEvent */
	id_event_print(&log_addr, &log_size);

	while (log_size != 0U) {
		event2_print(&log_addr, &log_size);
	}
#endif
}
