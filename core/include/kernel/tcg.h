/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 *
 * This file refers the following TCG specification.
 * TCG PC Client Platform Firmware Profile Specification
 */

#ifndef __KERNEL_TCG_H__
#define __KERNEL_TCG_H__

#include <tee_api_types.h>
#include <tpm2.h>

#define TPM2_EVENT_LOG_SIZE		4096

/*
 * SHA1 Event Log Entry Format
 *
 * @pcr_index:  PCRIndex event extended to
 * @event_type: Type of event (see EFI specs)
 * @digest:     Value extended into PCR index
 * @event_size: Size of event
 * @event:      Event data
 */
struct tcg_pcr_event {
	uint32_t pcr_index;
	uint32_t event_type;
	uint8_t digest[TPM2_SHA1_DIGEST_SIZE];
	uint32_t event_size;
	uint8_t event[];
};

/*
 * Crypto Agile Log Entry Format
 *
 * @pcr_index:	PCRIndex event extended to
 * @event_type:	Type of event
 * @digests:	List of digests extended to PCR index
 * @event_size: Size of the event data
 * @event:	Event data
 */
struct tcg_pcr_event2 {
	uint32_t pcr_index;
	uint32_t event_type;
	struct tpml_digest_values digests;
	uint32_t event_size;
	uint8_t event[];
} __packed;

#define TCG_EFI_SPEC_ID_EVENT_SIGNATURE_03 "Spec ID Event03"
#define TCG_EFI_SPEC_ID_EVENT_SPEC_VERSION_MAJOR_TPM2 2
#define TCG_EFI_SPEC_ID_EVENT_SPEC_VERSION_MINOR_TPM2 0
#define TCG_EFI_SPEC_ID_EVENT_SPEC_VERSION_ERRATA_TPM2 2

/*
 *  struct TCG_EfiSpecIdEventAlgorithmSize - hashing algorithm information
 *
 *  @algorithm_id:	algorithm defined in enum tpm2_algorithms
 *  @digest_size:	size of the algorithm
 */
struct tcg_efi_spec_id_event_algorithm_size {
	uint16_t      algorithm_id;
	uint16_t      digest_size;
};

/**
 * struct TCG_EfiSpecIDEventStruct - content of the event log header
 *
 * @signature:                  signature, set to Spec ID Event03
 * @platform_class:             class defined in TCG ACPI Specification
 *                              Client  Common Header.
 * @spec_version_minor:         minor version
 * @spec_version_major:         major version
 * @spec_errata:                major version
 * @uintn_size:                 size of the efi_uintn_t fields used in various
 *                              data structures used in this specification.
 *                              0x01 indicates uint32_t and 0x02 indicates
 *                              uint64_t
 * @number_of_algorithms:       hashing algorithms used in this event log
 * @digest_sizes:               array of number_of_algorithms pairs
 *                              1st member defines the algorithm id
 *                              2nd member defines the algorithm size
 */
struct tcg_efi_spec_id_event {
	uint8_t signature[16];
	uint32_t platform_class;
	uint8_t spec_version_minor;
	uint8_t spec_version_major;
	uint8_t spec_errata;
	uint8_t uintn_size;
	uint32_t number_of_algorithms;
	struct tcg_efi_spec_id_event_algorithm_size digest_sizes[];
} __packed;

/*
 * event types, cf.
 * "TCG Server Management Domain Firmware Profile Specification",
 * rev 1.00, 2020-05-01
 */
#define EV_NO_ACTION			U(0x00000003)

struct tcg_pcr_ops {
	/*
	 * pcr_info() - get the supported, active PCRs and number of banks
	 *
	 * @selection_mask:	bitmask with the algorithms supported
	 * @active_mask:	bitmask with the active algorithms
	 * @num_pcr:		number of PCR banks
	 *
	 */
	TEE_Result (*pcr_info)(uint32_t *selection_mask, uint32_t *active_mask,
			       uint32_t *num_pcr);
	/*
	 * pcr_extend() - Extend a PCR for a given tpml_digest_values
	 *
	 * @pcr_idx:		PCR Index
	 * @alg:		algorithm of digest
	 * @digest:		buffer containing the digest
	 * @digest_len:		length of the buffer
	 *
	 * @Return: status code
	 */
	TEE_Result (*pcr_extend)(uint8_t pcr_idx, uint16_t alg, void *digest,
				 uint32_t digest_len);
};

#if defined(CFG_CORE_TCG_PROVIDER)

/*
 * Eventlog is the informational record of measurements. These measurements
 * need to be extended to PCR's if the firmware passing the evenlog has
 * not done so. The function parses the TPM evenlog information received
 * from earlier firmware and extends the PCRs. The device supporting the
 * PCRs needs to be registered with the TCG framework.
 */
TEE_Result tcg_process_fw_eventlog(void);

/*
 * TCG PC Client Platform Firmware profile Specification talks about
 * eventlogging. These eventlogs need to be extended into PCR's. The PCRs
 * are available with TPM's. There may be other HSM's which may support PCRs.
 * The HSM's or TPM needs to provide interface to get PCR info and extend the
 * digests into PCR's. The platform needs to register the PCR providers
 * with the TCG framework.
 */
TEE_Result register_tcg_pcr_provider(struct tcg_pcr_ops *ops);

#else

static inline TEE_Result tcg_process_fw_eventlog(void)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result
register_tcg_pcr_provider(struct tcg_pcr_ops *ops __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

#endif

#endif /* __KERNEL_TCG_H__ */
