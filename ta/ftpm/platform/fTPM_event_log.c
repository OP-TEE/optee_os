/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdbool.h>
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

/*
 * Global variables.
 */
static bool log_extended = false;
static id_event_struct_header_t *event_header_ptr;

static int check_header_digest(const unsigned char *const digest)
{
    /*
     * Checks the header digest according to section 5.3 of
     * TCG EFI Protocol Specification. Family 2.0. Level 00 Revision 00.13
     * March 30, 2016.
     */

    unsigned int i;

    for (i = 0U; i < HEADER_DIGEST_SIZE; i++) {
        if (digest[i] != 0) {
            return 0;
        }
    }

    return 1;
}

/*
 * Function to process a TPM event log header.
 *
 * @buf_index Offset where the header is expected to start in the event log.
 * @buf Pointer to a buffer where the TPM event log is.
 * @log_size Size of the TPM event log.
 *
 * The function returns the offset on the event log after the header.
 */
static unsigned int process_header(unsigned int buf_index,
				   const unsigned char *const buf,
                                   const size_t log_size)
{
    uint32_t event_size;
    uint32_t digest_size;
    uint8_t vendor_info_size;

    if (buf_index + sizeof(tcg_pcr_event_t) + sizeof(id_event_struct_header_t)
                                                            >= log_size) {
#ifdef fTPMDebug
        EMSG("TPM Event log header extends beyond the scope of the event log buffer\n");
#endif
    }

    /*
     * Check PcrIndex.
     */
    if (*((uint32_t *)(buf + buf_index)) != 0U) {
        /*
         * PCR Index must be 0 on the header.
         * Ref. Section 5.3 of TCG EFI Protocol Specification. Family 2.0
         * Level 00 Revision 00.13. March 30, 2016
         */
        return 0U;
    }
    buf_index += sizeof(uint32_t);

    /*
     * Check EventType
     */
    if (*((uint32_t *)(buf + buf_index)) != EV_NO_ACTION) {
        /*
         * Event type must be EV_NO_ACTION on the header.
         * Ref. Section 5.3 of TCG EFI Protocol Specification. Family 2.0
         * Level 00 Revision 00.13. March 30, 2016
         */
        return 0U;
    }
    buf_index += sizeof(uint32_t);

    if (!check_header_digest(buf + buf_index)) {
        return 0U;
    }

    buf_index += HEADER_DIGEST_SIZE;

    memcpy(&event_size, buf + buf_index, sizeof(event_size));
    buf_index += sizeof(event_size);

    event_header_ptr = (id_event_struct_header_t *)(buf + buf_index);

    buf_index += sizeof(id_event_struct_header_t);

    digest_size = (event_header_ptr->number_of_algorithms *
                        sizeof(id_event_algorithm_size_t));

    if (buf_index + digest_size >= log_size) {
#ifdef fTPMDebug
        EMSG("TPM Event log header extends beyond the scope of the event log buffer\n");
#endif
        event_header_ptr = NULL;
        return 0U;
    }

    buf_index += digest_size;

    if (buf_index + sizeof(vendor_info_size) >= log_size) {
#ifdef fTPMDebug
        EMSG("TPM Event log header extends beyond the scope of the event log buffer\n");
#endif
        event_header_ptr = NULL;
        return 0U;
    }

    memcpy(&vendor_info_size, buf + buf_index, sizeof(vendor_info_size));

    if (digest_size + vendor_info_size + sizeof(vendor_info_size) +
                                         sizeof(id_event_struct_header_t) != event_size) {
#ifdef fTPMDebug
        EMSG("The parsed event size does not match the event size on the header\n");
#endif
        return 0U;
    }

    buf_index += sizeof(vendor_info_size);

    if (buf_index + vendor_info_size > log_size) {
#ifdef fTPMDebug
        EMSG("Event size larger than the log size\n");
#endif
        event_header_ptr = NULL;
        return 0U;
    }

    /*
     * Skips the vendor info.
     */
    buf_index += vendor_info_size;

    return buf_index;
}

/*
 * Function to proccess (and extend) an event from the TPM event log.
 *
 * @buf_index Offset where the event is expected to start in the event log.
 * @buf Pointer to a buffer where the TPM event log is.
 * @log_size Size of the TPM event log.
 *
 * The function returns the offset of the next event in the TPM event log
 * or 0 if fails.
 */
static unsigned int process_event(unsigned int buf_index,
                                  const unsigned char *const buf,
                                  const size_t log_size)
{
    TPM2_PCR_EXTEND_COMMAND cmd;
    unsigned char *digest_array;
    uint32_t count;
    uint32_t event_size;
    uint16_t alg_id;
    unsigned int digest_size;
    unsigned int i;
    unsigned char *response;
    uint32_t resplen;
    event2_header_t event;
    void *cmd_end = (void *)(&cmd + 1);

    if (buf_index + sizeof(event2_header_t) >= log_size) {
#ifdef fTPMDebug
        EMSG("Event header size larger than the log size\n");
#endif
        return 0U;
    }

    memcpy(&event, buf + buf_index, sizeof(event2_header_t));
    buf_index += sizeof(event2_header_t);

    if (event.digests.count > HASH_COUNT) {
#ifdef fTPMDebug
        EMSG("Number of digests on this event exceeds the maximum allowed\n");
#endif
        return 0U;
    }

    memset(&cmd, 0, sizeof(TPM2_PCR_EXTEND_COMMAND));

    cmd.Header.paramSize = sizeof(cmd.PcrHandle) +
                                  sizeof(cmd.AuthorizationSize) +
                                  sizeof(cmd.Header);

    cmd.PcrHandle = SwapBytes32(event.pcr_index);

    cmd.Header.commandCode = SwapBytes32(TPM_PCR_EXTEND);
    cmd.Header.tag = SwapBytes16(TPM_ST_SESS);

    /*
     * We are not using authorization sessions in this prototype code so
     * populate the auth session info based on how it is handled in
     * CopyAuthSessionCommand() with a NULL auth session. See
     * SecurityPkg/Library/Tpm2CommandLib/Tpm2Help.c in EDK2.
     */
    cmd.AuthSessionPcr.sessionHandle = SwapBytes32(TPM_RS_PW);
    cmd.AuthSessionPcr.nonce.b.size = 0U;
    *((uint8_t *)&cmd.AuthSessionPcr.sessionAttributes) = 0U;
    cmd.AuthSessionPcr.hmac.b.size = 0U;
    cmd.AuthorizationSize = SwapBytes32(AUTH_SIZE);
    cmd.Header.paramSize += (AUTH_SIZE);

    /*
     * As we are not using authorization sessions for this prototype,
     * AuthSessionPcr is empty and therefore the digests are allocated
     * straight after the empty AuthSessionPcr structure, so make the
     * pointer for the digests to point right after the empty
     * AuthSessionPcr structure.
     */
    digest_array = ((uint8_t *)&cmd.AuthSessionPcr) + AUTH_SIZE;

    /*
     * Populate the digest.
     */
    count = SwapBytes32(event.digests.count);
    memcpy(digest_array, &count, sizeof(count));
    digest_array += sizeof(count);

    cmd.Header.paramSize += sizeof(count);

    for (i = 0U; i < event.digests.count; i++) {
        unsigned int j;

        if (buf_index + sizeof(alg_id) >= log_size) {
            return 0U;
        }
        memcpy(&alg_id, buf + buf_index, sizeof(alg_id));
        alg_id = SwapBytes16(alg_id);
        buf_index += sizeof(alg_id);
        /*
         * Algorithm ID.
         */
        if ((void *)(digest_array + sizeof(alg_id)) >= cmd_end) {
#ifdef fTPMDebug
            EMSG("Not enough space for digest %u of %u\n", i,
                                                event.digests.count);
#endif
            return 0U;
        }
        memcpy(digest_array, &alg_id, sizeof(alg_id));
        digest_array += sizeof(alg_id);
        cmd.Header.paramSize += sizeof(alg_id);

        for (j = 0U; j < event_header_ptr->number_of_algorithms; j++) {
            if (SwapBytes16(alg_id) ==
                    event_header_ptr->digest_size[i].algorithm_id) {
                digest_size = event_header_ptr->digest_size[i].digest_size;
                break;
            }
        }

        if (j > event_header_ptr->number_of_algorithms) {
#ifdef fTPMDebug
            EMSG("Algorithm ID %i not found\n", alg_id);
#endif
            return 0U;
        }

        cmd.Header.paramSize += digest_size;

        if (buf_index + digest_size >= log_size ||
            digest_size > (sizeof(TPMT_HA) - sizeof(TPMI_ALG_HASH))) {
            /*
             * Sanity check: If the log extends beyond the
	         * maximum size of the log buffer or if the digest is
	         * bigger than the allocated space on the command structure, abort.
             */
#ifdef fTPMDebug
            EMSG("Log extends beyond the maximum size of the log buffer.\n");
            EMSG("alg_id = %i\n", alg_id);
            EMSG("log_size = %i\n", log_size);
            EMSG("buf_index = %i, digest_size = %i\n", buf_index, digest_size);
            EMSG("TPMH_HA = %i\n", sizeof(TPMT_HA));
            EMSG("TPMI_ALG_HASH = %i\n", sizeof(TPMI_ALG_HASH));
#endif
            return 0U;
        }
        memcpy(digest_array, buf + buf_index, digest_size);
        digest_array += digest_size;
        buf_index += digest_size;
    }

    cmd.Header.paramSize = SwapBytes32(cmd.Header.paramSize);

    if (buf_index + sizeof(event2_data_t) > log_size) {
        return 0U;
    }
    memcpy(&event_size, buf + buf_index, sizeof(event_size));
    buf_index += sizeof(event_size);
    buf_index += event_size;

    if (buf_index > log_size) {
#ifdef fTPMDebug
        EMSG("The event log extends beyond the log buffer:");
        EMSG("\tbuf_index = %i, log_size = %i\n", buf_index, log_size);
#endif
        return 0U;
    }

    resplen = 1024;
    response = (unsigned char *)malloc(resplen);

    if (response == NULL) {
#ifdef fTPMDebug
        EMSG("Not enough memory to allocate a response\n");
#endif
        return 0U;
    }

    memset(response, 0, resplen);

    ExecuteCommand(SwapBytes32(cmd.Header.paramSize), &cmd,
                               &resplen, &response);

#ifdef fTPMDebug
    uint16_t ret_tag;
    uint32_t resp_size;
    uint32_t tpm_rc;

    memcpy(&ret_tag, response, sizeof(ret_tag));
    memcpy(&resp_size, response + sizeof(ret_tag), sizeof(resp_size));
    memcpy(&tpm_rc, response + sizeof(ret_tag) + sizeof(resp_size),
           sizeof(tpm_rc));

    MSG("TPM2_PCR_EXTEND_COMMAND returned value:\n");
    MSG("\tret_tag = 0x%.4x, size = 0x%.8x, rc = 0x%.8x\n",
         SwapBytes16(ret_tag), SwapBytes32(resp_size), SwapBytes32(tpm_rc));
#endif

    free(response);

    return buf_index;
}

bool process_eventlog(const unsigned char *const buf, const size_t log_size)
{
    unsigned int buf_index = 0U;
    unsigned int event_count = 0U;

    if (log_extended == true) {
#ifdef fTPMDebug
        MSG("The event log has already been extended. Ignoring\n");
#endif
        return false;
    }

    log_extended = true;
    buf_index = process_header(buf_index, buf, log_size);
    if (buf_index == 0) {
#ifdef fTPMDebug
        EMSG("Fail to process TPM event log header. Skiping.\n");
#endif
        return false;
    }

    while (buf_index < log_size) {
        /*
         * Process the rest of the Event Log.
         */
        buf_index = process_event(buf_index, buf, log_size);
        event_count++;
    }

#ifdef fTPMDebug
    MSG("%i Event logs processed\n", event_count);
#endif

    event_header_ptr = NULL;

    return true;
}
