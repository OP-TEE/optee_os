/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef DRIVERS_QCOM_TME_TME_INTF_H
#define DRIVERS_QCOM_TME_TME_INTF_H

#include <drivers/qcom/tme/tme_intf_defs.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * TME use case interface: one function per TME use case. Each function builds
 * the request of its use case, exchanges it with the TME and returns the
 * decoded response. Every function blocks until the TME has answered, so it
 * can only be called from a thread context.
 */

/*
 * tme_fuse_read() - QFPROM fuse read
 *
 * Reading from RAW address directly is not supported on wildcat targets.
 * Clients can still pass the 'raw address' in conjunction with
 * TME_QFPROM_ADDR_SPACE_CORR so that the qfprom driver will do the RAW -> CORR
 * address mapping and read from corrected space.
 *
 * @addr_type:          Fuse address space (TME_QFPROM_ADDR_SPACE_*)
 * @fuse_addr:          SoC address of the QFPROM row to read
 * @fuse_data:          Receives the row contents, low word first. Must point
 *                      to space for at least TME_QFPROM_FUSE_DATA_WORDS
 *                      uint32_t values - a QFPROM row is always read two words
 *                      at a time, regardless of the width of interest.
 * @qfprom_api_status:  Status reported by the qfprom driver of the TME,
 *                      TME_QFPROM_NO_ERR on a clean read. Written only when
 *                      the call returns TEE_SUCCESS.
 *
 * Return TEE_SUCCESS if the exchange completed and the response was the
 * expected size, TEE_ERROR_BAD_PARAMETERS if @fuse_data or @qfprom_api_status
 * is NULL, or another TEE_Result error code otherwise.
 *
 * NOTE: TEE_SUCCESS only means that the request/response exchange succeeded.
 * The caller MUST also check @qfprom_api_status - the TME reports a rejected
 * or failed fuse read there, not in the return value.
 */
TEE_Result tme_fuse_read(TmeQfpromAddrSpace_t addr_type, uint32_t fuse_addr,
			 uint32_t *const fuse_data,
			 uint32_t *const qfprom_api_status);

/*
 * tme_fuse_write_multiple() - blow up to TME_MAX_FUSE_WRITE_REQ QFPROM rows in
 * a single request via the TME.
 *
 * ###########################################################################
 * # DESTRUCTIVE AND IRREVERSIBLE. QFPROM fuses are one-time-programmable:   #
 * # any bit set in fuse_array[].data[] is blown permanently on real silicon #
 * # and can never be cleared. Blowing the wrong row can brick the part or   #
 * # lock it out of secure boot.                                             #
 * #                                                                         #
 * # An all-zero data[] blows nothing, which is what makes it safe to use    #
 * # for exercising this path without altering chip state.                   #
 * ###########################################################################
 *
 * @fuse_array:         Rows to write. Not modified.
 * @fuse_array_len:     Number of entries in @fuse_array, must be in
 *                      1..TME_MAX_FUSE_WRITE_REQ.
 * @qfprom_api_status:  Status reported by the TME for the write,
 *                      TME_QFPROM_NO_ERR on success. Always written once the
 *                      arguments validate - set to TME_QFPROM_STATUS_UNSET
 *                      before the exchange.
 *
 * Return TEE_SUCCESS only if the exchange completed, the response was the
 * expected size, AND the TME reported TME_QFPROM_NO_ERR.
 * Return TEE_ERROR_BAD_PARAMETERS for invalid arguments,
 * TEE_ERROR_EXCESS_DATA for too many rows, or another TEE_Result error code
 * for a failed exchange or a rejected write.
 *
 * NOTE: unlike tme_fuse_read(), a nonzero status is folded into the return
 * value here, so TEE_SUCCESS does mean the write itself was accepted.
 */
TEE_Result tme_fuse_write_multiple(TMEFuse_t *fuse_array,
				   size_t fuse_array_len,
				   uint32_t *const qfprom_api_status);

/*
 * tme_write_config_register() - write a QFPROM configuration register via the
 * TME.
 *
 * @register_id:  Register to write (QFPROM_BIST_CTRL,
 *                QFPROM_WRITE_DISABLE_STICKY_BIT0/1).
 * @value:        Value to write into the register.
 *
 * Return TEE_SUCCESS if the exchange completed, the response was the expected
 * size, AND the TME reported a zero status, or another TEE_Result error code
 * otherwise.
 */
TEE_Result tme_write_config_register(tmeConfigRegisterId_e register_id,
				     uint32_t value);

/*
 * tme_update_rollback_version() - tell the TME to commit the recorded image
 * versions into the antirollback (ARB) fuses.
 *
 * ###########################################################################
 * # DESTRUCTIVE AND IRREVERSIBLE. This blows antirollback fuses, which are  #
 * # one-time-programmable: once the TME has raised the stored ARB version   #
 * # for an image, that part will permanently refuse to boot any older       #
 * # versioned build of it. There is no "undo" and no non-destructive dry    #
 * # run - unlike tme_fuse_write_multiple(), there is no payload to zero     #
 * # out, because the TME chooses the fuses itself from versions it          #
 * # recorded during authentication.                                         #
 * #                                                                         #
 * # Do NOT call this from a boot-time probe or self-test.                   #
 * ###########################################################################
 *
 * Until this is called, the TME caches version information instead of
 * committing it. Afterwards it also updates the rollback version as part of
 * signature verification for images authenticated later (e.g. modem). The TME
 * FW tracks that this call was made, so it is a one-time transition per boot.
 *
 * The intended single call site is the point at which the current boot is
 * declared good: at cold boot when A/B OTA is disabled, or, when A/B OTA is
 * enabled, only after HLOS has signalled a successful boot. Calling it before
 * that defeats the purpose of A/B rollback.
 *
 * Return TEE_SUCCESS if the exchange completed, the response was the expected
 * size, AND the TME reported a zero status, or another TEE_Result error code
 * otherwise.
 */
TEE_Result tme_update_rollback_version(void);

#endif /* DRIVERS_QCOM_TME_TME_INTF_H */
