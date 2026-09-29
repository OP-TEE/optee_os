// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 *
 * The driver in this file is based on
 * - TCG PC Client Device Driver Design Principles for TPM 2.0
 *   Version 1.1 Revision 0.04 [DD Specification]
 * - TCG PC Client Platform TPM Profile Specification for TPM 2.0
 *   Version 1.05 Revision 14 [PTP Specification]
 */

#include <assert.h>
#include <drivers/tpm2_chip.h>
#include <drivers/tpm2_cmd.h>
#include <drivers/tpm2_ptp_fifo.h>
#include <kernel/delay.h>
#include <trace.h>

/* DD specification states that 3 is a good choice for retry count */
#define TPM2_DD_RETRY_CNT	3

static bool tpm2_fifo_check_ops(const struct tpm2_ptp_phy_ops *ops)
{
	return ops && ops->rx32 && ops->tx32 && ops->rx8 && ops->tx8;
}

/*
 * Check if tpmRegValidSts bit is set in ACCESS Register. This is required
 * during TPM initialization sequence. [Refer Figure 2 from PTP Specification]
 */
static enum tpm2_result tpm2_fifo_wait_valid(struct tpm2_chip *chip,
					     uint32_t loc)
{
	const struct tpm2_ptp_phy_ops *ops = chip->phy_ops;
	enum tpm2_result ret = TPM2_OK;
	uint64_t timeout_ref = timeout_init_us(chip->timeout_a * 1000);
	uint8_t access = 0;

	do {
		ret = ops->rx8(chip, TPM2_ACCESS(loc), sizeof(access), &access);
		if (ret)
			return ret;

		if (access & TPM2_ACCESS_VALID)
			return TPM2_OK;

		mdelay(TPM2_TIMEOUT_RETRY_MS);
	} while (!timeout_elapsed(timeout_ref));

	return TPM2_ERR_TIMEOUT;
}

/* Check if activeLocality is 1 in TPM2 ACCESS Register for that locality */
static bool tpm2_fifo_check_locality(struct tpm2_chip *chip, uint32_t loc)
{
	const struct tpm2_ptp_phy_ops *ops = chip->phy_ops;
	uint8_t locality = 0;
	enum tpm2_result ret = TPM2_OK;

	ret = ops->rx8(chip, TPM2_ACCESS(loc), sizeof(locality), &locality);
	if (ret)
		return false;

	/*
	 * Check if requested locality is active. If it has been requested for
	 * use, return false.
	 */
	if ((locality & (TPM2_ACCESS_ACTIVE_LOCALITY | TPM2_ACCESS_VALID |
			 TPM2_ACCESS_REQUEST_USE)) ==
	    (TPM2_ACCESS_ACTIVE_LOCALITY | TPM2_ACCESS_VALID))
		return true;

	return false;
}

/* Based on Figure 2 - Locality Access protocol from DD Specification */
static enum tpm2_result tpm2_fifo_request_locality(struct tpm2_chip *chip,
						   uint32_t loc)
{
	const struct tpm2_ptp_phy_ops *ops = chip->phy_ops;
	uint64_t timeout_ref = 0;
	uint8_t buf = 0;
	enum tpm2_result ret = TPM2_OK;

	if (chip->locality >= 0)
		return TPM2_ERR_BUSY;

	/* first check if locality is active FIFO.activeLocality == 1 */
	if (tpm2_fifo_check_locality(chip, loc)) {
		chip->locality = loc;
		return TPM2_OK;
	}

	/* if not get one */
	buf = TPM2_ACCESS_REQUEST_USE;
	ret = ops->tx8(chip, TPM2_ACCESS(loc), sizeof(buf), &buf);
	if (ret)
		return ret;

	timeout_ref = timeout_init_us(chip->timeout_a * 1000);
	do {
		/* keep trying to get one until timeout */
		if (tpm2_fifo_check_locality(chip, loc)) {
			chip->locality = loc;
			return TPM2_OK;
		}

		mdelay(TPM2_TIMEOUT_RETRY_MS);
	} while (!timeout_elapsed(timeout_ref));

	return TPM2_ERR_NO_ACTIVE_LOCALITY;
}

static enum tpm2_result tpm2_fifo_relinquish_locality(struct tpm2_chip *chip)
{
	const struct tpm2_ptp_phy_ops *ops = chip->phy_ops;
	uint8_t buf = 0;
	enum tpm2_result ret = TPM2_OK;

	if (chip->locality < 0)
		return TPM2_OK;

	/* Writing to TPM2_ACCESS_ACTIVE_LOCALITY relinquishes locality */
	buf = TPM2_ACCESS_ACTIVE_LOCALITY;
	ret = ops->tx8(chip, TPM2_ACCESS(chip->locality), sizeof(buf), &buf);
	if (ret)
		return ret;

	chip->locality = -1;

	return TPM2_OK;
}

static enum tpm2_result tpm2_fifo_set_status(struct tpm2_chip *chip,
					     uint8_t status)
{
	const struct tpm2_ptp_phy_ops *ops = chip->phy_ops;
	uint8_t buf = status;

	return ops->tx8(chip, TPM2_STS(chip->locality), sizeof(buf), &buf);
}

static enum tpm2_result tpm2_fifo_get_status(struct tpm2_chip *chip,
					     uint8_t *status)
{
	const struct tpm2_ptp_phy_ops *ops = chip->phy_ops;
	enum tpm2_result ret = TPM2_OK;

	ret = ops->rx8(chip, TPM2_STS(chip->locality), sizeof(*status), status);
	if (ret)
		return ret;

	/* Few bits in STS register are always expected to be 0. */
	if ((*status & TPM2_STS_READ_ZERO)) {
		EMSG("Invalid status");
		return TPM2_ERR_INVALID_ARG;
	}

	return TPM2_OK;
}

/* Different status bit settings can require different timeouts */
static enum tpm2_result tpm2_fifo_wait_for_status(struct tpm2_chip *chip,
						  uint8_t mask,
						  uint32_t timeout_ms,
						  uint8_t *status)
{
	enum tpm2_result ret = TPM2_OK;
	uint64_t timeout_ref = timeout_init_us(timeout_ms * 1000);

	do {
		ret = tpm2_fifo_get_status(chip, status);
		if (ret)
			return ret;

		if ((*status & mask) == mask)
			return TPM2_OK;

		mdelay(TPM2_TIMEOUT_RETRY_MS);
	} while (!timeout_elapsed(timeout_ref));

	return TPM2_ERR_TIMEOUT;
}

static enum tpm2_result tpm2_fifo_get_burstcount(struct tpm2_chip *chip,
						 uint32_t *burstcount)
{
	const struct tpm2_ptp_phy_ops *ops = chip->phy_ops;
	uint32_t burst = 0;
	uint64_t timeout_ref = 0;
	enum tpm2_result ret = TPM2_OK;

	if (chip->locality < 0)
		return TPM2_ERR_INVALID_ARG;

	timeout_ref = timeout_init_us(chip->timeout_a * 1000);
	/* wait for burstcount */
	do {
		ret = ops->rx32(chip, TPM2_STS(chip->locality), &burst);
		if (ret)
			return ret;
		burst = burst & TPM2_STS_BURST_COUNT_MASK;
		if (burst) {
			*burstcount = (burst >> TPM2_STS_BURST_COUNT_SHIFT);
			return TPM2_OK;
		}

		mdelay(TPM2_TIMEOUT_RETRY_MS);
	} while (!timeout_elapsed(timeout_ref));

	return TPM2_ERR_TIMEOUT;
}

enum tpm2_result tpm2_fifo_init(struct tpm2_chip *chip)
{
	enum tpm2_result ret = TPM2_OK;
	const struct tpm2_ptp_phy_ops *ops = chip->phy_ops;
	uint32_t flags = 0;

	assert(tpm2_fifo_check_ops(ops));

	chip->timeout_a = TPM2_TIMEOUT_A;
	chip->timeout_b = TPM2_TIMEOUT_B;
	chip->timeout_c = TPM2_TIMEOUT_C;
	chip->timeout_d = TPM2_TIMEOUT_D;
	chip->locality = -1;

	/* Wait for VALID bit to be set in TPM_ACCESS */
	ret = tpm2_fifo_wait_valid(chip, 0);
	if (ret)
		return TPM2_ERR_NODEV;

	ret = tpm2_fifo_request_locality(chip, 0);
	if (ret)
		return ret;

	/* disable interrupts */
	ret = chip->phy_ops->rx32(chip, TPM2_INT_ENABLE(chip->locality),
				  &flags);
	if (ret)
		return ret;

	flags |= TPM2_INT_CMD_READY_INT | TPM2_INT_LOCALITY_CHANGE_INT |
		 TPM2_INT_DATA_AVAIL_INT | TPM2_INT_STS_VALID_INT;
	flags &= ~TPM2_GLOBAL_INT_ENABLE;

	ret = chip->phy_ops->tx32(chip, TPM2_INT_ENABLE(chip->locality), flags);
	if (ret)
		return ret;

	return tpm2_fifo_relinquish_locality(chip);
}

enum tpm2_result tpm2_fifo_end(struct tpm2_chip *chip)
{
	enum tpm2_result ret = TPM2_OK;

	/* Cancel any command that may have been sent to TPM */
	ret = tpm2_fifo_set_status(chip, TPM2_STS_COMMAND_READY);
	if (ret)
		return ret;

	/* Relinquish locality if it was requested earlier */
	return tpm2_fifo_relinquish_locality(chip);
}

/* Based on Figure 3 - Send Command using FIFO protocol in DD Specification */
enum tpm2_result tpm2_fifo_send(struct tpm2_chip *chip, uint8_t *buf,
				uint32_t len)
{
	enum tpm2_result ret = TPM2_OK;
	const struct tpm2_ptp_phy_ops *ops = NULL;
	uint32_t burstcnt = 0;
	uint32_t sent = 0;
	uint32_t wr_size = 0;
	uint32_t buf_len = 0;
	uint8_t retry_cnt = 0;
	uint8_t status = 0;

	if (!chip)
		return TPM2_ERR_GENERIC;

	ops = chip->phy_ops;

	/* locality will be relinquishd in tpm2_fifo_recv() */
	ret = tpm2_fifo_request_locality(chip, 0);
	if (ret)
		return ret;

	while (retry_cnt < TPM2_DD_RETRY_CNT) {
		/*
		 * If unable to get status, something fundamental is
		 * wrong. No retries needed.
		 */
		ret = tpm2_fifo_get_status(chip, &status);
		if (ret)
			break;

		if (!(status & TPM2_STS_COMMAND_READY)) {
			/*
			 * If unable to set status, something fundamental is
			 * wrong. No retries needed.
			 */
			ret = tpm2_fifo_set_status(chip,
						   TPM2_STS_COMMAND_READY);
			if (ret) {
				EMSG("Previous cmd cancel failed");
				break;
			}
			ret = tpm2_fifo_wait_for_status(chip,
							TPM2_STS_COMMAND_READY,
							chip->timeout_b,
							&status);
			if (ret) {
				retry_cnt++;
				continue;
			}
		}

		buf_len = len;
		sent = 0;
		while (buf_len > 0) {
			ret = tpm2_fifo_get_burstcount(chip, &burstcnt);
			if (ret)
				break;

			wr_size = MIN(buf_len, burstcnt);
			ret = ops->tx8(chip, TPM2_DATA_FIFO(chip->locality),
				       wr_size, buf + sent);
			if (ret)
				break;

			ret = tpm2_fifo_wait_for_status(chip, TPM2_STS_VALID,
							chip->timeout_a,
							&status);
			if (ret)
				break;

			sent += wr_size;
			buf_len -= wr_size;
			/* TPM2 should expect more data */
			if (buf_len && !(status & TPM2_STS_DATA_EXPECT)) {
				ret = TPM2_ERR_IO;
				break;
			}
		}

		/* If any error has occurred in transmit loop above retry */
		if (ret) {
			retry_cnt++;
			continue;
		}

		/* last check everything is ok and TPM2 expects no more data */
		ret = tpm2_fifo_wait_for_status(chip, TPM2_STS_VALID,
						chip->timeout_a, &status);
		if (ret) {
			retry_cnt++;
			continue;
		}

		/* All data has been read, TPM2 should not expect more data */
		if (status & TPM2_STS_DATA_EXPECT) {
			ret = TPM2_ERR_GENERIC;
			retry_cnt++;
			continue;
		}

		ret = tpm2_fifo_set_status(chip, TPM2_STS_GO);
		if (ret)
			break;

		return TPM2_OK;
	}

	/* Cancel command and relinquish locality */
	if (tpm2_fifo_end(chip))
		return TPM2_ERR_GENERIC;

	return ret;
}

/* Based on Fig 4 - Receive response using FIFO protocol in DD Specification */
enum tpm2_result tpm2_fifo_recv(struct tpm2_chip *chip, uint8_t *buf,
				uint32_t *len, uint32_t cmd_duration)
{
	uint32_t burstcnt = 0;
	uint32_t bytes2read = TPM2_HDR_LEN;
	bool param_size_flag = false;
	uint32_t sz = 0;
	uint32_t rxsize = 0;
	uint8_t retry_cnt = 0;
	uint8_t status = 0;
	uint8_t flags = 0;
	enum tpm2_result ret = TPM2_OK;
	const struct tpm2_ptp_phy_ops *ops = NULL;

	if (!chip)
		return TPM2_ERR_GENERIC;

	ops = chip->phy_ops;

	if (*len < TPM2_HDR_LEN) {
		EMSG("Unable to read TPM2 header");
		*len = TPM2_HDR_LEN;
		return TPM2_ERR_INVALID_ARG;
	}

	while (retry_cnt < TPM2_DD_RETRY_CNT) {
		/* If retry is happening, force TPM to resend response */
		if (retry_cnt)
			tpm2_fifo_set_status(chip, TPM2_STS_RESPONSE_RETRY);

		flags = TPM2_STS_VALID | TPM2_STS_DATA_AVAIL;
		ret = tpm2_fifo_wait_for_status(chip, flags, cmd_duration,
						&status);
		if (ret) {
			EMSG("Data not available in response buffer");
			goto out;
		}

		rxsize = 0;
		/* First read the TPM header */
		bytes2read = TPM2_HDR_LEN;
		param_size_flag = 0;
		ret = TPM2_OK;

		while (bytes2read - rxsize) {
			ret = tpm2_fifo_get_burstcount(chip, &burstcnt);
			if (ret)
				break;

			sz = MIN(burstcnt, bytes2read - rxsize);
			ret = ops->rx8(chip, TPM2_DATA_FIFO(chip->locality), sz,
				       buf + rxsize);
			if (ret)
				goto out;

			rxsize += sz;

			/*
			 * The first 6 bytes of the read header have the TPM
			 * command length.
			 */
			if (rxsize >= 6 && !param_size_flag) {
				bytes2read = tpm2_cmd_len((void *)buf);
				param_size_flag = true;

				if (bytes2read > *len) {
					EMSG("Buffer too small: %" PRIx32 "> %"
					      PRIx32, bytes2read, *len);
					/* Return required buffer length */
					*len = bytes2read;
					ret = TPM2_ERR_SHORT_BUFFER;
					goto out;
				}
			}
		}

		/* If error in burstcnt, need to retry */
		if (ret) {
			retry_cnt++;
			continue;
		}

		ret = tpm2_fifo_wait_for_status(chip, TPM2_STS_VALID,
						chip->timeout_a, &status);
		if (ret)
			goto out;

		/*
		 * Something went wrong if DATA_AVAIL is still set.
		 * Instruct TPM to RetryResponse.
		 */
		if (!(status & TPM2_STS_DATA_AVAIL))
			break;

		retry_cnt++;
	}
out:
	/* Cancel command and relinquish locality */
	if (tpm2_fifo_end(chip))
		return TPM2_ERR_GENERIC;

	return ret;
}
