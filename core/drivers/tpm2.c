// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 *
 */

#include <kernel/delay.h>
#include <tpm2.h>
#include <trace.h>

static bool tpm2_check_ops(struct tpm2_ops *ops)
{
	if (!ops || !ops->rx32 || !ops->tx32 || !ops->rx8 || !ops->tx8)
		return false;

	return true;
}

static bool tpm2_check_locality(struct tpm2_chip *chip, int loc)
{
	struct tpm2_ops *ops = chip->ops;
	uint8_t locality = 0;

	ops->rx8(chip, TPM2_ACCESS(loc), 1, &locality);
	if ((locality & (TPM2_ACCESS_ACTIVE_LOCALITY | TPM2_ACCESS_VALID |
	     TPM2_ACCESS_REQUEST_USE)) ==
	    (TPM2_ACCESS_ACTIVE_LOCALITY | TPM2_ACCESS_VALID)) {
		chip->locality = loc;
		return true;
	}

	return false;
}

static enum tpm2_result tpm2_get_locality(struct tpm2_chip *chip, int loc)
{
	struct tpm2_ops *ops = chip->ops;
	uint32_t t_cnt = 0;
	uint8_t buf = TPM2_ACCESS_REQUEST_USE;

	/* first check if locality exists */
	if (tpm2_check_locality(chip, loc)) {
		DMSG("Locality ok");
		return TPM2_OK;
	}

	/* if not get one */
	DMSG("t_cnt = %" PRIu32 ", to = %" PRIu32, t_cnt, chip->timeout_a);
	ops->tx8(chip, TPM2_ACCESS(loc), 1, &buf);
	do {
		/* keep trying to get one until timeout */
		if (tpm2_check_locality(chip, loc))
			return TPM2_OK;

		mdelay(TPM2_TIMEOUT_MS);
		t_cnt += TPM2_TIMEOUT_MS;
	} while (t_cnt < chip->timeout_a);

	EMSG("Timeout t_cnt = %" PRIu32 " ms", t_cnt);
	return TPM2_ERR_TIMEOUT;
}

static enum tpm2_result tpm2_free_locality(struct tpm2_chip *chip)
{
	enum tpm2_result ret = TPM2_OK;
	struct tpm2_ops *ops = chip->ops;
	uint8_t buf = TPM2_ACCESS_ACTIVE_LOCALITY;

	if (chip->locality < 0)
		return TPM2_OK;

	ret = ops->tx8(chip, TPM2_ACCESS(chip->locality), 1, &buf);
	chip->locality = -1;

	return ret;
}

static enum tpm2_result tpm2_get_ready(struct tpm2_chip *chip)
{
	struct tpm2_ops *ops = chip->ops;
	uint8_t buf = TPM2_STS_COMMAND_READY;

	/*
	 * put module on ready
	 * all pending commands will be cancelled
	 */
	return ops->tx8(chip, TPM2_STS(chip->locality), 1, &buf);
}

static enum tpm2_result tpm2_get_status(struct tpm2_chip *chip, uint8_t *status)
{
	struct tpm2_ops *ops = chip->ops;

	if (chip->locality < 0)
		return TPM2_ERR_INVALID_ARG;

	ops->rx8(chip, TPM2_STS(chip->locality), 1, status);

	if ((*status & TPM2_STS_READ_ZERO)) {
		EMSG("Invalid status");
		return TPM2_ERR_INVALID_ARG;
	}

	return TPM2_OK;
}

static enum tpm2_result tpm2_wait_for_status(struct tpm2_chip *chip,
					     uint8_t mask,
					     uint32_t timeout,
					     uint8_t *status)
{
	enum tpm2_result ret = TPM2_OK;
	uint32_t t_cnt = 0;

	DMSG("t_cnt = %" PRIu32 ", to = %" PRIu32, t_cnt, timeout);
	do {
		ret = tpm2_get_status(chip, status);
		if (ret)
			return ret;

		if ((*status & mask) == mask) {
			DMSG("Status ok");
			return TPM2_OK;
		}

		mdelay(TPM2_TIMEOUT_MS);
		t_cnt += TPM2_TIMEOUT_MS;
	} while (t_cnt < timeout);

	EMSG("Timeout t_cnt = %" PRIu32 " ms", t_cnt);
	return TPM2_ERR_TIMEOUT;
}

static enum tpm2_result tpm2_get_burstcount(struct tpm2_chip *chip,
					    uint32_t *burstcount)
{
	struct tpm2_ops *ops = chip->ops;
	uint32_t burst = 0;
	uint32_t t_cnt = 0;

	if (chip->locality < 0)
		return TPM2_ERR_INVALID_ARG;

	DMSG("t_cnt = %" PRIu32 ", to = %" PRIu32, t_cnt, chip->timeout_a);
	/* wait for burstcount */
	do {
		ops->rx32(chip, TPM2_STS(chip->locality), &burst);
		*burstcount = (burst >> 8) & 0xFFFF;
		if (*burstcount) {
			DMSG("Burstcount ok");
			return TPM2_OK;
		}

		mdelay(TPM2_TIMEOUT_MS);
		t_cnt += TPM2_TIMEOUT_MS;
	} while (t_cnt < chip->timeout_a);

	EMSG("Timeout t_cnt = %" PRIu32 " ms", t_cnt);
	return TPM2_ERR_TIMEOUT;
}

uint32_t tpm2_convert2be(uint8_t *buf)
{
	return buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
}

enum tpm2_result tpm2_init(struct tpm2_chip *chip)
{
	enum tpm2_result ret = TPM2_OK;
	struct tpm2_ops *ops = chip->ops;
	uint32_t flags = 0;

	if (!tpm2_check_ops(ops)) {
		EMSG("No rx tx functions defined");
		return TPM2_ERR_INIT;
	}

	/*
	 * chip->timeout_a start out as 0 in tpm2_get_locality()
	 */
	ret = tpm2_get_locality(chip, 0);
	if (ret)
		return ret;

	chip->timeout_a = TPM2_TIMEOUT_SHORT_MS;
	chip->timeout_b = TPM2_TIMEOUT_LONG_MS;
	chip->timeout_c = TPM2_TIMEOUT_SHORT_MS;
	chip->timeout_d = TPM2_TIMEOUT_SHORT_MS;

	/* disable interrupts */
	chip->ops->rx32(chip, TPM2_INT_ENABLE(chip->locality), &flags);
	flags |= TPM2_INT_CMD_READY_INT | TPM2_INT_LOCALITY_CHANGE_INT |
		 TPM2_INT_DATA_AVAIL_INT | TPM2_INT_STS_VALID_INT;
	flags &= ~TPM2_GLOBAL_INT_ENABLE;
	chip->ops->tx32(chip, TPM2_INT_ENABLE(chip->locality), flags);

	chip->ops->rx8(chip, TPM2_RID(chip->locality), 1, &chip->rid);
	chip->ops->rx32(chip, TPM2_DID_VID(chip->locality), &chip->vend_dev);

	return tpm2_free_locality(chip);
}

enum tpm2_result tpm2_end(struct tpm2_chip *chip)
{
	tpm2_get_ready(chip);
	tpm2_free_locality(chip);

	return TPM2_OK;
}

enum tpm2_result tpm2_open(struct tpm2_chip *chip)
{
	enum tpm2_result ret = TPM2_OK;

	if (chip->is_open)
		return TPM2_ERR_INIT;

	ret = tpm2_get_locality(chip, 0);
	if (!ret)
		chip->is_open = 1;

	return ret;
}

enum tpm2_result tpm2_close(struct tpm2_chip *chip)
{
	enum tpm2_result ret = TPM2_OK;

	if (chip->is_open) {
		ret = tpm2_free_locality(chip);
		chip->is_open = 0;
	}

	return ret;
}

enum tpm2_result tpm2_tx(struct tpm2_chip *chip, uint8_t *buf, uint32_t len)
{
	enum tpm2_result ret = TPM2_OK;
	struct tpm2_ops *ops = chip->ops;
	uint32_t burstcnt = 0;
	uint32_t sent = 0;
	uint32_t wr_size = 0;
	uint8_t data = TPM2_STS_GO;
	uint8_t status = 0;

	if (!chip)
		return TPM2_ERR_GENERIC;

	/* free in tpm2_rx() */
	ret = tpm2_get_locality(chip, 0);
	if (ret)
		return ret;

	ret = tpm2_get_status(chip, &status);
	if (ret)
		goto free_locality;

	if (!(status & TPM2_STS_COMMAND_READY)) {
		ret = tpm2_get_ready(chip);
		if (ret) {
			EMSG("Previous cmd cancel failed");
			goto free_locality;
		}
		ret = tpm2_wait_for_status(chip, TPM2_STS_COMMAND_READY,
					   chip->timeout_b, &status);
		if (ret) {
			EMSG("Module not ready\n");
			goto free_locality;
		}
	}

	while (len > 0) {
		ret = tpm2_get_burstcount(chip, &burstcnt);
		if (ret)
			goto free_locality;

		wr_size = MIN(len, burstcnt);
		ret = ops->tx8(chip, TPM2_DATA_FIFO(chip->locality), wr_size,
			       buf + sent);
		if (ret < 0)
			goto free_locality;

		ret = tpm2_wait_for_status(chip, TPM2_STS_VALID,
					   chip->timeout_c, &status);
		if (ret)
			goto free_locality;

		sent += wr_size;
		len -= wr_size;
		/* TPM2 should expect more data */
		if (len && !(status & TPM2_STS_DATA_EXPECT)) {
			ret = TPM2_ERR_IO;
			goto free_locality;
		}
	}

	/* last check everything is ok and TPM2 expects no more data */
	ret = tpm2_wait_for_status(chip, TPM2_STS_VALID, chip->timeout_c,
				   &status);
	if (ret)
		goto free_locality;

	if (status & TPM2_STS_DATA_EXPECT) {
		ret = TPM2_ERR_IO;
		goto free_locality;
	}

	ret = ops->tx8(chip, TPM2_STS(chip->locality), 1, &data);
	if (ret)
		goto free_locality;

	return sent;

free_locality:
	tpm2_get_ready(chip);
	tpm2_free_locality(chip);

	return ret;
}

static enum tpm2_result tpm2_rx_dat(struct tpm2_chip *chip, uint8_t *buf,
				    uint32_t cnt, uint32_t *size)
{
	enum tpm2_result ret = TPM2_OK;
	struct tpm2_ops *ops = chip->ops;
	uint32_t burstcnt = 0;
	uint32_t len = 0;
	uint8_t status = 0;

	*size = 0;
	while (*size < cnt &&
	       !tpm2_wait_for_status(chip, TPM2_STS_DATA_AVAIL | TPM2_STS_VALID,
				    chip->timeout_c, &status)) {
		ret = tpm2_get_burstcount(chip, &burstcnt);
		if (ret)
			return ret;

		len = MIN(burstcnt, cnt - *size);
		ret = ops->rx8(chip, TPM2_DATA_FIFO(chip->locality), len,
			       buf + *size);
		if (ret)
			return ret;

		*size += len;
	}

	return ret;
}

enum tpm2_result tpm2_rx(struct tpm2_chip *chip, uint8_t *buf, uint32_t len)
{
	enum tpm2_result ret = TPM2_OK;
	uint32_t expected = 0;
	uint32_t size = 0;
	uint32_t tmp_size = 0;

	if (len < TPM2_HDR_LEN)
		return TPM2_ERR_ARG_LIST_TOO_LONG;

	ret = tpm2_rx_dat(chip, buf, TPM2_HDR_LEN, &size);
	if (ret || size < TPM2_HDR_LEN) {
		EMSG("Unable to read TPM2 header\n");
		goto out;
	}

	expected = tpm2_convert2be(buf + TPM2_CMD_COUNT_OFFSET);

	if (expected > len) {
		size = TPM2_ERR_IO;
		EMSG("Too much data: %" PRIu32 " > %" PRIu32, expected, len);
		goto out;
	}

	ret = tpm2_rx_dat(chip, &buf[TPM2_HDR_LEN], expected - TPM2_HDR_LEN,
			  &tmp_size);
	size += tmp_size;
	if (ret || size < expected) {
		EMSG("Unable to rx remaining data");
		size = TPM2_ERR_IO;
		goto out;
	}

out:
	tpm2_get_ready(chip);
	/* obtained from tpm2_tx() */
	tpm2_free_locality(chip);

	return size;
}

