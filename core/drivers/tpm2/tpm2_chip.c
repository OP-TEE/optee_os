// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <assert.h>
#include <drivers/tpm2_chip.h>
#include <io.h>
#include <tpm2.h>
#include <trace.h>

static struct tpm2_chip *tpm2_device;

enum tpm2_result tpm2_chip_send(uint8_t *buf, uint32_t len)
{
	if (!tpm2_device || !tpm2_device->ops->send)
		return TPM2_ERR_NODEV;

	return tpm2_device->ops->send(tpm2_device, buf, len);
}

enum tpm2_result tpm2_chip_recv(uint8_t *buf, uint32_t *len,
				uint32_t cmd_duration)
{
	if (!tpm2_device || !tpm2_device->ops->recv)
		return TPM2_ERR_NODEV;

	return tpm2_device->ops->recv(tpm2_device, buf, len, cmd_duration);
}

enum tpm2_result tpm2_chip_register(struct tpm2_chip *chip)
{
	enum tpm2_result ret = TPM2_OK;
	uint8_t full = 1;

	/* Only 1 tpm2 device is supported */
	assert(!tpm2_device);

	if (!chip || !chip->ops)
		return TPM2_ERR_NODEV;

	/* Assign timeouts etc based on interface */
	ret = chip->ops->init(chip);
	if (ret)
		return ret;

	tpm2_device = chip;

	/* Now that interface is initialized do basic init of tpm */
	ret = tpm2_startup(TPM2_SU_CLEAR);
	if (ret) {
		EMSG("TPM2 Startup Failed");
		return ret;
	}

	ret = tpm2_selftest(full);
	if (ret)
		EMSG("TPM2 Self Test Failed");

	return ret;
}
