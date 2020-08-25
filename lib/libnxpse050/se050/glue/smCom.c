// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */
#include <kernel/mutex.h>
#include <smCom.h>
#include <stdio.h>
#include <trace.h>

static ApduTransceiveRawFunction_t transceive_raw;
static ApduTransceiveFunction_t transceive;
static struct mutex lock = MUTEX_INITIALIZER;

void smCom_Init(ApduTransceiveFunction_t t, ApduTransceiveRawFunction_t traw)
{
	transceive_raw = traw;
	transceive = t;
}

void smCom_DeInit(void)
{
	mutex_lock(&lock);
	transceive_raw = NULL;
	transceive = NULL;
	mutex_unlock(&lock);
}

uint32_t smCom_Transceive(void *ctx, apdu_t *apdu)
{
	uint32_t ret = SMCOM_NO_PRIOR_INIT;

	if (!transceive)
		return ret;

	mutex_lock(&lock);
	ret = transceive(ctx, apdu);
	mutex_unlock(&lock);

	return ret;
}

uint32_t smCom_TransceiveRaw(void *ctx, uint8_t *tx, uint16_t tx_len,
			     uint8_t *rx, uint32_t *rx_len)
{
	uint32_t ret = SMCOM_NO_PRIOR_INIT;

	if (!transceive_raw)
		return ret;

	mutex_lock(&lock);
	ret = transceive_raw(ctx, tx, tx_len, rx, rx_len);
	mutex_unlock(&lock);

	return ret;
}
