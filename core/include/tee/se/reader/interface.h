/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 */

#ifndef TEE_READER_INTERFACE_H
#define TEE_READER_INTERFACE_H

#include <tee_api_types.h>

#include <sys/queue.h>

struct tee_se_reader {
	char name[TEE_SE_READER_NAME_MAX];
	struct tee_se_reader_ops *ops;
	void *private_data;
	TEE_SEReaderProperties prop;
};

enum tee_se_reader_state {
	READER_STATE_SE_EJECTED,
	READER_STATE_SE_INSERTED
};

enum tee_se_reader_type {
	READER_TYPE_ESE,
	READER_TYPE_SD,
	READER_TYPE_UICC,
};

struct tee_se_reader_ops {
	TEE_Result (*open)(struct tee_se_reader *);
	void (*close)(struct tee_se_reader *);
	enum tee_se_reader_state (*get_state)(struct tee_se_reader *);
	TEE_Result (*get_atr)(struct tee_se_reader *,
			uint8_t **atr, size_t *atr_len);
	TEE_Result (*transmit)(struct tee_se_reader *, uint8_t *tx_buf,
			size_t tx_len, uint8_t *rx_buf, size_t *rx_len);
};

TEE_Result tee_se_manager_register_reader(struct tee_se_reader *);
TEE_Result tee_se_manager_unregister_reader(struct tee_se_reader *);

#endif
