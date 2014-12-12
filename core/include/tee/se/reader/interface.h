/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
