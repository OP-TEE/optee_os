/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef TEE_SE_READER_H
#define TEE_SE_READER_H

#include <tee_api_types.h>
#include <kernel/mutex.h>
#include <sys/queue.h>

struct tee_se_reader_proxy;
struct tee_se_session;

TEE_Result tee_se_reader_get_name(struct tee_se_reader_proxy *proxy,
		char **reader_name, size_t *reader_name_len);

void tee_se_reader_get_properties(struct tee_se_reader_proxy *proxy,
		TEE_SEReaderProperties *prop);

TEE_Result tee_se_reader_attach(struct tee_se_reader_proxy *proxy);

void tee_se_reader_detach(struct tee_se_reader_proxy *proxy);

TEE_Result tee_se_reader_open_session(struct tee_se_reader_proxy *proxy,
		struct tee_se_session **session);

void tee_se_reader_close_sessions(struct tee_se_reader_proxy *proxy);

TEE_Result tee_se_reader_get_atr(struct tee_se_reader_proxy *proxy,
		uint8_t **atr, size_t *atr_len);

TEE_Result tee_se_reader_transmit(struct tee_se_reader_proxy *proxy,
		uint8_t *tx_buf, size_t tx_buf_len, uint8_t *rx_buf, size_t *rx_buf_len);

void tee_se_reader_lock_basic_channel(struct tee_se_reader_proxy *proxy);

void tee_se_reader_unlock_basic_channel(struct tee_se_reader_proxy *proxy);

bool tee_se_reader_is_basic_channel_locked(struct tee_se_reader_proxy *proxy);

#endif
