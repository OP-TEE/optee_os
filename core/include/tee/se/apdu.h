/* SPDX-License-Identifier: BSD-2-Clause */
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
#ifndef TEE_SE_APDU
#define TEE_SE_APDU

struct cmd_apdu;
struct resp_apdu;
struct apdu_base;

#define to_apdu_base(apdu)	((struct apdu_base *)(apdu))

struct cmd_apdu *alloc_cmd_apdu(uint8_t cla, uint8_t ins, uint8_t p1,
		uint8_t p2, uint8_t lc, uint8_t le, uint8_t *data);

struct cmd_apdu *alloc_cmd_apdu_from_buf(uint8_t *buf, size_t length);

struct resp_apdu *alloc_resp_apdu(uint8_t le);

uint8_t *resp_apdu_get_data(struct resp_apdu *apdu);

size_t resp_apdu_get_data_len(struct resp_apdu *apdu);

uint8_t resp_apdu_get_sw1(struct resp_apdu *apdu);

uint8_t resp_apdu_get_sw2(struct resp_apdu *apdu);

uint8_t *apdu_get_data(struct apdu_base *apdu);

size_t apdu_get_length(struct apdu_base *apdu);

void apdu_acquire(struct apdu_base *apdu);

void apdu_release(struct apdu_base *apdu);


#endif
