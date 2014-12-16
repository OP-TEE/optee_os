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

/* Based on GP TEE Secure Element API Specification Version 1.00 */
#ifndef TEE_INTERNAL_SE_API_H
#define TEE_INTERNAL_SE_API_H

#include <tee_api_defines.h>
#include <tee_api_types.h>

TEE_Result TEE_SEServiceOpen(TEE_SEServiceHandle *seServiceHandle);

void TEE_SEServiceClose(TEE_SEServiceHandle seServiceHandle);

TEE_Result TEE_SEServiceGetReaders(
		TEE_SEServiceHandle seServiceHandle,
		TEE_SEReaderHandle *seReaderHandleList,
		size_t *seReaderHandleListLen);

void TEE_SEReaderGetProperties(TEE_SEReaderHandle seReaderHandle,
		TEE_SEReaderProperties *readerProperties);

TEE_Result TEE_SEReaderGetName(TEE_SEReaderHandle seReaderHandle,
		char *readerName, size_t *readerNameLen);

TEE_Result TEE_SEReaderOpenSession(TEE_SEReaderHandle seReaderHandle,
		TEE_SESessionHandle *seSessionHandle);

void TEE_SEReaderCloseSessions(TEE_SEReaderHandle seReaderHandle);

TEE_Result TEE_SESessionGetATR(TEE_SESessionHandle seSessionHandle,
		void *atr, size_t *atrLen);

TEE_Result TEE_SESessionIsClosed(TEE_SESessionHandle seSessionHandle);

void TEE_SESessionClose(TEE_SESessionHandle seSessionHandle);

TEE_Result TEE_SESessionOpenBasicChannel(TEE_SESessionHandle seSessionHandle,
		TEE_SEAID *seAID, TEE_SEChannelHandle *seChannelHandle);

TEE_Result TEE_SESessionOpenLogicalChannel(TEE_SESessionHandle seSessionHandle,
		TEE_SEAID *seAID, TEE_SEChannelHandle *seChannelHandle);

TEE_Result TEE_SEChannelSelectNext(TEE_SEChannelHandle seChannelHandle);

TEE_Result TEE_SEChannelGetSelectResponse(TEE_SEChannelHandle seChannelHandle,
		void *response, size_t *responseLen);

TEE_Result TEE_SEChannelTransmit(TEE_SEChannelHandle seChannelHandle,
		void *command, size_t commandLen,
		void *response, size_t *responseLen);

void TEE_SEChannelClose(TEE_SEChannelHandle seChannelHandle);
#endif
