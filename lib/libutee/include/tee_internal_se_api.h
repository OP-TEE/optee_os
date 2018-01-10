/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
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
