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


#include <tee_api.h>

#include <tee_internal_se_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>
#include <sys/queue.h>

#include <utee_syscalls.h>

#define VERIFY_HANDLE(handle, ops) \
do { \
	if ((handle) == TEE_HANDLE_NULL) \
		TEE_Panic(0); \
	ret = (ops); \
	if (ret == TEE_ERROR_BAD_PARAMETERS) \
		TEE_Panic(0); \
} while (0)

TEE_Result TEE_SEServiceOpen(
		TEE_SEServiceHandle *seServiceHandle)
{
	TEE_Result ret;
	uint32_t s;

	if (seServiceHandle == NULL)
		TEE_Panic(0);

	ret = utee_se_service_open(&s);
	if (ret == TEE_SUCCESS)
		*seServiceHandle = (TEE_SEServiceHandle)(uintptr_t)s;
	return ret;
}

void TEE_SEServiceClose(
		TEE_SEServiceHandle seServiceHandle)
{
	TEE_Result ret;

	VERIFY_HANDLE(seServiceHandle,
			utee_se_service_close((unsigned long)seServiceHandle));

}

TEE_Result TEE_SEServiceGetReaders(
		TEE_SEServiceHandle seServiceHandle,
		TEE_SEReaderHandle *seReaderHandleList,
		size_t *seReaderHandleListLen)
{
	TEE_Result ret = TEE_SUCCESS;

	if (seReaderHandleList == NULL ||
		seReaderHandleListLen == NULL)
		TEE_Panic(0);
	else {
		uint64_t rl_len = *seReaderHandleListLen;
		uint32_t rl[rl_len];
		size_t n;

		VERIFY_HANDLE(seServiceHandle,
			utee_se_service_get_readers(
				(unsigned long)seServiceHandle, rl, &rl_len));
		if (ret != TEE_SUCCESS)
			return ret;
		for (n = 0; n < rl_len; n++)
			seReaderHandleList[n] =
				(TEE_SEReaderHandle)(uintptr_t)rl[n];
		*seReaderHandleListLen = rl_len;
	}
	return ret;
}

void TEE_SEReaderGetProperties(TEE_SEReaderHandle seReaderHandle,
		TEE_SEReaderProperties *readerProperties)
{
	TEE_Result ret;
	uint32_t prop;

	VERIFY_HANDLE(seReaderHandle,
		utee_se_reader_get_prop((unsigned long)seReaderHandle, &prop));

	readerProperties->sePresent = !!(prop & UTEE_SE_READER_PRESENT);
	readerProperties->teeOnly = !!(prop & UTEE_SE_READER_TEE_ONLY);
	readerProperties->selectResponseEnable =
			!!(prop & UTEE_SE_READER_SELECT_RESPONE_ENABLE);
}

TEE_Result TEE_SEReaderGetName(TEE_SEReaderHandle seReaderHandle,
		char *readerName, size_t *readerNameLen)
{
	TEE_Result ret;
	uint64_t nl;

	if (readerName == NULL || readerNameLen == NULL ||
		*readerNameLen == 0)
		TEE_Panic(0);

	nl = *readerNameLen;
	VERIFY_HANDLE(seReaderHandle,
		utee_se_reader_get_name((unsigned long)seReaderHandle,
			readerName, &nl));
	*readerNameLen = nl;

	return ret;
}

TEE_Result TEE_SEReaderOpenSession(TEE_SEReaderHandle seReaderHandle,
		TEE_SESessionHandle *seSessionHandle)
{
	TEE_Result ret;
	uint32_t s;

	if (seSessionHandle == NULL)
		TEE_Panic(0);

	VERIFY_HANDLE(seReaderHandle,
		utee_se_reader_open_session((unsigned long)seReaderHandle, &s));
	if (ret == TEE_SUCCESS)
		*seSessionHandle = (TEE_SESessionHandle)(uintptr_t)s;
	return ret;
}


void TEE_SEReaderCloseSessions(
		TEE_SEReaderHandle seReaderHandle)
{
	TEE_Result ret;

	VERIFY_HANDLE(seReaderHandle,
		utee_se_reader_close_sessions((unsigned long)seReaderHandle));
}

TEE_Result TEE_SESessionGetATR(TEE_SESessionHandle seSessionHandle,
		void *atr, size_t *atrLen)
{
	TEE_Result ret;
	uint64_t al;

	if (atr == NULL || atrLen == NULL || *atrLen == 0)
		TEE_Panic(0);

	al = *atrLen;
	VERIFY_HANDLE(seSessionHandle,
		utee_se_session_get_atr((unsigned long)seSessionHandle,
					atr, &al));
	*atrLen = al;
	return ret;
}

TEE_Result TEE_SESessionIsClosed(TEE_SESessionHandle seSessionHandle)
{
	TEE_Result ret;

	VERIFY_HANDLE(seSessionHandle,
		utee_se_session_is_closed((unsigned long)seSessionHandle));
	return ret;
}

void TEE_SESessionClose(TEE_SESessionHandle seSessionHandle)
{
	TEE_Result ret;

	VERIFY_HANDLE(seSessionHandle,
		utee_se_session_close((unsigned long)seSessionHandle));
}

TEE_Result TEE_SESessionOpenBasicChannel(TEE_SESessionHandle seSessionHandle,
		TEE_SEAID *seAID, TEE_SEChannelHandle *seChannelHandle)
{
	TEE_Result ret;
	uint32_t s;
	const void *p = NULL;
	size_t l = 0;

	if (seChannelHandle == NULL)
		TEE_Panic(0);

	if (seAID) {
		p = seAID->buffer;
		l = seAID->bufferLen;
	}
	VERIFY_HANDLE(seSessionHandle,
		utee_se_session_open_channel((unsigned long)seSessionHandle,
					     false, p, l, &s));
	if (ret == TEE_SUCCESS)
		*seChannelHandle = (TEE_SEChannelHandle)(uintptr_t)s;
	return ret;
}

TEE_Result TEE_SESessionOpenLogicalChannel(TEE_SESessionHandle seSessionHandle,
		TEE_SEAID *seAID, TEE_SEChannelHandle *seChannelHandle)
{
	TEE_Result ret;
	uint32_t s;
	const void *p = NULL;
	size_t l = 0;

	if (seChannelHandle == NULL)
		TEE_Panic(0);

	if (seAID) {
		p = seAID->buffer;
		l = seAID->bufferLen;
	}
	VERIFY_HANDLE(seSessionHandle,
		utee_se_session_open_channel((unsigned long)seSessionHandle,
					     true, p, l, &s));
	if (ret == TEE_SUCCESS)
		*seChannelHandle = (TEE_SEChannelHandle)(uintptr_t)s;
	return ret;
}

TEE_Result TEE_SEChannelSelectNext(TEE_SEChannelHandle seChannelHandle)
{
	TEE_Result ret;

	VERIFY_HANDLE(seChannelHandle,
		utee_se_channel_select_next((unsigned long)seChannelHandle));
	return ret;
}

TEE_Result TEE_SEChannelGetSelectResponse(TEE_SEChannelHandle seChannelHandle,
		void *response, size_t *responseLen)
{
	TEE_Result ret;
	uint64_t rl;

	if (!responseLen)
		TEE_Panic(0);

	rl = *responseLen;
	VERIFY_HANDLE(seChannelHandle,
		utee_se_channel_get_select_resp((unsigned long)seChannelHandle,
			response, &rl));
	if (ret == TEE_SUCCESS)
		*responseLen = rl;
	return ret;
}

TEE_Result TEE_SEChannelTransmit(TEE_SEChannelHandle seChannelHandle,
		void *command, size_t commandLen,
		void *response, size_t *responseLen)
{
	TEE_Result ret;
	uint64_t rl;

	if (!responseLen)
		TEE_Panic(0);

	rl = *responseLen;
	VERIFY_HANDLE(seChannelHandle,
		utee_se_channel_transmit((unsigned long)seChannelHandle,
			command, commandLen, response, &rl));
	if (ret == TEE_SUCCESS)
		*responseLen = rl;
	return ret;
}

void TEE_SEChannelClose(TEE_SEChannelHandle seChannelHandle)
{
	TEE_Result ret;

	VERIFY_HANDLE(seChannelHandle,
		utee_se_channel_close((unsigned long)seChannelHandle));
}
