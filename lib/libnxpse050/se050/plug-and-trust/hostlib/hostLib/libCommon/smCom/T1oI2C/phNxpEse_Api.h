/*
 * Copyright 2012-2014,2018-2020 NXP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 *
 * \brief ESE Lib layer interface to application
 * @{ */

#ifndef _PHNXPESE_API_H_
#define _PHNXPESE_API_H_

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include "smComT1oI2C.h"

#include "phEseStatus.h"

/**
 *
 * \brief Ese data buffer
 *
 */
typedef struct phNxpEse_data
{
    uint32_t len; /*!< length of the buffer */
    uint8_t  *p_data; /*!< pointer to a buffer */
} phNxpEse_data;


/**
 *
 * \brief Ese library init parameters to be set while calling phNxpEse_init
 *
 */
typedef struct phNxpEse_initParams
{
    phNxpEse_initMode initMode; /*!< Ese communication mode */
} phNxpEse_initParams;


ESESTATUS phNxpEse_init(void *conn_ctx, phNxpEse_initParams initParams, phNxpEse_data *AtrRsp);
ESESTATUS phNxpEse_open(void **conn_ctx, phNxpEse_initParams initParams, const char *pConnString);
ESESTATUS phNxpEse_Transceive(void* conn_ctx, phNxpEse_data *pCmd, phNxpEse_data *pRsp);
ESESTATUS phNxpEse_deInit(void* conn_ctx);
ESESTATUS phNxpEse_close(void* conn_ctx);
ESESTATUS phNxpEse_reset(void* conn_ctx);
ESESTATUS phNxpEse_chipReset(void* conn_ctx);
ESESTATUS phNxpEse_setIfsc(uint16_t IFSC_Size);
ESESTATUS phNxpEse_EndOfApdu(void* conn_ctx);
void* phNxpEse_memset(void *buff, int val, size_t len);
void* phNxpEse_memcpy(void *dest, const void *src, size_t len);
void *phNxpEse_memalloc(uint32_t size);
void phNxpEse_free(void* ptr);
ESESTATUS phNxpEse_getAtr(void* conn_ctx, phNxpEse_data *pRsp);
ESESTATUS phNxpEse_getCip(void* conn_ctx, phNxpEse_data *pRsp);
/** @} */
#endif /* _PHNXPESE_API_H_ */
