/*
 * Copyright 2010-2014,2018-2020 NXP
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
#ifndef _PHNXPESE_INTERNAL_H_
#define _PHNXPESE_INTERNAL_H_

#include <phNxpEse_Api.h>

#ifdef T1oI2C_UM1225_SE050
/* MW version 02.13.00 onwards */
#   error Do not define T1oI2C_UM1225_SE050, define T1oI2C_UM11225 instead.
#endif

/********************* Definitions and structures *****************************/

typedef enum
{
   ESE_STATUS_CLOSE = 0x00,
   ESE_STATUS_BUSY,
   ESE_STATUS_RECOVERY,
   ESE_STATUS_IDLE,
   ESE_STATUS_OPEN,
} phNxpEse_LibStatus;

/* Macros definition */
#define MAX_DATA_LEN      260

/* I2C Control structure */
typedef struct phNxpEse_Context
{
    phNxpEse_LibStatus   EseLibStatus;      /* Indicate if Ese Lib is open or closed */
    void *pDevHandle;

    uint8_t p_read_buff[MAX_DATA_LEN];
    uint16_t cmd_len;
    uint8_t p_cmd_data[MAX_DATA_LEN];
    phNxpEse_initParams initParams;
} phNxpEse_Context_t;


ESESTATUS phNxpEse_WriteFrame(void* conn_ctx, uint32_t data_len, const uint8_t *p_data);
ESESTATUS phNxpEse_read(void* conn_ctx, uint32_t *data_len, uint8_t **pp_data);
void phNxpEse_clearReadBuffer(void* conn_ctx);

#endif /* _PHNXPESE_INTERNAL_H_ */
