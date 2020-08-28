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

 /**
 * \addtogroup eSe_PAL_I2C
 * \brief PAL I2C port implementation for linux
 * @{ */
#ifndef _PHNXPESE_PAL_I2C_H
#define _PHNXPESE_PAL_I2C_H

/* Basic type definitions */
#include <phEseTypes.h>


/*!
 * \brief ESE Poll timeout (min 1 miliseconds)
 */
#define ESE_POLL_DELAY_MS (1)
/*!
 * \brief ESE Poll timeout (max 2 seconds).
 * Increased to 500. Need more timeout for RSA operations. We get NACK before WTX
 */
#define ESE_NAD_POLLING_MAX (2*250)
/*!
 * \brief Max retry count for Write
 */
#define MAX_RETRY_COUNT   3

/*!
 * \brief ESE wakeup delay in case of write error retry
 */
#define WAKE_UP_DELAY_MS 5 //5 ms
/*!
 * \brief ESE wakeup delay in case of write error retry
 */
#define NAD_POLLING_SCALER 1
/*!
 * \brief ESE wakeup delay in case of write error retry
 */
#define CHAINED_PKT_SCALER 1
/*!
 * \brief This function is used to set slave address of ESE
 *
 */
// #define I2C_MASTER_SLAVE_ADDR_7BIT (0x90U >> 1)  //slve bit address is 20U but driver do right shift so set to 40U
#define SMCOM_I2C_ADDRESS           (0x90)

/*!
 * \ingroup eSe_PAL_I2C
 *
 * \brief PAL Configuration exposed to upper layer.
 */
typedef struct phPalEse_Config
{
    int8_t *pDevName;
    /*!< Port name connected to ESE
      *
      * Platform specific canonical device name to which ESE is connected.
      *
      * e.g. On Linux based systems this would be /dev/p73
      */

    int8_t DeviceAddress;
    /*!< I2C Address of SE connected
      */

    uint32_t dwBaudRate;
    /*!< Communication speed between DH and ESE
      *
      * This is the baudrate of the bus for communication between DH and ESE
      */

    void *pDevHandle;
    /*!< Device handle output */
} phPalEse_Config_t,*pphPalEse_Config_t;    /* pointer to phPalEse_Config_t */

void phPalEse_i2c_close(void *pDevHandle);
ESESTATUS phPalEse_i2c_open_and_configure(pphPalEse_Config_t pConfig);
int phPalEse_i2c_read(void *pDevHandle, uint8_t * pBuffer, int nNbBytesToRead);
int phPalEse_i2c_write(void *pDevHandle,uint8_t * pBuffer, int nNbBytesToWrite);
/** @} */
#endif  /*  _PHNXPESE_PAL_I2C_H    */
