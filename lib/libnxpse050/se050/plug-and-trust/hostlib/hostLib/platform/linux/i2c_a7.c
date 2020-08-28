/*
 * Copyright 2017-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @par Description
 * MCIMX6UL-EVK / MCIMX8M-EVK board specific & Generic i2c code
 * @par History
 *
 **/
#include "i2c_a7.h"
#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <linux/version.h>
#include <errno.h>
#include <time.h>

// #define NX_LOG_ENABLE_SMCOM_DEBUG 1

#include "nxLog_smCom.h"

static char* default_axSmDevice_name = "/dev/i2c-1";
static int default_axSmDevice_addr = 0x48;      // 7-bit address

/**
* Opens the communication channel to I2C device
*/
i2c_error_t axI2CInit(void **conn_ctx, const char *pDevName)
{
    unsigned long funcs;
    int axSmDevice = 0;
    char *pdev_name = NULL;
    char *pdev_addr_str = NULL;
    U32 dev_addr = 0x00;
    char temp[32] = { 0, };

    if (pDevName != NULL && (strcasecmp("none", pDevName) != 0) ) {
        memcpy(temp, pDevName, strlen(pDevName));
        temp[strlen(pDevName)] = '\0';

        pdev_name = strtok(temp, ":");
        if (pdev_name == NULL) {
            perror("Invalid connection string");
            LOG_I("Pass i2c device address in the format <i2c_port>:<i2c_addr(optional. Default 0x48)>.");
            LOG_I("Example ./example /dev/i2c-1:0x48 OR ./example /dev/i2c-1");
            return I2C_FAILED;
        }

        pdev_addr_str = strtok(NULL, ":");
        if (pdev_addr_str != NULL) {
            dev_addr = strtol(pdev_addr_str, NULL, 0);
        }
        else {
            dev_addr = default_axSmDevice_addr;
        }
    }
    else {
        pdev_name = default_axSmDevice_name;
        dev_addr = default_axSmDevice_addr;
    }

    LOG_D("I2CInit: opening %s\n", pdev_name);

    if ((axSmDevice = open(pdev_name, O_RDWR)) < 0)
    {
        LOG_E("opening failed...");
        perror("Failed to open the i2c bus");
        LOG_I("Pass i2c device address in the format <i2c_port>:<i2c_addr(optional. Default 0x48)>.");
        LOG_I("Example ./example /dev/i2c-1:0x48 OR ./example /dev/i2c-1");
        return I2C_FAILED;
    }

    if (ioctl(axSmDevice, I2C_SLAVE, dev_addr) < 0)
    {
        LOG_E("I2C driver failed setting address\n");
    }

    // clear PEC flag
    if (ioctl(axSmDevice, I2C_PEC, 0) < 0)
    {
        LOG_E("I2C driver: PEC flag clear failed\n");
    }
    else
    {
        LOG_D("I2C driver: PEC flag cleared\n");
    }

    // Query functional capacity of I2C driver
    if (ioctl(axSmDevice, I2C_FUNCS, &funcs) < 0)
    {
        LOG_E("Cannot get i2c adapter functionality\n");
        return I2C_FAILED;
    }
    else
    {
        if (funcs & I2C_FUNC_I2C)
        {
            LOG_D("I2C driver supports plain i2c-level commands.\n");
#if defined(SCI2C) //if SCI2C is enabled
            if ( (funcs & I2C_FUNC_SMBUS_READ_BLOCK_DATA) == I2C_FUNC_SMBUS_READ_BLOCK_DATA )
            {
                LOG_D("I2C driver supports Read Block.\n");
            }
            else
            {
                LOG_E("I2C driver does not support Read Block!\n");
                return I2C_FAILED;
            }
#endif
        }
        else
        {
            LOG_E("I2C driver CANNOT support plain i2c-level commands!\n");
            return I2C_FAILED;
        }
    }

    *conn_ctx = malloc(sizeof(int));
    *(int*)(*conn_ctx) = axSmDevice;
    return I2C_OK;
}

/**
* Closes the communication channel to I2C device (not implemented)
*/
void axI2CTerm(void* conn_ctx, int mode)
{
    AX_UNUSED_ARG(mode);
    if (conn_ctx != NULL) {
        free(conn_ctx);
    }
    return;
}

#if defined(SCI2C)
/**
 * Write a single byte to the slave device.
 * In the context of the SCI2C protocol, this command is only invoked
 * to trigger a wake-up of the attached secure module. As such this
 * wakeup command 'wakes' the device, but does not receive a valid response.
 * \note \par bus is currently not used to distinguish between I2C masters.
*/
i2c_error_t axI2CWriteByte(void* conn_ctx, unsigned char bus, unsigned char addr, unsigned char * pTx)
{
    int nrWritten = -1;
    i2c_error_t rv;
    int axSmDevice = *(int*)conn_ctx;

    if (bus != I2C_BUS_0)
    {
        LOG_E("axI2CWriteByte on wrong bus %x (addr %x)\n", bus, addr);
    }

    nrWritten = write(axSmDevice, pTx, 1);
    if (nrWritten < 0)
    {
        // I2C_LOG_PRINTF("Failed writing data (nrWritten=%d).\n", nrWritten);
        rv = I2C_FAILED;
    }
    else
    {
        if (nrWritten == 1)
        {
            rv = I2C_OK;
        }
        else
        {
            rv = I2C_FAILED;
        }
    }

    return rv;
}
#endif // defined(SCI2C)

#if defined(SCI2C) || defined(T1oI2C)
i2c_error_t axI2CWrite(void* conn_ctx, unsigned char bus, unsigned char addr, unsigned char * pTx, unsigned short txLen)
{
    int nrWritten = -1;
    i2c_error_t rv;
    int axSmDevice = *(int*)conn_ctx;
#ifdef LOG_I2C
    int i = 0;
#endif

    if (bus != I2C_BUS_0)
    {
        LOG_E("axI2CWrite on wrong bus %x (addr %x)\n", bus, addr);
    }
    LOG_MAU8_D("TX (axI2CWrite) > ",pTx,txLen);
    nrWritten = write(axSmDevice, pTx, txLen);
    if (nrWritten < 0)
    {
       LOG_E("Failed writing data (nrWritten=%d).\n", nrWritten);
       rv = I2C_FAILED;
    }
    else
    {
        if (nrWritten == txLen) // okay
        {
            rv = I2C_OK;
        }
        else
        {
            rv = I2C_FAILED;
        }
    }
    LOG_D("Done with rv = %02x ", rv);

    return rv;
}
#endif // defined(SCI2C) || defined(T1oI2C)

#if defined(SCI2C)
i2c_error_t axI2CWriteRead(void* conn_ctx, unsigned char bus, unsigned char addr, unsigned char * pTx,
      unsigned short txLen, unsigned char * pRx, unsigned short * pRxLen)
{
    struct i2c_rdwr_ioctl_data packets;
    struct i2c_msg messages[2];
    int r = 0;
    int i = 0;
    int axSmDevice = *(int*)conn_ctx;

    if (bus != I2C_BUS_0) // change if bus 0 is not the correct bus
    {
        LOG_E("axI2CWriteRead on wrong bus %x (addr %x)\n", bus, addr);
    }

    messages[0].addr  = default_axSmDevice_addr;
    messages[0].flags = 0;
    messages[0].len   = txLen;
    messages[0].buf   = pTx;

    // NOTE:
    // By setting the 'I2C_M_RECV_LEN' bit in 'messages[1].flags' one ensures
    // the I2C Block Read feature is used.
    messages[1].addr  = default_axSmDevice_addr;
    messages[1].flags = I2C_M_RD | I2C_M_RECV_LEN;
    messages[1].len   = 256;
    messages[1].buf   = pRx;
    messages[1].buf[0] = 1;

    // NOTE:
    // By passing the two message structures via the packets structure as
    // a parameter to the ioctl call one ensures a Repeated Start is triggered.
    packets.msgs      = messages;
    packets.nmsgs     = 2;

    LOG_MAU8_D("TX (axI2CWriteRead ) > ",&packets.msgs[0].buf[i], txLen);

    // Send the request to the kernel and get the result back
    r = ioctl(axSmDevice, I2C_RDWR, &packets);

    // NOTE:
    // The ioctl return value in case of a NACK on the write address is '-1'
    // This impacts the error handling routine of the caller.
    // If possible distinguish between a general I2C error and a NACK on address
    // The way to do this is platform specific (depends on I2C bus driver).
    if (r < 0)
    {
        // LOG_E("axI2CWriteRead: ioctl cmd I2C_RDWR fails with value %d (errno: 0x%08X)\n", r, errno);
        // perror("Errorstring: ");
#ifdef PLATFORM_IMX
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
        #define E_NACK_I2C_IMX ENXIO
        // #warning "ENXIO"
    #else
        #define E_NACK_I2C_IMX EIO
        // #warning "EIO"
    #endif // LINUX_VERSION_CODE
        // In case of IMX, errno == E_NACK_I2C_IMX is not exclusively bound to NACK on address,
        // it can also signal a NACK on a data byte
        if (errno == E_NACK_I2C_IMX) {
            // I2C_LOG_PRINTF("axI2CWriteRead: ioctl signal NACK (errno = %d)\n", errno);
            return I2C_NACK_ON_ADDRESS;
        }
        else {
            // printf("axI2CWriteRead: ioctl error (errno = %d)\n", errno);
            return I2C_FAILED;
        }
#else
        // I2C_LOG_PRINTF("axI2CWriteRead: ioctl cmd I2C_RDWR fails with value %d (errno: 0x%08X)\n", r, errno);
        return I2C_FAILED;
#endif // PLATFORM_IMX
    }
    else
    {
        int rlen = packets.msgs[1].buf[0]+1;

        //I2C_LOG_PRINTF("packets.msgs[1].len is %d \n", packets.msgs[1].len);
        LOG_MAU8_D("RX (axI2CWriteRead) < ",&packets.msgs[1].buf[i], rlen);
        for (i = 0; i < rlen; i++)
        {
            pRx[i] = packets.msgs[1].buf[i];
        }
        *pRxLen = rlen;
    }

    return I2C_OK;
}
#endif // defined(SCI2C)

#ifdef T1oI2C
i2c_error_t axI2CRead(void* conn_ctx, unsigned char bus, unsigned char addr, unsigned char * pRx, unsigned short rxLen)
{
    int nrRead = -1;
    i2c_error_t rv;
    int axSmDevice = *(int*)conn_ctx;

    if (bus != I2C_BUS_0)
    {
        LOG_E("axI2CRead on wrong bus %x (addr %x)\n", bus, addr);
    }

   nrRead = read(axSmDevice, pRx, rxLen);
   if (nrRead < 0)
   {
      //LOG_E("Failed Read data (nrRead=%d).\n", nrRead);
      rv = I2C_FAILED;
   }
   else
   {
        if (nrRead == rxLen) // okay
        {
            rv = I2C_OK;
        }
        else
        {
            rv = I2C_FAILED;
        }
   }
    LOG_D("Done with rv = %02x ", rv);
    LOG_MAU8_D("TX (axI2CRead): ",pRx,rxLen);
    return rv;
}
#endif // T1oI2C
