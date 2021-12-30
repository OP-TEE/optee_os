/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Devendra Devadiga
 */

#ifndef __PTA_BOOT_LOG_H
#define __PTA_BOOT_LOG_H


#define BOOT_LOG_SERVICE_UUID \
        { 0x60276949, 0x7FF3, 0x4920, \
                { 0x9B, 0xCE, 0x84, 0x0C, 0x9D, 0xCF, 0x30, 0x98 } }

#define PTA_BOOT_LOG_NAME                   "pta.bootlog"

/*
 * Get boot log memory message
 *
 * [out]    memref[0]:    Destination
 * [out]    value[0].a:   Length of log
 * [out]    memref.size:  Size of buffer alloocated
 */
#define PTA_BOOT_LOG_GET_MSG		1

/*
 * Get size of boot log message
 *
 * [out]    value[0].a:   Length of log
 */

#define PTA_BOOT_LOG_GET_SIZE		2

/*
 * Set length of log to zero i.e clear the log
 *
 * [out/in]   None:   Length of log
 */

#define PTA_BOOT_LOG_CLEAR		3

#endif /* __PTA_BOOT_LOG_H */
