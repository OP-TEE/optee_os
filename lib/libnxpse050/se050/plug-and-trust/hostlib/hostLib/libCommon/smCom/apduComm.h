/*
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _APDUCOMM_H_
#define _APDUCOMM_H_

#include "sm_types.h"
/// @cond
#define APDU_OFFSET_CLA                 (0)
#define APDU_OFFSET_INS                 (1)
#define APDU_OFFSET_P1                  (2)
#define APDU_OFFSET_P2                  (3)
/// @endcond
#define APDU_OFFSET_LC                  (4) //!< Zero index based offset into the APDU of the LC field.

/**
 * Contains APDU exchanged between Host and Secure Modulde.
 */
typedef struct
{
    U8 cla;
    U8 ins;
    U8 p1;
    U8 p2;
    U8* pBuf;
    U16 buflen;
    U16 rxlen;
    U8 extendedLength;
    U8 hasData;
    U16 lc;
    U8 lcLength;
    U8 hasLe;
    U16 le;
    U8 leLength;
    U16 offset;

#ifdef TGT_A71CL
    U8 txHasChkSum;
    U16 txChkSum;
    U16 txChkSumLength;
    U8 rxHasChkSum;
    U16 rxChkSum;
    U16 rxChkSumLength;
#endif

} apdu_t;

/**
 * Contains APDU TxRx case as described in ISO/IEC FDIS 7816-3 spec.
 */
typedef enum
{
    APDU_TXRX_CASE_1  = 0x00,
    APDU_TXRX_CASE_2  = 0x01,
    APDU_TXRX_CASE_2E = 0x02,
    APDU_TXRX_CASE_3  = 0x03,
    APDU_TXRX_CASE_3E = 0x04,
    APDU_TXRX_CASE_4  = 0x05,
    APDU_TXRX_CASE_4E = 0x06,
    APDU_TXRX_CASE_INVALID = 0xFF,
} apduTxRx_case_t;
#endif //_APDUCOMM_H_
