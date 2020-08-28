/*
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 *
 * @par Description
 * This file provides an interface to generic APDU response evaluation.
 * @par History
 * 1.0   20-feb-2012 : Initial version
 *
 */

#ifndef _SM_ERRORS_
#define _SM_ERRORS_

#include "apduComm.h"

#ifdef __cplusplus
extern "C" {
#endif

U16 CheckNoResponseData(apdu_t * pApdu);
U16 CheckNoResponseDataRaw(U8 *rawResponse, U16 rawResponseLen);

#ifdef __cplusplus
}
#endif
#endif //_SM_ERRORS_
