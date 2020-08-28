/*
 * Copyright 2018-2019 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _AX_RESET_H
#define _AX_RESET_H

#include "sm_types.h"

/*
 * Where applicable, Configure the PINs on the Host
 *
 */
void axReset_HostConfigure(void);

/*
 * Where applicable, PowerCycle the SE
 *
 * Pre-Requistie: @ref axReset_Configure has been called
 */
void axReset_ResetPluseDUT(void);

/*
 * Where applicable, put SE in low power/standby mode
 *
 * Pre-Requistie: @ref axReset_Configure has been called
 */
void axReset_PowerDown(void);

/*
 * Where applicable, put SE in powered/active mode
 *
 * Pre-Requistie: @ref axReset_Configure has been called
 */
void axReset_PowerUp(void);

/*
 * Where applicable, Unconfigure the PINs on the Host
 *
 */
void axReset_HostUnconfigure(void);

#endif // _AX_RESET_H
