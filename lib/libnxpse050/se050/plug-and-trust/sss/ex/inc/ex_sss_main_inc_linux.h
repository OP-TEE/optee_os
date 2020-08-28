/*
 * Copyright 2019 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ax_reset.h"

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

void ex_sss_main_linux_conf()
{
    axReset_HostConfigure();
    axReset_PowerUp();
}

void ex_sss_main_linux_unconf()
{
    axReset_PowerDown();
    axReset_HostUnconfigure();
}
