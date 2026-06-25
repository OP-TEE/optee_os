/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __XPORT_QMP_H
#define __XPORT_QMP_H

/*
 * xport_qmp_init() - Initialize QMP transport
 *
 * This function initializes the QMP transport layer for TME communication.
 * It should be called during driver initialization.
 */
void xport_qmp_init(void);

#endif /* __XPORT_QMP_H */
