/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 *
 * Empty implementation for undefined symbols due to our use case not selecting
 * all the files in the se05 middleware
 */

#ifndef WRAPS_H
#define WRAPS_H

sss_status_t sm_sleep(uint32_t ms);
int rand(void);
void srand(unsigned int seed);
unsigned int time(void *foo __unused);

#endif /* WRAPS_H */
