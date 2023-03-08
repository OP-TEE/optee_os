/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#ifndef __DRIVERS_HFIC_H
#define __DRIVERS_HFIC_H
#include <kernel/interrupt.h>

struct hfic_data {
	struct itr_chip chip;
};

void hfic_init(struct hfic_data *hd);
void hfic_it_handle(struct hfic_data *hd);

#endif /*__DRIVERS_HFIC_H*/
