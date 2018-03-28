/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2018 EPAM Systems. All rights reserved. */

#ifndef KERNEL_VIRTUALIZATION_H
#define KERNEL_VIRTUALIZATION_H

#include <stdbool.h>
#include <stdint.h>

#define HYP_CLIENT_ID		0
#define INVALID_CLIENT_ID	0xFFFF

uint32_t virt_guest_created(uint16_t client_id);
uint32_t virt_guest_destroyed(uint16_t client_id);
bool check_virt_guest(uint16_t client_id);

#endif	/* KERNEL_VIRTUALIZATION_H */
