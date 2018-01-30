/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef KERNEL_VIRTUALIZATION_H
#define KERNEL_VIRTUALIZATION_H

#include <stdbool.h>
#include <stdint.h>

uint32_t client_created(uint16_t client_id);
uint32_t client_destroyed(uint16_t client_id);
bool check_client(uint16_t client_id);

#endif	/* KERNEL_VIRTUALIZATION_H */
