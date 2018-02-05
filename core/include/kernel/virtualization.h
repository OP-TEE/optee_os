/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef KERNEL_VIRTUALIZATION_H
#define KERNEL_VIRTUALIZATION_H

#include <stdbool.h>
#include <stdint.h>

uint32_t virt_guest_created(uint16_t client_id);
uint32_t virt_guest_destroyed(uint16_t client_id);
bool check_virt_guest(uint16_t client_id);

#endif	/* KERNEL_VIRTUALIZATION_H */
