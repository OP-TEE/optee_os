/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026, Owen O'Hehir
 *
 * Symbols that psci_rk3506.c needs from the two assembly files: the
 * secondary-CPU wait loop in pen_rk3506.S and the CPU power-down
 * routine in plat_init_rk3506.S.
 */

#ifndef PLAT_ROCKCHIP_PEN_RK3506_H
#define PLAT_ROCKCHIP_PEN_RK3506_H

#include <compiler.h>
#include <stdint.h>
#include <types_ext.h>

/*
 * Start and end of the small wait loop in pen_rk3506.S. psci_rk3506.c
 * copies the code between these symbols into IRAM, so it is written to
 * run correctly from any address.
 */
extern const uint8_t rk3506_pen_start[];
extern const uint8_t rk3506_pen_end[];

/*
 * Takes the calling CPU offline: turns off its MMU and sends it back to
 * the wait loop. Defined in plat_init_rk3506.S.
 */
void __noreturn rk3506_cpu_down(vaddr_t pen_pa);

#endif /* PLAT_ROCKCHIP_PEN_RK3506_H */
