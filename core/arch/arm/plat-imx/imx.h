/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2019 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */
#ifndef PLAT_IMX_IMX_H
#define PLAT_IMX_IMX_H

#include <stdint.h>
#include <stdbool.h>

#define SOC_MX6SL	0x60
#define SOC_MX6DL	0x61
#define SOC_MX6SX	0x62
#define SOC_MX6Q	0x63
#define SOC_MX6UL	0x64
#define SOC_MX6ULL	0x65
#define SOC_MX6SLL	0x67
#define SOC_MX6D	0x6A
#define SOC_MX7D	0x72
#define SOC_MX7ULP	0xE1
#define SOC_MX8QX	0xE2
#define SOC_MX8QM	0xE3
#define SOC_MX8DXL	0xE4
#define SOC_MX8M	0x82
#define SOC_MX8ULP	0x83
#define SOC_MX93	0xC1

#ifndef __ASSEMBLER__
bool soc_is_imx6(void);
bool soc_is_imx6sx(void);
bool soc_is_imx6sl(void);
bool soc_is_imx6sll(void);
bool soc_is_imx6ul(void);
bool soc_is_imx6ull(void);
bool soc_is_imx6sdl(void);
bool soc_is_imx6dq(void);
bool soc_is_imx6dqp(void);
bool soc_is_imx7ds(void);
bool soc_is_imx7ulp(void);
bool soc_is_imx8m(void);
bool soc_is_imx8mq(void);
bool soc_is_imx8mm(void);
bool soc_is_imx8mn(void);
bool soc_is_imx8mp(void);
bool soc_is_imx8mq_b0_layer(void);
uint32_t imx_soc_type(void);
uint32_t imx_soc_rev_major(void);
uint32_t imx_soc_rev_minor(void);
uint32_t imx_get_digprog(void);
#endif /* __ASSEMBLER__ */
#endif
