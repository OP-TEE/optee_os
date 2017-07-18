/*
 * Copyright 2017 NXP
 * All rights reserved.
 *
 * Peng Fan <peng.fan@nxp.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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

uint32_t imx_get_src_gpr(int cpu);
void imx_set_src_gpr(int cpu, uint32_t val);

bool soc_is_imx6ul(void);
bool soc_is_imx6ull(void);
bool soc_is_imx6sdl(void);
bool soc_is_imx6dq(void);
bool soc_is_imx6dqp(void);
bool soc_is_imx7ds(void);
bool soc_is_imx7d(void);
bool soc_is_imx7s(void);
uint32_t imx_soc_type(void);
void imx_gpcv2_set_core1_pdn_by_software(void);
void imx_gpcv2_set_core1_pup_by_software(void);
void imx_gpcv2_set_core_pgc(bool enable, uint32_t offset);
#endif
