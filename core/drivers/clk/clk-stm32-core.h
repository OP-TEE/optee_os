/* SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause) */
/*
 * Copyright (C) STMicroelectronics 2022 - All Rights Reserved
 */

#ifndef CLK_STM32_CORE_H
#define CLK_STM32_CORE_H

#include <drivers/clk.h>

struct mux_cfg {
	uint16_t offset;
	uint8_t shift;
	uint8_t width;
	uint8_t ready;
};

struct gate_cfg {
	uint16_t offset;
	uint8_t bit_idx;
	uint8_t set_clr;
};

struct div_table_cfg {
	unsigned int val;
	unsigned int div;
};

struct div_cfg {
	uint16_t offset;
	uint8_t shift;
	uint8_t width;
	uint8_t flags;
	uint8_t ready;
	const struct div_table_cfg *table;
};

struct clk_stm32_priv {
	uintptr_t base;
	const struct mux_cfg *muxes;
	const uint32_t nb_muxes;
	const struct gate_cfg *gates;
	const uint32_t nb_gates;
	const struct div_cfg *div;
	const uint32_t nb_div;
	void *pdata;
};

struct clk_fixed_rate_cfg {
	unsigned long rate;
};

struct fixed_factor_cfg {
	unsigned int mult;
	unsigned int div;
};

struct clk_gate_cfg {
	uint32_t offset;
	uint8_t bit_idx;
};

struct clk_stm32_mux_cfg {
	int mux_id;
};

struct clk_stm32_gate_cfg {
	int gate_id;
};

struct clk_stm32_div_cfg {
	int div_id;
};

struct clk_stm32_composite_cfg {
	int gate_id;
	int div_id;
	int mux_id;
};

struct clk_stm32_timer_cfg {
	uint32_t apbdiv;
	uint32_t timpre;
};

struct clk_stm32_gate_ready_cfg {
	int gate_id;
	int gate_rdy_id;
};

/* Define for divider clocks */
#define CLK_DIVIDER_ONE_BASED		BIT(0)
#define CLK_DIVIDER_POWER_OF_TWO	BIT(1)
#define CLK_DIVIDER_ALLOW_ZERO		BIT(2)
#define CLK_DIVIDER_HIWORD_MASK		BIT(3)
#define CLK_DIVIDER_ROUND_CLOSEST	BIT(4)
#define CLK_DIVIDER_READ_ONLY		BIT(5)
#define CLK_DIVIDER_MAX_AT_ZERO		BIT(6)
#define CLK_DIVIDER_BIG_ENDIAN		BIT(7)

#define DIV_NO_RDY		UINT8_MAX
#define MUX_NO_RDY		UINT8_MAX

#define MASK_WIDTH_SHIFT(_width, _shift) \
	GENMASK_32(((_width) + (_shift) - 1U), (_shift))

/* Define for composite clocks */
#define NO_MUX		INT32_MAX
#define NO_DIV		INT32_MAX
#define NO_GATE		INT32_MAX

void stm32_gate_enable(uint16_t gate_id);
void stm32_gate_disable(uint16_t gate_id);
bool stm32_gate_is_enabled(uint16_t gate_id);
TEE_Result stm32_gate_wait_ready(uint16_t gate_id, bool ready_on);
TEE_Result stm32_gate_rdy_enable(uint16_t gate_id);
TEE_Result stm32_gate_rdy_disable(uint16_t gate_id);

size_t stm32_mux_get_parent(uint32_t mux_id);
TEE_Result stm32_mux_set_parent(uint16_t pid, uint8_t sel);

TEE_Result stm32_div_set_rate(int div_id, unsigned long rate,
			      unsigned long prate);

uint32_t stm32_div_get_value(int div_id);
TEE_Result stm32_div_set_value(uint32_t div_id, uint32_t value);

int clk_stm32_parse_fdt_by_name(const void *fdt, int node, const char *name,
				uint32_t *tab, uint32_t *nb);

struct clk_stm32_priv *clk_stm32_get_priv(void);
uintptr_t clk_stm32_get_rcc_base(void);

TEE_Result clk_stm32_init(struct clk_stm32_priv *priv, uintptr_t base);

#endif /* CLK_STM32_CORE_H */
