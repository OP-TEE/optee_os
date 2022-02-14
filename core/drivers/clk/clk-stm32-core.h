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
	size_t nb_clk_refs;
	struct clk **clk_refs;
	const struct mux_cfg *muxes;
	const uint32_t nb_muxes;
	const struct gate_cfg *gates;
	const uint32_t nb_gates;
	const struct div_cfg *div;
	const uint32_t nb_div;
	bool (*is_critical)(struct clk *clk);
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

unsigned long clk_stm32_divider_get_rate(struct clk *clk,
					 unsigned long parent_rate);

TEE_Result clk_stm32_divider_set_rate(struct clk *clk,
				      unsigned long rate,
				      unsigned long parent_rate);

size_t clk_stm32_composite_get_parent(struct clk *clk);
TEE_Result clk_stm32_composite_set_parent(struct clk *clk, size_t pidx);
unsigned long clk_stm32_composite_get_rate(struct clk *clk,
					   unsigned long parent_rate);
TEE_Result clk_stm32_composite_set_rate(struct clk *clk, unsigned long rate,
					unsigned long parent_rate);
TEE_Result clk_stm32_composite_gate_enable(struct clk *clk);
void clk_stm32_composite_gate_disable(struct clk *clk);

TEE_Result clk_stm32_set_parent_by_index(struct clk *clk, size_t pidx);

extern const struct clk_ops clk_fixed_factor_ops;
extern const struct clk_ops clk_fixed_clk_ops;
extern const struct clk_ops clk_stm32_gate_ops;
extern const struct clk_ops clk_stm32_gate_ready_ops;
extern const struct clk_ops clk_stm32_divider_ops;
extern const struct clk_ops clk_stm32_mux_ops;
extern const struct clk_ops clk_stm32_composite_ops;

#define PARENT(x...) { x }

#define STM32_FIXED_RATE(_name, _rate)\
	struct clk _name = {\
		.ops = &clk_fixed_clk_ops,\
		.priv = &(struct clk_fixed_rate_cfg) {\
			.rate = (_rate),\
		},\
		.name = #_name,\
		.flags = 0,\
		.num_parents = 0,\
	}

#define STM32_FIXED_FACTOR(_name, _parent, _flags, _mult, _div)\
	struct clk _name = {\
		.ops = &clk_fixed_factor_ops,\
		.priv = &(struct fixed_factor_cfg) {\
			.mult = _mult,\
			.div = _div,\
		},\
		.name = #_name,\
		.flags = (_flags),\
		.num_parents = 1,\
		.parents = { (_parent) },\
	}

#define STM32_GATE(_name, _parent, _flags, _gate_id)\
	struct clk _name = {\
		.ops = &clk_stm32_gate_ops,\
		.priv = &(struct clk_stm32_gate_cfg) {\
			.gate_id = _gate_id,\
		},\
		.name = #_name,\
		.flags = (_flags),\
		.num_parents = 1,\
		.parents = { (_parent) },\
	}

#define STM32_DIVIDER(_name, _parent, _flags, _div_id)\
	struct clk _name = {\
		.ops = &clk_stm32_divider_ops,\
		.priv = &(struct clk_stm32_div_cfg) {\
			.div_id = (_div_id),\
		},\
		.name = #_name,\
		.flags = (_flags),\
		.num_parents = 1,\
		.parents = { (_parent) },\
	}

#define STM32_MUX(_name, _nb_parents, _parents, _flags, _mux_id)\
	struct clk _name = {\
		.ops = &clk_stm32_mux_ops,\
		.priv = &(struct clk_stm32_mux_cfg) {\
			.mux_id = (_mux_id),\
		},\
		.name = #_name,\
		.flags = (_flags),\
		.num_parents = (_nb_parents),\
		.parents = _parents,\
	}

#define STM32_GATE_READY(_name, _parent, _flags, _gate_id)\
	struct clk _name = {\
		.ops = &clk_stm32_gate_ready_ops,\
		.priv = &(struct clk_stm32_gate_cfg) {\
			.gate_id = _gate_id,\
		},\
		.name = #_name,\
		.flags = (_flags),\
		.num_parents = 1,\
		.parents = { _parent },\
	}

#define STM32_COMPOSITE(_name, _nb_parents, _parents, _flags,\
			_gate_id, _div_id, _mux_id)\
	struct clk _name = {\
		.ops = &clk_stm32_composite_ops,\
		.priv = &(struct clk_stm32_composite_cfg) {\
			.gate_id = (_gate_id),\
			.div_id = (_div_id),\
			.mux_id = (_mux_id),\
		},\
		.name = #_name,\
		.flags = (_flags),\
		.num_parents = (_nb_parents),\
		.parents = _parents,\
	}

struct clk_stm32_priv *clk_stm32_get_priv(void);
uintptr_t clk_stm32_get_rcc_base(void);

TEE_Result clk_stm32_init(struct clk_stm32_priv *priv, uintptr_t base);

void stm32mp_clk_provider_probe_final(const void *fdt, int node,
				      struct clk_stm32_priv *priv);

#endif /* CLK_STM32_CORE_H */
