/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, STMicroelectronics
 */

#include <drivers/rstctrl.h>
#include <stdbool.h>
#include <sys/queue.h>

/*
 * struct stm32_reset_cfg - Reset line controller data
 * @offset: Byte offset in reset controller IOMEM
 * @bit_index: Bit position of reset line control at IOMEM @offset
 * @set_clr: True is @offset is an atomic SET/CLR register, false otherwise
 * @inverted: True is reset line is asserted at level 0, false otherwise
 * @no_deassert: True is reset line cannot be deasserted, false otherwise
 * @no_timeout: True if reset state cannot be read back for timeout detection
 */
struct stm32_reset_cfg {
	unsigned int offset;
	unsigned int bit_index;
	bool set_clr;
	bool inverted;
	bool no_deassert;
	bool no_timeout;
};

/*
 * struct stm32_reset_data - Reset controller platform data
 * @nb_lines: Number of reset lines
 * @rst_lines: Table of reset lines
 * @get_rstctrl_ops: Handler to retrieve the controller operation handlers
 */
struct stm32_reset_data {
	unsigned int nb_lines;
	const struct stm32_reset_cfg **rst_lines;
	const struct rstctrl_ops * (*get_rstctrl_ops)(unsigned int id);
};

/*
 * struct stm32_rstline - Exposed rstctrl instance
 * @id: Identifier used in the device tree bindings
 * @rstctrl: Related reset controller instance
 * @link: Reference in reset controller list
 */
struct stm32_rstline {
	unsigned int id;
	struct rstctrl rstctrl;
	const struct stm32_reset_data *data;
	SLIST_ENTRY(stm32_rstline) link;
};

struct stm32_rstline *to_stm32_rstline(struct rstctrl *rstctrl);

TEE_Result stm32_rstctrl_provider_probe(const void *fdt, int offs,
					const void *compat_data);
