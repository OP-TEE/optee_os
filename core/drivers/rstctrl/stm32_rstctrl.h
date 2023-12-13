/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, STMicroelectronics
 */

#include <drivers/rstctrl.h>
#include <sys/queue.h>

/*
 * struct stm32_reset_data - Reset controller platform data
 * @get_rstctrl_ops: Handler to retrieve the controller operation handlers
 */
struct stm32_reset_data {
	struct rstctrl_ops * (*get_rstctrl_ops)(unsigned int id);
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
	SLIST_ENTRY(stm32_rstline) link;
};

struct stm32_rstline *to_stm32_rstline(struct rstctrl *rstctrl);

TEE_Result stm32_rstctrl_provider_probe(const void *fdt, int offs,
					const void *compat_data);
