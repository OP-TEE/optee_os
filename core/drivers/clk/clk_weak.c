// SPDX-License-Identifier: (BSD-2-Clause)
/*
 * Copyright (C) 2021, Linaro Limited
 */

#include <drivers/clk.h>
#include <tee_api_defines.h>

/* Weak functions for the clock driver. Platform implements the needed API */

const char __weak *clk_get_name(struct clk *clk __unused)
{
	static const char no_name[] = "n.a";

	return no_name;
}

unsigned long __weak clk_get_rate(struct clk *clk __unused)
{
	return 0;
}

TEE_Result __weak clk_set_rate(struct clk *clk __unused,
			       unsigned long rate __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result __weak clk_enable(struct clk *clk __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void __weak clk_disable(struct clk *clk __unused)
{
}

struct clk __weak *clk_get_parent(struct clk *clk __unused)
{
	return NULL;
}

size_t __weak clk_get_num_parents(struct clk *clk __unused)
{
	return 0;
}

struct clk __weak *clk_get_parent_by_index(struct clk *clk __unused,
					   size_t pidx __unused)
{
	return NULL;
}

TEE_Result __weak clk_set_parent(struct clk *clk __unused,
				 struct clk *parent __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
