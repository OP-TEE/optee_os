/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Bootlin
 */

#ifndef __DRIVERS_CLK_H
#define __DRIVERS_CLK_H

#include <kernel/refcount.h>
#include <stdint.h>
#include <tee_api_types.h>

/* Flags for clock */
#define CLK_SET_RATE_GATE	BIT(0) /* must be gated across rate change */
#define CLK_SET_PARENT_GATE	BIT(1) /* must be gated across re-parent */

/**
 * struct clk - Clock structure
 *
 * @name: Clock name
 * @priv: Private data for the clock provider
 * @ops: Clock operations
 * @parent: Current parent
 * @rate: Current clock rate (cached after init or rate change)
 * @flags: Specific clock flags
 * @enabled_count: Enable/disable reference counter
 * @num_parents: Number of parents
 * @parents: Array of possible parents of the clock
 */
struct clk {
	const char *name;
	void *priv;
	const struct clk_ops *ops;
	struct clk *parent;
	unsigned long rate;
	unsigned int flags;
	struct refcount enabled_count;
	size_t num_parents;
	struct clk *parents[];
};

/**
 * struct clk_ops
 *
 * @enable: Enable the clock
 * @disable: Disable the clock
 * @set_parent: Set the clock parent based on index
 * @get_parent: Get the current parent index of the clock
 * @set_rate: Set the clock rate
 * @get_rate: Get the clock rate
 */
struct clk_ops {
	TEE_Result (*enable)(struct clk *clk);
	void (*disable)(struct clk *clk);
	TEE_Result (*set_parent)(struct clk *clk, size_t index);
	size_t (*get_parent)(struct clk *clk);
	TEE_Result (*set_rate)(struct clk *clk, unsigned long rate,
			       unsigned long parent_rate);
	unsigned long (*get_rate)(struct clk *clk,
				  unsigned long parent_rate);
};

/**
 * Return the clock name
 *
 * @clk: Clock for which the name is needed
 * Return a const char * pointing to the clock name
 */
static inline const char *clk_get_name(struct clk *clk)
{
	return clk->name;
}

/**
 * clk_alloc - Allocate a clock structure
 *
 * @name: Clock name
 * @ops: Clock operations
 * @parent_clks: Parents of the clock
 * @parent_count: Number of parents of the clock
 *
 * Return a clock struct properly initialized or NULL if allocation failed
 */
struct clk *clk_alloc(const char *name, const struct clk_ops *ops,
		      struct clk **parent_clks, size_t parent_count);

/**
 * clk_free - Free a clock structure
 *
 * @clk: Clock to be freed or NULL
 */
void clk_free(struct clk *clk);

/**
 * clk_register - Register a clock within the clock framework
 *
 * @clk: Clock struct to be registered
 * Return a TEE_Result compliant value
 */
TEE_Result clk_register(struct clk *clk);

/**
 * clk_get_rate - Get clock rate
 *
 * @clk: Clock for which the rate is needed
 * Return the clock rate in Hz
 */
unsigned long clk_get_rate(struct clk *clk);

/**
 * clk_set_rate - Set a clock rate
 *
 * @clk: Clock to be set with the rate
 * @rate: Rate to set in Hz
 * Return a TEE_Result compliant value
 */
TEE_Result clk_set_rate(struct clk *clk, unsigned long rate);

/**
 * clk_enable - Enable a clock and its ascendance
 *
 * @clk: Clock to be enabled
 * Return a TEE_Result compliant value
 */
TEE_Result clk_enable(struct clk *clk);

/**
 * clk_disable - Disable a clock
 *
 * @clk: Clock to be disabled
 */
void clk_disable(struct clk *clk);

/**
 * clk_is_enabled - Informative state on the clock
 *
 * This function is useful during specific system sequences where core
 * executes atomically (primary core boot, some low power sequences).
 *
 * @clk: Clock refernece
 */
bool clk_is_enabled(struct clk *clk);

/**
 * clk_get_parent - Get the current clock parent
 *
 * @clk: Clock for which the parent is needed
 * Return the clock parent or NULL if there is no parent
 */
struct clk *clk_get_parent(struct clk *clk);

/**
 * clk_get_num_parents - Get the number of parents for a clock
 *
 * @clk: Clock for which the number of parents is needed
 * Return the number of parents
 */
static inline size_t clk_get_num_parents(struct clk *clk)
{
	return clk->num_parents;
}

/**
 * Get a clock parent by its index
 *
 * @clk: Clock for which the parent is needed
 * @pidx: Parent index for the clock
 * Return the clock parent at index @pidx or NULL if out of bound
 */
struct clk *clk_get_parent_by_index(struct clk *clk, size_t pidx);

/**
 * clk_set_parent - Set the current clock parent
 *
 * @clk: Clock for which the parent should be set
 * @parent: Parent clock to set
 * Return a TEE_Result compliant value
 */
TEE_Result clk_set_parent(struct clk *clk, struct clk *parent);

#endif /* __DRIVERS_CLK_H */
