/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Bootlin
 */

#ifndef __DRIVERS_CLK_H
#define __DRIVERS_CLK_H

#include <assert.h>
#include <kernel/refcount.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <util.h>

/* Flags for clock */
#define CLK_SET_RATE_GATE	BIT(0) /* must be gated across rate change */
#define CLK_SET_PARENT_GATE	BIT(1) /* must be gated across re-parent */

/*
 * Type of clock instantiated:
 *
 * CLK_OP_ELT identities a full fledged clock. The struct clk * reference can be
 * cast to struct clk_elt * to access clock element data.
 *
 * CLK_OP_ORPHAN identifies a simple clock without parents. struct clk fully
 * represents the clock.
 */
enum clk_ops_id {
	CLK_OPS_INVALID = 0,
	CLK_OPS_ELT,
	CLK_OPS_ORPHAN,
};

/**
 * struct clk - Minimal clock core structure
 *
 * This minimalist core clock struct is intended to clock drivers
 * that need to optimatize their RAM footprint.
 *
 * @ops: Clock operations
 * @enabled_count: Enable/disable reference counter
 */
struct clk {
	const struct clk_ops *ops;
	struct refcount enabled_count;
};

/**
 * struct clk_elt - Full-fledged clock element
 *
 * @clk: Clock core structure
 * @priv: Private data for the clock provider
 * @name: Clock name
 * @rate: Current clock rate (cached after init or rate change)
 * @flags: Specific clock flags
 * @parent: Current parent
 * @num_parents: Number of parents
 * @parents: Array of possible parents of the clock
 */
struct clk_elt {
	struct clk clk;
	void *priv;
	unsigned long rate;
	const char *name;
	unsigned int flags;
	struct clk *parent;
	size_t num_parents;
	struct clk *parents[];
};

/**
 * struct clk_ops - Clock operations
 * @id: Identifier of the ops type (actually not an operator)
 * @enable: Enable the clock
 * @disable: Disable the clock
 * @set_parent: Set the clock parent based on index
 * @get_parent: Get the current parent index of the clock
 * @set_rate: Set the clock rate
 * @get_rate: Get the clock rate
 * @get_name: Get clock name (shall be clk_elt_name() when @id is CLK_OPS_ELT)
 */
struct clk_ops {
	enum clk_ops_id id;
	TEE_Result (*enable)(struct clk *clk);
	void (*disable)(struct clk *clk);
	TEE_Result (*set_parent)(struct clk *clk, size_t index);
	size_t (*get_parent)(struct clk *clk);
	TEE_Result (*set_rate)(struct clk *clk, unsigned long rate,
			       unsigned long parent_rate);
	unsigned long (*get_rate)(struct clk *clk,
				  unsigned long parent_rate);
	const char *(*get_name)(struct clk *clk);
};

/*
 * Helper to identify clock operator type
 */
static inline bool is_clk_elt(struct clk *clk)
{
	return clk->ops->id == CLK_OPS_ELT;
}

static inline struct clk_elt *clk_to_clk_elt(struct clk *clk)
{
	assert(is_clk_elt(clk));

	return container_of(clk, struct clk_elt, clk);
}

static inline bool is_clk_orphan(struct clk *clk)
{
	return clk->ops->id == CLK_OPS_ORPHAN;
}

/**
 * Return the clock name
 *
 * @clk: Clock for which the name is needed
 * Return a const char * pointing to the clock name
 */
const char *clk_get_name(struct clk *clk);

/**
 * Mandated get_name operator when for struct clk_elt instances
 *
 * @clk: Clock for which the name is needed
 * Return a const char * pointing to the clock name
 *
 * This function mandates @clk refers to a struct clk_elt instance
 */
const char *clk_elt_name(struct clk *clk);

/**
 * clk_alloc - Allocate and initialize a clock instance
 *
 * @name: Clock name or NULL
 * @ops: Clock operations
 * @parent_clks: Parents of the clock
 * @parent_count: Number of parents of the clock
 *
 * Return a struct clk * or NULL if allocation failed.
 * The return address actually points to a struct clk_elt instance.
 * One can use clk_to_clk_elt() to convert the reference type.
 */
struct clk *clk_alloc(const char *name, const struct clk_ops *ops,
		      struct clk **parent_clks, size_t parent_count);

/**
 * clk_alloc_orphans - Allocate and initialize an array of orphan clocks
 *
 * @ops: Clock operations
 * @count: Number of clocks (> 0)
 *
 * Returns a clock struct properly initialized or NULL if allocation failed
 */
struct clk *clk_alloc_orphans(const struct clk_ops *ops, size_t count);

/**
 * clk_init_instance - Initialize a clock instance
 *
 * @clk: Reference to clock instance to initialize
 * @ops: Clock operations pointner for the clock
 */
void clk_init_instance(struct clk *clk, const struct clk_ops *ops);

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
size_t clk_get_num_parents(struct clk *clk);

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
