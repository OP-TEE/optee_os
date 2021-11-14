// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Bootlin
 */

#include <assert.h>
#include <drivers/clk.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <malloc.h>
#include <stddef.h>

/* Global clock tree lock */
static unsigned int clk_lock = SPINLOCK_UNLOCK;

void clk_init_instance(struct clk *clk, const struct clk_ops *ops)
{
	assert(clk && ops &&
	       (ops->id == CLK_OPS_STANDARD ||
		(ops->id == CLK_OPS_LIGHTWEIGHT && !ops->set_parent &&
		 !ops->get_parent)));

	clk->ops = ops;
	refcount_set(&clk->enabled_count, 0);
}

struct clk *clk_alloc(const char *name, const struct clk_ops *ops,
		      struct clk **parent_clks, size_t parent_count)
{
	struct clk_std *clk_std = NULL;
	size_t parent = 0;

	assert(ops->id == CLK_OPS_STANDARD);
	if (name && !ops->get_name)
		DMSG("Clock name unregistered for %s", name);

	clk_std = calloc(1, sizeof(*clk_std) +
			 parent_count * sizeof(*parent_clks));
	if (!clk_std)
		return NULL;

	clk_std->num_parents = parent_count;
	for (parent = 0; parent < parent_count; parent++)
		clk_std->parents[parent] = parent_clks[parent];

	clk_std->name = name;
	clk_init_instance(&clk_std->clk, ops);

	return &clk_std->clk;
}

void clk_std_free(struct clk *clk)
{
	if (clk)
		free(clk_to_clk_std(clk));
}

struct clk *clk_lw_alloc(const struct clk_ops *ops, size_t count)
{
	struct clk *clk = NULL;
	size_t n = 0;

	assert(ops->id == CLK_OPS_LIGHTWEIGHT);

	clk = calloc(count, sizeof(*clk));
	if (!clk)
		return NULL;

	for (n = 0; n < count; n++)
		clk_init_instance(clk + n, ops);

	return clk;
}

void clk_lw_free(struct clk *clk)
{
	free(clk);
}

static bool __maybe_unused clk_check(struct clk *clk)
{
	if (!clk->ops)
		return false;

	if (is_clk_std(clk)) {
		struct clk_std *clk_std = clk_to_clk_std(clk);

		if (clk->ops->set_parent && !clk->ops->get_parent)
			return false;

		if (clk_std->num_parents > 1 && !clk->ops->get_parent)
			return false;

		return true;
	}

	if (is_clk_lw(clk)) {
		if (clk->ops->set_parent || clk->ops->get_parent) {
			DMSG("Unpexpected parent clock ops on clock %s",
			     clk_get_name(clk));
			return false;
		}

		return true;
	}

	return false;
}

static void cache_rate_no_lock(struct clk *clk)
{
	unsigned long parent_rate = 0;
	struct clk_std *clk_std = NULL;

	if (!is_clk_std(clk))
		return;

	clk_std = clk_to_clk_std(clk);
	if (clk_std->parent)
		parent_rate = clk_get_rate(clk_std->parent);

	if (clk->ops->compute_rate)
		clk_std->rate = clk->ops->compute_rate(clk, parent_rate);
	else
		clk_std->rate = parent_rate;
}

struct clk *clk_get_parent_by_index(struct clk *clk, size_t pidx)
{
	if (!is_clk_std(clk))
		return NULL;

	if (pidx >= clk_to_clk_std(clk)->num_parents)
		return NULL;

	return clk_to_clk_std(clk)->parents[pidx];
}

static void clk_init_parent(struct clk *clk)
{
	struct clk_std *clk_std = NULL;
	size_t pidx = 0;

	if (!is_clk_std(clk))
		return;

	clk_std = clk_to_clk_std(clk);
	switch (clk_std->num_parents) {
	case 0:
		break;
	case 1:
		clk_std->parent = clk_std->parents[0];
		break;
	default:
		pidx = clk->ops->get_parent(clk);
		assert(pidx < clk_std->num_parents);

		clk_std->parent = clk_std->parents[pidx];
		break;
	}
}

TEE_Result clk_register(struct clk *clk)
{
	assert(clk_check(clk));

	clk_init_parent(clk);
	cache_rate_no_lock(clk);

	DMSG("Registered %sclock %s, freq %lu",
	     is_clk_lw(clk) ? "lightweight " : "", clk_get_name(clk),
	     clk_get_rate(clk));

	return TEE_SUCCESS;
}

TEE_Result clk_set_priv(struct clk *clk, void *priv)
{
	if (!is_clk_std(clk)) {
		DMSG("Unexpected clock type");
		return TEE_ERROR_GENERIC;
	}

	clk_to_clk_std(clk)->priv = priv;
	return TEE_SUCCESS;
}

const char *clk_std_name(struct clk *clk)
{
	return clk_to_clk_std(clk)->name;
}

static bool clk_is_enabled_no_lock(struct clk *clk)
{
	return refcount_val(&clk->enabled_count) != 0;
}

bool clk_is_enabled(struct clk *clk)
{
	return clk_is_enabled_no_lock(clk);
}

static void clk_disable_no_lock(struct clk *clk)
{
	struct clk *parent = NULL;

	if (!refcount_dec(&clk->enabled_count))
		return;

	if (clk->ops->disable)
		clk->ops->disable(clk);

	parent = clk_get_parent(clk);
	if (parent)
		clk_disable_no_lock(parent);
}

static TEE_Result clk_enable_no_lock(struct clk *clk)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct clk *parent = NULL;

	if (refcount_inc(&clk->enabled_count))
		return TEE_SUCCESS;

	parent = clk_get_parent(clk);
	if (parent) {
		res = clk_enable_no_lock(parent);
		if (res)
			return res;
	}

	if (clk->ops->enable) {
		res = clk->ops->enable(clk);
		if (res) {
			if (parent)
				clk_disable_no_lock(parent);

			return res;
		}
	}

	refcount_set(&clk->enabled_count, 1);

	return TEE_SUCCESS;
}

TEE_Result clk_enable(struct clk *clk)
{
	uint32_t exceptions = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	exceptions = cpu_spin_lock_xsave(&clk_lock);
	res = clk_enable_no_lock(clk);
	cpu_spin_unlock_xrestore(&clk_lock, exceptions);

	return res;
}

void clk_disable(struct clk *clk)
{
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&clk_lock);
	clk_disable_no_lock(clk);
	cpu_spin_unlock_xrestore(&clk_lock, exceptions);
}

unsigned long clk_std_rate(struct clk *clk)
{
	return clk_to_clk_std(clk)->rate;
}

static TEE_Result clk_set_rate_no_lock(struct clk *clk, unsigned long rate)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned long parent_rate = 0;

	if (is_clk_std(clk)) {
		struct clk_std *clk_std = clk_to_clk_std(clk);

		if (clk_std->parent)
			parent_rate = clk_get_rate(clk_std->parent);
	}

	res = clk->ops->set_rate(clk, rate, parent_rate);
	if (res)
		return res;

	cache_rate_no_lock(clk);

	return TEE_SUCCESS;
}

TEE_Result clk_set_rate(struct clk *clk, unsigned long rate)
{
	uint32_t exceptions = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!clk->ops->set_rate)
		return TEE_ERROR_NOT_SUPPORTED;

	exceptions =  cpu_spin_lock_xsave(&clk_lock);

	if (clk_to_clk_std(clk)->flags & CLK_SET_RATE_GATE &&
	    clk_is_enabled_no_lock(clk))
		res = TEE_ERROR_BAD_STATE;
	else
		res = clk_set_rate_no_lock(clk, rate);

	cpu_spin_unlock_xrestore(&clk_lock, exceptions);

	return res;
}

struct clk *clk_get_parent(struct clk *clk)
{
	if (is_clk_std(clk))
		return clk_to_clk_std(clk)->parent;

	return NULL;
}

size_t clk_get_num_parents(struct clk *clk)
{
	if (is_clk_std(clk))
		return clk_to_clk_std(clk)->num_parents;

	return 0;
}

static TEE_Result clk_get_parent_idx(struct clk *clk, struct clk *parent,
				     size_t *pidx)
{
	size_t i = 0;

	for (i = 0; i < clk_get_num_parents(clk); i++) {
		if (clk_get_parent_by_index(clk, i) == parent) {
			*pidx = i;
			return TEE_SUCCESS;
		}
	}

	EMSG("Clock %s is not a parent of clock %s", clk_get_name(parent),
	     clk_get_name(clk));

	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result clk_set_parent_no_lock(struct clk *clk, struct clk *parent,
					 size_t pidx)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	bool was_enabled = false;
	struct clk_std *clk_std = clk_to_clk_std(clk);

	/* Requested parent is already the one set */
	if (clk_std->parent == parent)
		return TEE_SUCCESS;

	was_enabled = clk_is_enabled_no_lock(clk);
	/* Call is needed to decrement refcount on current parent tree */
	if (was_enabled)
		clk_disable_no_lock(clk);

	res = clk->ops->set_parent(clk, pidx);
	if (res)
		goto out;

	clk_std->parent = parent;

	/* The parent changed and the rate might also have changed */
	cache_rate_no_lock(clk);

out:
	/* Call is needed to increment refcount on the new parent tree */
	if (was_enabled) {
		res = clk_enable_no_lock(clk);
		if (res)
			panic("Failed to re-enable clock after setting parent");
	}

	return res;
}

TEE_Result clk_set_parent(struct clk *clk, struct clk *parent)
{
	size_t pidx = 0;
	uint32_t exceptions = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct clk_std *clk_std = NULL;

	if (!clk->ops->set_parent)
		return TEE_ERROR_BAD_PARAMETERS;

	res = clk_get_parent_idx(clk, parent, &pidx);
	assert(!res);

	clk_std = clk_to_clk_std(clk);

	exceptions = cpu_spin_lock_xsave(&clk_lock);

	if (clk_std->flags & CLK_SET_PARENT_GATE && clk_is_enabled_no_lock(clk))
		res = TEE_ERROR_BAD_STATE;
	else
		res = clk_set_parent_no_lock(clk, parent, pidx);

	cpu_spin_unlock_xrestore(&clk_lock, exceptions);

	return res;
}
