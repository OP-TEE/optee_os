// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Bootlin
 */

#include <drivers/clk.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <malloc.h>
#include <stddef.h>

/* Global clock tree lock */
static unsigned int clk_lock = SPINLOCK_UNLOCK;

struct clk *clk_alloc(const char *name, const struct clk_ops *ops,
		      struct clk **parent_clks, size_t parent_count)
{
	struct clk *clk = NULL;
	size_t parent = 0;

	clk = calloc(1, sizeof(*clk) + parent_count * sizeof(clk));
	if (!clk)
		return NULL;

	clk->num_parents = parent_count;
	for (parent = 0; parent < parent_count; parent++)
		clk->parents[parent] = parent_clks[parent];

	clk->name = name;
	clk->ops = ops;
	refcount_set(&clk->enabled_count, 0);

	return clk;
}

void clk_free(struct clk *clk)
{
	free(clk);
}

static bool __maybe_unused clk_check(struct clk *clk)
{
	if (!clk->ops)
		return false;

	if (clk->ops->set_parent && !clk->ops->get_parent)
		return false;

	if (clk->num_parents > 1 && !clk->ops->get_parent)
		return false;

	return true;
}

static void clk_compute_rate_no_lock(struct clk *clk)
{
	unsigned long parent_rate = 0;

	if (clk->parent)
		parent_rate = clk->parent->rate;

	if (clk->ops->get_rate)
		clk->rate = clk->ops->get_rate(clk, parent_rate);
	else
		clk->rate = parent_rate;
}

struct clk *clk_get_parent_by_index(struct clk *clk, size_t pidx)
{
	if (pidx >= clk->num_parents)
		return NULL;

	return clk->parents[pidx];
}

static void clk_init_parent(struct clk *clk)
{
	size_t pidx = 0;

	switch (clk->num_parents) {
	case 0:
		break;
	case 1:
		clk->parent = clk->parents[0];
		break;
	default:
		pidx = clk->ops->get_parent(clk);
		assert(pidx < clk->num_parents);

		clk->parent = clk->parents[pidx];
		break;
	}
}

TEE_Result clk_register(struct clk *clk)
{
	assert(clk_check(clk));

	clk_init_parent(clk);
	clk_compute_rate_no_lock(clk);

	DMSG("Registered clock %s, freq %lu", clk->name, clk_get_rate(clk));

	return TEE_SUCCESS;
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

unsigned long clk_get_rate(struct clk *clk)
{
	return clk->rate;
}

static TEE_Result clk_set_rate_no_lock(struct clk *clk, unsigned long rate)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned long parent_rate = 0;

	if (clk->parent)
		parent_rate = clk_get_rate(clk->parent);

	res = clk->ops->set_rate(clk, rate, parent_rate);
	if (res)
		return res;

	clk_compute_rate_no_lock(clk);

	return TEE_SUCCESS;
}

TEE_Result clk_set_rate(struct clk *clk, unsigned long rate)
{
	uint32_t exceptions = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!clk->ops->set_rate)
		return TEE_ERROR_NOT_SUPPORTED;

	exceptions =  cpu_spin_lock_xsave(&clk_lock);

	if (clk->flags & CLK_SET_RATE_GATE && clk_is_enabled_no_lock(clk))
		res = TEE_ERROR_BAD_STATE;
	else
		res = clk_set_rate_no_lock(clk, rate);

	cpu_spin_unlock_xrestore(&clk_lock, exceptions);

	return res;
}

struct clk *clk_get_parent(struct clk *clk)
{
	return clk->parent;
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
	EMSG("Clock %s is not a parent of clock %s", parent->name, clk->name);

	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result clk_set_parent_no_lock(struct clk *clk, struct clk *parent,
					 size_t pidx)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	bool was_enabled = false;

	/* Requested parent is already the one set */
	if (clk->parent == parent)
		return TEE_SUCCESS;

	was_enabled = clk_is_enabled_no_lock(clk);
	/* Call is needed to decrement refcount on current parent tree */
	if (was_enabled)
		clk_disable_no_lock(clk);

	res = clk->ops->set_parent(clk, pidx);
	if (res)
		goto out;

	clk->parent = parent;

	/* The parent changed and the rate might also have changed */
	clk_compute_rate_no_lock(clk);

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

	if (clk_get_parent_idx(clk, parent, &pidx) || !clk->ops->set_parent)
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = cpu_spin_lock_xsave(&clk_lock);
	if (clk->flags & CLK_SET_PARENT_GATE && clk_is_enabled_no_lock(clk)) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	res = clk_set_parent_no_lock(clk, parent, pidx);
out:
	cpu_spin_unlock_xrestore(&clk_lock, exceptions);

	return res;
}
