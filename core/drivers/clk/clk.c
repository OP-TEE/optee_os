// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Bootlin
 * Copyright (c) 2023, STMicroelectronics
 */

#include <config.h>
#include <drivers/clk.h>
#include <kernel/boot.h>
#include <kernel/mutex_pm_aware.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <malloc.h>
#include <stddef.h>
#include <stdio.h>

/* Global clock tree access protection complying the power state transitions */
static struct mutex_pm_aware mu = MUTEX_PM_AWARE_INITIALIZER;

#ifdef CFG_DRIVERS_CLK_PRINT_TREE
static SLIST_HEAD(, clk) clock_list = SLIST_HEAD_INITIALIZER(clock_list);
#endif

static void lock_clk(void)
{
	mutex_pm_aware_lock(&mu);
}

static void unlock_clk(void)
{
	mutex_pm_aware_unlock(&mu);
}

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
	if (!clk || !clk->ops)
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

#ifdef CFG_DRIVERS_CLK_PRINT_TREE
	SLIST_INSERT_HEAD(&clock_list, clk, link);
#endif

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
	TEE_Result res = TEE_ERROR_GENERIC;

	lock_clk();
	res = clk_enable_no_lock(clk);
	unlock_clk();

	return res;
}

void clk_disable(struct clk *clk)
{
	lock_clk();
	clk_disable_no_lock(clk);
	unlock_clk();
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

	assert(!(clk->flags & CLK_SET_RATE_PARENT) || clk->parent);
	if (clk->flags & CLK_SET_RATE_PARENT) {
		res = clk_set_rate_no_lock(clk->parent, rate);
		if (res)
			return res;
		rate = clk_get_rate(clk->parent);
	}

	if (clk->ops->set_rate) {
		if (clk->flags & CLK_SET_RATE_UNGATE) {
			res = clk_enable_no_lock(clk);
			if (res)
				return res;
		}

		res = clk->ops->set_rate(clk, rate, parent_rate);

		if (clk->flags & CLK_SET_RATE_UNGATE)
			clk_disable_no_lock(clk);

		if (res)
			return res;
	}

	clk_compute_rate_no_lock(clk);

	return TEE_SUCCESS;
}

TEE_Result clk_set_rate(struct clk *clk, unsigned long rate)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	lock_clk();

	if (clk->flags & CLK_SET_RATE_GATE && clk_is_enabled_no_lock(clk))
		res = TEE_ERROR_BAD_STATE;
	else
		res = clk_set_rate_no_lock(clk, rate);

	unlock_clk();

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
	if (was_enabled) {
		if (clk->flags & CLK_SET_PARENT_PRE_ENABLE) {
			res = clk_enable_no_lock(parent);
			if (res)
				return res;
		}

		clk_disable_no_lock(clk);
	}

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

		if (clk->flags & CLK_SET_PARENT_PRE_ENABLE) {
			/* Balance refcount when new parent was pre-enabled */
			clk_disable_no_lock(parent);
		}
	}

	return res;
}

TEE_Result clk_set_parent(struct clk *clk, struct clk *parent)
{
	size_t pidx = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (clk_get_parent_idx(clk, parent, &pidx) || !clk->ops->set_parent)
		return TEE_ERROR_BAD_PARAMETERS;

	lock_clk();
	if (clk->flags & CLK_SET_PARENT_GATE && clk_is_enabled_no_lock(clk)) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	res = clk_set_parent_no_lock(clk, parent, pidx);
out:
	unlock_clk();

	return res;
}

TEE_Result clk_get_rates_array(struct clk *clk, size_t start_index,
			       unsigned long *rates, size_t *nb_elts)
{
	if (!clk->ops->get_rates_array)
		return TEE_ERROR_NOT_SUPPORTED;

	return clk->ops->get_rates_array(clk, start_index, rates, nb_elts);
}

TEE_Result clk_get_rates_steps(struct clk *clk, unsigned long *min,
			       unsigned long *max, unsigned long *step)
{
	if (!clk->ops->get_rates_steps)
		return TEE_ERROR_NOT_SUPPORTED;

	return clk->ops->get_rates_steps(clk, min, max, step);
}

TEE_Result clk_get_duty_cycle(struct clk *clk,
			      struct clk_duty_cycle *duty_cycle)
{
	if (clk->ops->get_duty_cycle)
		return clk->ops->get_duty_cycle(clk, duty_cycle);

	if (clk->parent && (clk->flags & CLK_DUTY_CYCLE_PARENT))
		return clk_get_duty_cycle(clk->parent, duty_cycle);

	/* Default set 50% duty cycle */
	duty_cycle->num = 1;
	duty_cycle->den = 2;

	return TEE_SUCCESS;
}

/* Return updated message buffer position of NULL on failure */
static __printf(3, 4) char *add_msg(char *cur, char *end, const char *fmt, ...)
{
	va_list ap = { };
	int max_len = end - cur;
	int ret = 0;

	va_start(ap, fmt);
	ret = vsnprintf(cur, max_len, fmt, ap);
	va_end(ap);

	if (ret < 0 || ret >= max_len)
		return NULL;

	return cur + ret;
}

static struct clk *find_next_clk(struct clk *parent __maybe_unused,
				 struct clk *sibling __maybe_unused)
{
	struct clk *clk = NULL;

#ifdef CFG_DRIVERS_CLK_PRINT_TREE
	if (sibling)
		clk = SLIST_NEXT(sibling, link);
	else
		clk = SLIST_FIRST(&clock_list);

	while (clk && clk->parent != parent)
		clk = SLIST_NEXT(clk, link);
#endif

	return clk;
}

static bool clk_is_parent_last_child(struct clk *clk)
{
	return !find_next_clk(clk->parent, clk);
}

static bool indent_last_node_already_found(struct clk *node_clk,
					   int node_indent, int cur_indent)
{
	struct clk *clk = node_clk;
	int n = 0;

	/* Find parent clock at level @node_indent - @cur_indent - 1 */
	for (n = 0; n < node_indent - cur_indent - 1; n++)
		clk = clk->parent;

	return clk_is_parent_last_child(clk);
}

static void __maybe_unused print_clk(struct clk *clk, int indent)
{
	static const char * const rate_unit[] = { "Hz", "kHz", "MHz", "GHz" };
	int max_unit = ARRAY_SIZE(rate_unit);
	unsigned long rate = 0;
	char msg_buf[128] = { };
	char *msg_end = msg_buf + sizeof(msg_buf);
	char *msg = msg_buf;
	int n = 0;

	/*
	 * Currently prints the clock state based on the clock refcount.
	 * A future change could print the hardware clock state when
	 * related clock driver provides a struct clk_ops::is_enabled handler
	 */

	if (indent) {
		/* Indent for root clock level */
		msg = add_msg(msg, msg_end, "   ");
		if (!msg)
			goto out;

		/* Indent for root parent to clock parent levels */
		for (n = 0; n < indent - 1; n++) {
			if (indent_last_node_already_found(clk, indent, n))
				msg = add_msg(msg, msg_end, "    ");
			else
				msg = add_msg(msg, msg_end, "|   ");

			if (!msg)
				goto out;
		}

		/* Clock indentation */
		if (clk_is_parent_last_child(clk))
			msg = add_msg(msg, msg_end, "`-- ");
		else
			msg = add_msg(msg, msg_end, "|-- ");
	} else {
		/* Root clock indentation */
		msg = add_msg(msg, msg_end, "o- ");
	}
	if (!msg)
		goto out;

	rate = clk_get_rate(clk);
	for (n = 1; rate && !(rate % 1000) && n < max_unit; n++)
		rate /= 1000;

	msg = add_msg(msg, msg_end, "%s \t(%3s / refcnt %u / %ld %s)",
		      clk_get_name(clk),
		      refcount_val(&clk->enabled_count) ? "on " : "off",
		      refcount_val(&clk->enabled_count),
		      rate, rate_unit[n - 1]);
	if (!msg)
		goto out;

out:
	if (!msg)
		snprintf(msg_end - 4, 4, "...");

	DMSG("%s", msg_buf);
}

static void print_tree(void)
{
	struct clk *clk = NULL;
	struct clk *parent = NULL;
	struct clk *next = NULL;
	int indent = -1;

#ifdef CFG_DRIVERS_CLK_PRINT_TREE
	if (SLIST_EMPTY(&clock_list)) {
		DMSG("-- No registered clock");
		return;
	}
#endif

	while (true) {
		next = find_next_clk(parent, clk);
		if (next) {
			print_clk(next, indent + 1);
			/* Enter the subtree of the next clock */
			parent = next;
			indent++;
			clk = NULL;
		} else {
			/*
			 * We've processed all children at this level.
			 * If parent is NULL we're at the top and are done.
			 */
			if (!parent)
				break;
			/*
			 * Move up one level to resume with the next
			 * child clock of the parent.
			 */
			clk = parent;
			parent = clk->parent;
			indent--;
		}
	}
}

void clk_print_tree(void)
{
	if (IS_ENABLED(CFG_DRIVERS_CLK_PRINT_TREE) &&
	    TRACE_LEVEL >= TRACE_DEBUG) {
		DMSG("Clock tree summary (informative):");
		print_tree();
	}
}
