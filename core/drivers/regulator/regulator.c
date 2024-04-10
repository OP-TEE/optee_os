// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, STMicroelectronics
 */

#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <drivers/regulator.h>
#include <initcall.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/mutex_pm_aware.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <kernel/tee_time.h>
#include <kernel/thread.h>
#include <libfdt.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <util.h>

static SLIST_HEAD(, regulator) regulator_device_list =
	SLIST_HEAD_INITIALIZER(regulator);

/* Access protection mutex complying the power state transitions context */
static void lock_regulator(struct regulator *regulator)
{
	mutex_pm_aware_lock(&regulator->mutex);
}

static void unlock_regulator(struct regulator *regulator)
{
	mutex_pm_aware_unlock(&regulator->mutex);
}

static TEE_Result set_state(struct regulator *regulator, bool on_not_off)
{
	if (!regulator->ops->set_state)
		return TEE_SUCCESS;

	return regulator->ops->set_state(regulator, on_not_off);
}

static TEE_Result regulator_refcnt_enable(struct regulator *regulator)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	FMSG("%s", regulator_name(regulator));

	if (regulator->supply) {
		res = regulator_enable(regulator->supply);
		if (res)
			return res;
	}

	lock_regulator(regulator);

	if (!regulator->refcount) {
		res = set_state(regulator, true);
		if (res) {
			EMSG("regul %s set state failed with %#"PRIx32,
			     regulator_name(regulator), res);

			unlock_regulator(regulator);

			if (regulator->supply &&
			    regulator_disable(regulator->supply))
				panic();

			return res;
		}
	}

	regulator->refcount++;
	if (!regulator->refcount)
		panic();

	FMSG("%s refcount: %u", regulator_name(regulator), regulator->refcount);

	unlock_regulator(regulator);

	return TEE_SUCCESS;
}

TEE_Result regulator_enable(struct regulator *regulator)
{
	assert(regulator);
	FMSG("%s", regulator_name(regulator));

	if (regulator_is_always_on(regulator))
		return TEE_SUCCESS;

	return regulator_refcnt_enable(regulator);
}

static TEE_Result regulator_refcnt_disable(struct regulator *regulator)
{
	FMSG("%s", regulator_name(regulator));

	lock_regulator(regulator);

	if (regulator->refcount == 1) {
		TEE_Result res = set_state(regulator, false);

		if (res) {
			EMSG("regul %s set state failed with %#"PRIx32,
			     regulator_name(regulator), res);
			unlock_regulator(regulator);
			return res;
		}
	}

	if (!regulator->refcount) {
		EMSG("Unbalanced %s", regulator_name(regulator));
		panic();
	}

	regulator->refcount--;

	FMSG("%s refcount: %u", regulator_name(regulator), regulator->refcount);

	unlock_regulator(regulator);

	if (regulator->supply && regulator_disable(regulator->supply)) {
		/* We can't leave this unbalanced */
		EMSG("Can't disable %s", regulator_name(regulator->supply));
		panic();
	}

	return TEE_SUCCESS;
}

TEE_Result regulator_disable(struct regulator *regulator)
{
	assert(regulator);
	FMSG("%s", regulator_name(regulator));

	if (regulator_is_always_on(regulator))
		return TEE_SUCCESS;

	return regulator_refcnt_disable(regulator);
}

bool regulator_is_enabled(struct regulator *regulator)
{
	TEE_Result res = TEE_SUCCESS;
	bool enabled = false;

	if (!regulator->ops->get_state)
		return true;

	lock_regulator(regulator);
	res = regulator->ops->get_state(regulator, &enabled);
	unlock_regulator(regulator);

	if (res)
		EMSG("regul %s get state failed with %#"PRIx32,
		     regulator_name(regulator), res);

	return !res && enabled;
}

int regulator_get_voltage(struct regulator *regulator)
{
	TEE_Result res = TEE_SUCCESS;
	int level_uv = regulator->min_uv;

	if (regulator->ops->get_voltage) {
		res = regulator->ops->get_voltage(regulator, &level_uv);
		if (res) {
			EMSG("%s get_voltage failed with %#"PRIx32,
			     regulator_name(regulator), res);
			level_uv = 0;
		}
	}

	return level_uv;
}

TEE_Result regulator_set_voltage(struct regulator *regulator, int level_uv)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int cur_uv = 0;

	assert(regulator);
	FMSG("%s %duV", regulator_name(regulator), level_uv);

	if (level_uv < regulator->min_uv || level_uv > regulator->max_uv)
		return TEE_ERROR_BAD_PARAMETERS;

	cur_uv = regulator_get_voltage(regulator);
	if (level_uv == cur_uv)
		return TEE_SUCCESS;

	if (!regulator->ops->set_voltage)
		return TEE_ERROR_NOT_SUPPORTED;

	lock_regulator(regulator);
	res = regulator->ops->set_voltage(regulator, level_uv);
	unlock_regulator(regulator);

	if (res) {
		EMSG("regul %s set volt failed with %#"PRIx32,
		     regulator_name(regulator), res);
		return res;
	}

	return TEE_SUCCESS;
}

TEE_Result regulator_supported_voltages(struct regulator *regulator,
					struct regulator_voltages_desc **desc,
					const int **levels)
{
	TEE_Result res = TEE_ERROR_NOT_SUPPORTED;

	assert(regulator && desc && levels);

	if (regulator->ops->supported_voltages)
		res = regulator->ops->supported_voltages(regulator, desc,
							 levels);
	if (res == TEE_ERROR_NOT_SUPPORTED) {
		*desc = &regulator->voltages_fallback.desc;
		*levels = regulator->voltages_fallback.levels;
	} else if (res) {
		return res;
	}

	if ((*desc)->type == VOLTAGE_TYPE_FULL_LIST) {
		assert((*desc)->num_levels);
		assert((*levels)[0] >= regulator->min_uv);
		assert((*levels)[(*desc)->num_levels - 1] <= regulator->max_uv);
	} else if ((*desc)->type == VOLTAGE_TYPE_INCREMENT) {
		assert((*levels)[0] >= regulator->min_uv);
		assert((*levels)[1] <= regulator->max_uv);
	} else {
		assert(0);
	}

	return TEE_SUCCESS;
}

TEE_Result regulator_register(struct regulator *regulator)
{
	TEE_Result res = TEE_SUCCESS;
	int min_uv = 0;
	int max_uv = 0;
	int uv = 0;

	if (!regulator || !regulator->ops ||
	    regulator->flags & ~REGULATOR_FLAGS_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_pm_aware_init(&regulator->mutex);

	regulator_get_range(regulator, &min_uv, &max_uv);
	if (min_uv > max_uv)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Sanitize regulator effective level */
	uv = regulator_get_voltage(regulator);

	if (uv < min_uv || uv > max_uv) {
		res = regulator_set_voltage(regulator, min_uv);
		if (res)
			return res;
	}

	/* Unbalanced enable refcount to keep always-on regulators enabled */
	if (regulator_is_always_on(regulator)) {
		res = regulator_refcnt_enable(regulator);
		if (res)
			return res;
	}

	/* Preset voltage list in case ops::supported_voltages is NULL */
	if (regulator->min_uv == regulator->max_uv) {
		regulator->voltages_fallback.desc.type = VOLTAGE_TYPE_FULL_LIST;
		regulator->voltages_fallback.desc.num_levels = 1;
		regulator->voltages_fallback.levels[0] = regulator->min_uv;
	} else {
		regulator->voltages_fallback.desc.type = VOLTAGE_TYPE_INCREMENT;
		regulator->voltages_fallback.levels[0] = regulator->min_uv;
		regulator->voltages_fallback.levels[1] = regulator->max_uv;
		regulator->voltages_fallback.levels[2] = 1;
	}

	SLIST_INSERT_HEAD(&regulator_device_list, regulator, link);

	return TEE_SUCCESS;
}

/*
 * Clean-up regulators that are not used.
 */
static TEE_Result regulator_core_cleanup(void)
{
	struct regulator *regulator = NULL;

	SLIST_FOREACH(regulator, &regulator_device_list, link) {
		if (!regulator->refcount) {
			DMSG("disable %s", regulator_name(regulator));
			lock_regulator(regulator);
			set_state(regulator, false /* disable */);
			unlock_regulator(regulator);
		}
	}

	regulator_print_tree();

	return TEE_SUCCESS;
}

release_init_resource(regulator_core_cleanup);

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

static struct regulator *find_next_regulator(struct regulator *parent,
					     struct regulator *sibling)
{
	struct regulator *regulator = NULL;

	if (sibling)
		regulator = SLIST_NEXT(sibling, link);
	else
		regulator = SLIST_FIRST(&regulator_device_list);

	while (regulator && regulator->supply != parent)
		regulator = SLIST_NEXT(regulator, link);

	return regulator;
}

/* Regulator is the last supplied one by its supply in the registered list */
static bool regulator_is_supply_last_supplied(struct regulator *regulator)
{
	return !find_next_regulator(regulator->supply, regulator);
}

/* Supply last node may already be printed for indentation level @cur_indent */
static bool indent_with_empty_string(struct regulator *node_regulator,
				     int node_indent, int cur_indent)
{
	struct regulator *r = node_regulator;
	int n = 0;

	/* Find supply at indentation level @node_indent - @cur_indent - 1 */
	for (n = 0; n < node_indent - cur_indent - 1; n++)
		r = r->supply;

	return regulator_is_supply_last_supplied(r);
}

static void __maybe_unused print_regulator(struct regulator *regulator,
					   int indent)
{
	static const char * const level_unit[] = { "uV", "mV", "V" };
	int max_unit = ARRAY_SIZE(level_unit);
	int level_max = 0;
	int level_min = 0;
	int level_cur = 0;
	char msg_buf[128] = { };
	char *msg_end = msg_buf + sizeof(msg_buf);
	char *msg = msg_buf;
	int n_max = 0;
	int n_min = 0;
	int n_cur = 0;
	int n = 0;

	if (indent) {
		/* Indent for root clock level */
		msg = add_msg(msg, msg_end, "   ");
		if (!msg)
			goto out;

		/* Indent for root supply to regulator supply levels */
		for (n = 0; n < indent - 1; n++) {
			if (indent_with_empty_string(regulator, indent, n))
				msg = add_msg(msg, msg_end, "    ");
			else
				msg = add_msg(msg, msg_end, "|   ");
			if (!msg)
				goto out;
		}

		/* Regulator indentation */
		if (regulator_is_supply_last_supplied(regulator))
			msg = add_msg(msg, msg_end, "`-- ");
		else
			msg = add_msg(msg, msg_end, "|-- ");

		if (!msg)
			goto out;
	} else {
		/* Root supply indentation */
		msg = add_msg(msg, msg_end, "o- ");
	}

	regulator_get_range(regulator, &level_min, &level_max);
	level_cur = regulator_get_voltage(regulator);

	for (n_cur = 1; !(level_cur % 1000) && n_cur < max_unit; n_cur++)
		level_cur /= 1000;
	for (n_max = 1; !(level_max % 1000) && n_max < max_unit; n_max++)
		level_max /= 1000;
	for (n_min = 1; !(level_min % 1000) && n_min < max_unit; n_min++)
		level_min /= 1000;

	msg = add_msg(msg, msg_end, "%s \t(%3s / refcnt %u / flags %#"PRIx32
		      " / %d %s ", regulator_name(regulator),
		      regulator_is_enabled(regulator) ? "on " : "off",
		      regulator->refcount, regulator->flags,
		      level_cur, level_unit[n_cur - 1]);
	if (!msg)
		goto out;

	if (level_min == level_max)
		msg = add_msg(msg, msg_end, "fixed)");
	else if (level_max == INT_MAX)
		msg = add_msg(msg, msg_end, "[%d %s .. MAX])",
			      level_min, level_unit[n_min - 1]);
	else
		msg = add_msg(msg, msg_end, "[%d %s .. %d %s])",
			      level_min, level_unit[n_min - 1],
			      level_max, level_unit[n_max - 1]);

out:
	if (!msg)
		snprintf(msg_end - 4, 4, "...");

	DMSG("%s", msg_buf);
}

static void print_tree(void)
{
	struct regulator *regulator = NULL;
	struct regulator *parent = NULL;
	struct regulator *next = NULL;
	int indent = -1;

	while (true) {
		next = find_next_regulator(parent, regulator);
		if (next) {
			print_regulator(next, indent + 1);
			/* Enter the subtree of the next regulator */
			parent = next;
			indent++;
			regulator = NULL;
		} else {
			/*
			 * We've processed all children at this level.
			 * If parent is NULL we're at the top and are done.
			 */
			if (!parent)
				break;
			/*
			 * Move up one level to resume with the next
			 * regulator of the parent.
			 */
			regulator = parent;
			parent = regulator->supply;
			indent--;
		}
	}
}

void regulator_print_tree(void)
{
	if (IS_ENABLED(CFG_DRIVERS_REGULATOR_PRINT_TREE) &&
	    TRACE_LEVEL >= TRACE_DEBUG) {
		DMSG("Regulator tree summary");
		if (SLIST_EMPTY(&regulator_device_list))
			DMSG("-- No registered regulator");
		else
			print_tree();
	}
}
