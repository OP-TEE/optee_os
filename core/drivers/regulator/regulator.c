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
#include <kernel/mutex.h>
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

static void lock_regulator(struct regulator *regulator)
{
	/*
	 * Regulator operation may occur at runtime and during specific
	 * system power transition: power off, PM suspend and resume.
	 * These operate upon fastcall entries, under PSCI services
	 * execution, where non-secure world is not operational. In these
	 * cases we cannot take a mutex and will expect the mutex is
	 * unlocked.
	 */
	if (thread_get_id_may_fail() == THREAD_ID_INVALID) {
		assert(!regulator->lock.state);
		return;
	}

	mutex_lock(&regulator->lock);
}

static void unlock_regulator(struct regulator *regulator)
{
	if (thread_get_id_may_fail() == THREAD_ID_INVALID) {
		/* Path for PM sequences when with local Monitor */
		return;
	}

	mutex_unlock(&regulator->lock);
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

TEE_Result regulator_set_voltage(struct regulator *regulator, int level_uv)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(regulator);
	FMSG("%s %duV", regulator_name(regulator), level_uv);

	if (level_uv < regulator->min_uv || level_uv > regulator->max_uv)
		return TEE_ERROR_BAD_PARAMETERS;

	if (level_uv == regulator->cur_uv)
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

	regulator->cur_uv = level_uv;

	return TEE_SUCCESS;
}

TEE_Result regulator_supported_voltages(struct regulator *regulator,
					struct regulator_voltages **voltages)
{
	assert(regulator && voltages);

	if (regulator->ops->supported_voltages) {
		TEE_Result res = TEE_ERROR_GENERIC;

		res = regulator->ops->supported_voltages(regulator, voltages);
		if (res == TEE_SUCCESS)
			return TEE_SUCCESS;
		if (res != TEE_ERROR_NOT_SUPPORTED)
			return res;
	}

	*voltages = &regulator->voltages_fallback.desc;

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

	regulator_get_range(regulator, &min_uv, &max_uv);
	if (min_uv > max_uv)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Sanitize regulator effective level */
	if (regulator->ops->get_voltage) {
		res = regulator->ops->get_voltage(regulator, &uv);
		if (res)
			return res;
	} else {
		uv = min_uv;
	}
	regulator->cur_uv = uv;

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
 * Log regulators state
 */
void regulator_print_state(const char *message __maybe_unused)
{
	struct regulator *regulator = NULL;

	DMSG("Regulator state: %s", message);
	DMSG("name     use\ten\tuV\tmin\tmax\tflags\tsupply");

	SLIST_FOREACH(regulator, &regulator_device_list, link)
		DMSG("%8s %u\t%d\t%d\t%d\t%d\t%#x\t%s\n",
		     regulator->name, regulator->refcount,
		     regulator_is_enabled(regulator),
		     regulator_get_voltage(regulator),
		     regulator->min_uv, regulator->max_uv, regulator->flags,
		     regulator->supply ? regulator_name(regulator->supply) :
		     "<none>");
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

	regulator_print_state(__func__);

	return TEE_SUCCESS;
}

release_init_resource(regulator_core_cleanup);
