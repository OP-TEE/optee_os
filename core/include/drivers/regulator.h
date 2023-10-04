/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, STMicroelectronics
 */
#ifndef DRIVERS_REGULATOR_H
#define DRIVERS_REGULATOR_H

#include <assert.h>
#include <bitstring.h>
#include <kernel/mutex.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <stdbool.h>
#include <stdint.h>
#include <util.h>

/* Regulator property flags: related to device tree binding properties */

/* Regulator should never be disabled. DT property: regulator-always-on */
#define REGULATOR_ALWAYS_ON	BIT(0)

#define REGULATOR_FLAGS_MASK	REGULATOR_ALWAYS_ON

struct regulator_ops;

/*
 * struct regu_dt_desc - Regulator description passed to regulator_dt_register()
 * @priv: Regulator driver private data
 * @name: Regulator string name for debug purpose
 * @supply_name: Regulator supply name for node property *-supply or NULL
 * @ops: Operation handlers for the regulator
 * @regulator: Pointer to preallocated regulator or NULL if none
 */
struct regu_dt_desc {
	void *priv;
	char *name;
	const char *supply_name;
	const struct regulator_ops *ops;
	struct regulator *regulator;
};

/*
 * struct regulator - A regulator instance
 * @ops: Operation handlers for the regulator
 * @supply: Regulator supply reference or NULL if none
 * @priv: Regulator driver private data
 * @name: Regulator string name for debug purpose or NULL
 * @min_uv: Min possible voltage level in microvolt (uV)
 * @max_uv: Max possible voltage level in microvolt (uV)
 * @cur_uv: Current voltage level in microvolt (uV)
 * @flags: REGULATOR_* property flags
 * @refcount: Regulator enable request reference counter
 * @lock: Mutex for concurrent access protection
 * @link: Link in initialized regulator list
 */
struct regulator {
	/* Fields initialized by caller of regulator_register() */
	const struct regulator_ops *ops;
	struct regulator *supply;
	void *priv;
	char *name;
	int min_uv;
	int max_uv;
	/* Fields internal to regulator framework */
	int cur_uv;
	unsigned int flags;
	unsigned int refcount;
	struct mutex lock;	/* Concurrent access protection */
	SLIST_ENTRY(regulator) link;
};

/*
 * struct regulator_ops - Regulator operation handlers
 *
 * @set_state: Enable or disable a regulator
 * @get_state: Get regulator effective state
 * @set_voltage: Set voltage level in microvolt (uV)
 * @get_voltage: Get current voltage in microvolt (uV)
 * @supplied_init: Optional, finalize initialization once supply is ready
 */
struct regulator_ops {
	TEE_Result (*set_state)(struct regulator *r, bool enabled);
	TEE_Result (*get_state)(struct regulator *r, bool *enabled);
	TEE_Result (*set_voltage)(struct regulator *r, int level_uv);
	TEE_Result (*get_voltage)(struct regulator *r, int *level_uv);
	TEE_Result (*supplied_init)(struct regulator *r, const void *fdt,
				    int node);
};

#ifdef CFG_DRIVERS_REGULATOR
/*
 * regulator_enable() - Enable regulator
 * @regulator: Regulator reference
 */
TEE_Result regulator_enable(struct regulator *regulator);

/*
 * regulator_disable() - Disable regulator
 * @regulator: Regulator reference
 */
TEE_Result regulator_disable(struct regulator *regulator);

/*
 * regulator_is_enabled() - Return whether or not regulator is currently enabled
 * despite its refcount value.
 * @regulator: Regulator reference
 */
bool regulator_is_enabled(struct regulator *regulator);

/*
 * regulator_set_voltage() - Set regulator to target level in microvolt
 * @regulator: Regulator reference
 * @level_uv: Level in microvolt
 */
TEE_Result regulator_set_voltage(struct regulator *regulator, int level_uv);

/*
 * regulator_register() - Register and initialize a regulator
 * @regulator: Regulator reference
 */
TEE_Result regulator_register(struct regulator *regulator);

/* Print registered regulators and their state to the output console */
void regulator_print_state(const char *message);
#else
static inline TEE_Result regulator_enable(struct regulator *regulator __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result regulator_disable(struct regulator *regulator __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline bool regulator_is_enabled(struct regulator *regulator __unused)
{
	return false;
}

static inline TEE_Result regulator_set_voltage(struct regulator *regul __unused,
					       int level_mv __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result regulator_init(struct regulator *regulator __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline void regulator_print_state(const char *message __unused)
{
}
#endif /*CFG_DRIVERS_REGULATOR*/

#if defined(CFG_DRIVERS_REGULATOR) && defined(CFG_DT)
/*
 * regulator_dt_register() - Register a regulator to related to a DT node
 * @fdt: FDT to work on
 * @node: DT node of the regulator exposed by regulator driver
 * @provider_node: Node where xxx-supply property is found or -1 if no supply.
 * @desc: Description of the regulator to register
 *
 * This function registers and initializes a regulator instance once its supply
 * if found, if any. Regulators registered with this function can be found by
 * their consumer drivers using API function regulator_dt_get_supply() or like.
 *
 * Return TEE_SUCCESS in case of success
 * Return TEE_ERROR_OUT_OF_MEMORY if failed on memory allocation
 * Return any other TEE_Result compliant code in case of error
 */
TEE_Result regulator_dt_register(const void *fdt, int node, int provider_node,
				 const struct regu_dt_desc *desc);
#else
static inline TEE_Result regulator_dt_get_supply(const void *fdt __unused,
						 int node __unused,
						 const char *supply __unused,
						 struct regulator **r __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result
regulator_dt_register(const void *fdt __unused, int node __unused,
		      int provider_node __unused,
		      const struct regu_dt_desc *d __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /* CFG_DRIVERS_REGULATOR && CFG_DT */

/*
 * regulator_name() - Return regulator name or NULL
 * @regulator: Regulator reference
 */
static inline const char *regulator_name(struct regulator *regulator)
{
	return regulator->name;
}

/*
 * regulator_is_always_on() - Return the state of REGULATOR_ALWAYS_ON flag
 * @regulator: Regulator reference
 */
static inline bool regulator_is_always_on(struct regulator *regulator)
{
	return regulator->flags & REGULATOR_ALWAYS_ON;
}

/*
 * regulator_set_min_voltage() - Set regulator to its min level
 * @regulator: Regulator reference
 */
static inline TEE_Result regulator_set_min_voltage(struct regulator *regulator)
{
	return regulator_set_voltage(regulator, regulator->min_uv);
}

/*
 * regulator_get_voltage() - Get regulator current level in microvolt
 * @regulator: Regulator reference
 */
static inline int regulator_get_voltage(struct regulator *regulator)
{
	return regulator->cur_uv;
}

/*
 * regulator_get_range() - Get regulator min and/or max support levels
 * @regulator: Regulator reference
 * @min_mv: Output reference to min level in microvolt (uV) or NULL
 * @max_mv: Output reference to max level in microvolt (uV) or NULL
 */
static inline void regulator_get_range(struct regulator *regulator, int *min_uv,
				       int *max_uv)
{
	assert(regulator);
	if (min_uv)
		*min_uv = regulator->min_uv;
	if (max_uv)
		*max_uv = regulator->max_uv;
}
#endif /* DRIVERS_REGULATOR_H */
