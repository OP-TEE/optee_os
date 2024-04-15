/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021-2024, STMicroelectronics
 */

#ifndef __DRIVERS_STPMIC1_REGULATOR_H
#define __DRIVERS_STPMIC1_REGULATOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Return true if @name refers to a knwon regulator, return false otherwise
 */
bool stpmic1_regulator_is_valid(const char *name);

/*
 * Enable STPMIC1 regulator identified by @name.
 * Return 0 on success and a non-0 value if failing
 */
int stpmic1_regulator_enable(const char *name);

/*
 * Disable STPMIC1 regulator identified by @name.
 * Return 0 on success and a non-0 value if failing
 */
int stpmic1_regulator_disable(const char *name);

/*
 * Return true if regulator identified by @name is enabled and false otherwise.
 * Return 0 on success and a non-0 value if failing
 */
bool stpmic1_is_regulator_enabled(const char *name);

/*
 * Retrieve regulator levels array (in millivolts) and/or levels count
 * @name: regulator identifier
 * @levels: output reference for an arrays of the supported levels, or NULL
 * @levels_count: output reference for number of supported levels, or NULL
 */
void stpmic1_regulator_levels_mv(const char *name, const uint16_t **levels,
				 size_t *levels_count);

/*
 * Set voltage level @millivolt for target regulator @name
 * @name: regulator identifier
 * @millivot: target voltage level, in mV
 */
int stpmic1_regulator_voltage_set(const char *name, uint16_t millivolts);

/*
 * Get current voltage level (in millivolt) for target regulator @name
 * @name: regulator identifier
 * Return a positive millivolt level on success or a negative value on error
 */
int stpmic1_regulator_voltage_get(const char *name);

#endif /*__DRIVERS_STPMIC1_REGULATOR_H*/
