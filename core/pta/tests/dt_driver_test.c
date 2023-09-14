// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 *
 * Tests introduce dummy test drivers and assiciated devices defined in
 * dt_driver_test.dtsi file with device resource dependencies.
 */

#include <assert.h>
#include <config.h>
#include <crypto/crypto.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/gpio.h>
#include <drivers/regulator.h>
#include <drivers/rstctrl.h>
#include <initcall.h>
#include <kernel/dt_driver.h>
#include <kernel/delay.h>
#include <libfdt.h>
#include <malloc.h>
#include <sys/queue.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>

#define DT_TEST_MSG(...)	FMSG("(dt-driver-test) " __VA_ARGS__)

/* Test state IDs */
enum dt_test_sid { DEFAULT = 0, IN_PROGRESS, SUCCESS, FAILED };

/*
 * DT tests state to be reported from PTA_INVOKE_TESTS_CMD_DT_TEST_STATUS
 * possibly printed to console. A test can be skipped (DEFAULT) or be
 * successful (SUCCESS) orthewise it has failed (IN_PROGRESS, FAILED).
 */
struct dt_test_state {
	enum dt_test_sid probe_deferral;
	enum dt_test_sid probe_clocks;
	enum dt_test_sid probe_gpios;
	enum dt_test_sid probe_regulators;
	enum dt_test_sid probe_resets;
	enum dt_test_sid crypto_dependencies;
};

/*
 * References allocated from heap to be free once test completed
 * dt_test_alloc(), dt_test_free(), dt_test_free_all()
 */
struct dt_test_free_ref {
	void *p;
	SLIST_ENTRY(dt_test_free_ref) link;
};

static struct dt_test_state dt_test_state;

static const char __maybe_unused * const dt_test_str_sid[] = {
	[DEFAULT] = "not run",
	[IN_PROGRESS] = "in-progress",
	[SUCCESS] = "successful",
	[FAILED] = "failed",
};

/* Reference allocations during test for release_init_resource initcall level */
static SLIST_HEAD(dt_test_free_refs, dt_test_free_ref) dt_test_free_list =
	SLIST_HEAD_INITIALIZER(dt_test_free_list);

static void __maybe_unused *dt_test_alloc(size_t size)
{
	struct dt_test_free_ref *ref = NULL;

	ref = calloc(1, sizeof(*ref) + size);
	if (!ref)
		return NULL;

	ref->p = ref + 1;
	SLIST_INSERT_HEAD(&dt_test_free_list, ref, link);

	return ref->p;
}

static void __maybe_unused dt_test_free(void *p)
{
	struct dt_test_free_ref *ref = NULL;
	struct dt_test_free_ref *t_ref = NULL;

	if (!p)
		return;

	SLIST_FOREACH_SAFE(ref, &dt_test_free_list, link, t_ref) {
		if (ref->p == p) {
			SLIST_REMOVE(&dt_test_free_list, ref,
				     dt_test_free_ref, link);
			free(ref);
			return;
		}
	}

	panic();
}

static void dt_test_free_all(void)
{
	while (!SLIST_EMPTY(&dt_test_free_list)) {
		struct dt_test_free_ref *ref = SLIST_FIRST(&dt_test_free_list);

		SLIST_REMOVE(&dt_test_free_list, ref, dt_test_free_ref, link);
		free(ref);
	}
}

static TEE_Result dt_test_release(void)
{
	dt_test_free_all();

	DT_TEST_MSG("Probe deferral: %s",
		    dt_test_str_sid[dt_test_state.probe_deferral]);
	DT_TEST_MSG("Clocks probe: %s",
		    dt_test_str_sid[dt_test_state.probe_clocks]);
	DT_TEST_MSG("GPIO ctrl probe: %s",
		    dt_test_str_sid[dt_test_state.probe_gpios]);
	DT_TEST_MSG("Regulator probe: %s",
		    dt_test_str_sid[dt_test_state.probe_regulators]);
	DT_TEST_MSG("Reset ctrl probe: %s",
		    dt_test_str_sid[dt_test_state.probe_resets]);
	DT_TEST_MSG("Crypto deps.: %s",
		    dt_test_str_sid[dt_test_state.crypto_dependencies]);

	return dt_driver_test_status();
}

release_init_resource(dt_test_release);

TEE_Result dt_driver_test_status(void)
{
	TEE_Result res = TEE_SUCCESS;

	if (dt_test_state.probe_deferral != SUCCESS) {
		EMSG("Probe deferral test failed");
		res = TEE_ERROR_GENERIC;
	}
	if (IS_ENABLED(CFG_DRIVERS_CLK) &&
	    dt_test_state.probe_clocks != SUCCESS) {
		EMSG("Clocks probing test failed");
		res = TEE_ERROR_GENERIC;
	}
	if (IS_ENABLED(CFG_DRIVERS_GPIOS) &&
	    dt_test_state.probe_gpios != SUCCESS) {
		EMSG("GPIO controllers probing test failed");
		res = TEE_ERROR_GENERIC;
	}
	if (IS_ENABLED(CFG_DRIVERS_REGULATOR) &&
	    dt_test_state.probe_regulators != SUCCESS) {
		EMSG("Regulator probing test failed");
		res = TEE_ERROR_GENERIC;
	}
	if (IS_ENABLED(CFG_DRIVERS_RSTCTRL) &&
	    dt_test_state.probe_resets != SUCCESS) {
		EMSG("Reset controllers probing test failed");
		res = TEE_ERROR_GENERIC;
	}
	if (dt_test_state.crypto_dependencies != SUCCESS) {
		EMSG("Probe deferral on crypto dependencies test failed");
		res = TEE_ERROR_GENERIC;
	}

	return res;
}

static TEE_Result probe_test_clocks(const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct clk *clk0 = NULL;
	struct clk *clk1 = NULL;
	struct clk *clk = NULL;

	DT_TEST_MSG("Probe clocks");
	dt_test_state.probe_clocks = IN_PROGRESS;

	res = clk_dt_get_by_index(fdt, node, 0, &clk0);
	if (res)
		goto err;

	res = clk_dt_get_by_index(fdt, node, 1, &clk1);
	if (res)
		goto err;

	DT_TEST_MSG("Check valid clock references");

	if (clk_enable(clk0)) {
		DT_TEST_MSG("Can't enable %s", clk_get_name(clk0));
		res = TEE_ERROR_GENERIC;
		goto err;
	}
	clk_disable(clk0);

	res = clk_dt_get_by_name(fdt, node, "clk0", &clk);
	if (res || clk != clk0) {
		DT_TEST_MSG("Unexpected clock reference");
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	res = clk_dt_get_by_name(fdt, node, "clk1", &clk);
	if (res || clk != clk1) {
		DT_TEST_MSG("Unexpected clock reference");
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	DT_TEST_MSG("Bad clock reference");

	res = clk_dt_get_by_index(fdt, node, 3, &clk);
	if (!res) {
		DT_TEST_MSG("Unexpected clock found on invalid index");
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	res = clk_dt_get_by_name(fdt, node, "clk2", &clk);
	if (!res) {
		DT_TEST_MSG("Unexpected clock found on invalid name");
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	dt_test_state.probe_clocks = SUCCESS;
	return TEE_SUCCESS;

err:
	if (res != TEE_ERROR_DEFER_DRIVER_INIT)
		dt_test_state.probe_clocks = FAILED;

	return res;
}

static TEE_Result probe_test_resets(const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rstctrl *rstctrl0 = NULL;
	struct rstctrl *rstctrl1 = NULL;
	struct rstctrl *rstctrl = NULL;

	DT_TEST_MSG("Probe reset controllers");
	dt_test_state.probe_resets = IN_PROGRESS;

	res = rstctrl_dt_get_by_index(fdt, node, 0, &rstctrl0);
	if (res)
		goto err;

	DT_TEST_MSG("Check valid reset controller");

	if (rstctrl_assert(rstctrl0)) {
		EMSG("Can't assert rstctrl %s", rstctrl_name(rstctrl0));
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	res = rstctrl_dt_get_by_name(fdt, node, "rst0", &rstctrl);
	if (res)
		goto err;

	if (rstctrl != rstctrl0) {
		EMSG("Unexpected reset controller reference");
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	res = rstctrl_dt_get_by_name(fdt, node, "rst1", &rstctrl1);
	if (res)
		goto err;

	if (!rstctrl1 || rstctrl1 == rstctrl0) {
		EMSG("Unexpected reset controller reference");
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	dt_test_state.probe_resets = SUCCESS;
	return TEE_SUCCESS;

err:
	if (res != TEE_ERROR_DEFER_DRIVER_INIT)
		dt_test_state.probe_resets = FAILED;

	return res;
}

static TEE_Result probe_test_gpios(const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct gpio *gpio = NULL;

	DT_TEST_MSG("Probe GPIO controllers");
	dt_test_state.probe_gpios = IN_PROGRESS;

	res = gpio_dt_get_by_index(fdt, node, 0, "test", &gpio);
	if (res)
		goto err;

	if (gpio_get_direction(gpio) != GPIO_DIR_IN) {
		EMSG("Unexpected gpio_get_direction() return value");
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	/* GPIO is declared as ACTIVE_LOW in device-tree */
	if (gpio_get_value(gpio) != GPIO_LEVEL_LOW) {
		EMSG("Unexpected gpio_get_value() return value");
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	res = gpio_dt_get_by_index(fdt, node, 1, "test", &gpio);
	if (res)
		goto err;

	if (gpio_get_direction(gpio) != GPIO_DIR_IN) {
		EMSG("Unexpected gpio_get_direction() return value");
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	if (gpio_get_value(gpio) != GPIO_LEVEL_HIGH) {
		EMSG("Unexpected gpio_get_value() return value");
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	dt_test_state.probe_gpios = SUCCESS;
	return TEE_SUCCESS;

err:
	if (res != TEE_ERROR_DEFER_DRIVER_INIT)
		dt_test_state.probe_gpios = FAILED;

	return res;
}

/* IDs used for GPIOs that control some regulators */
#define DT_TEST_GPIO4REGU_FIXED_ENABLE	0
#define DT_TEST_GPIO4REGU_GPIO_ENABLE	1
#define DT_TEST_GPIO4REGU_GPIO_VOLTAGE	2
#define DT_TEST_GPIO4REGU_PIN_COUNT	3

#if defined(CFG_DRIVERS_REGULATOR) && defined(CFG_DRIVERS_GPIO)
/* Helper to check states of GPIOs that control some regulators */
static void gpio4regu_get_state(unsigned int pin_id, enum gpio_dir *direction,
				enum gpio_level *level);
#else
static void gpio4regu_get_state(unsigned int pin_id __unused,
				enum gpio_dir *direction __unused,
				enum gpio_level *level __unused)
{
}
#endif

static TEE_Result probe_test_regulator_test1(const void *fdt, int node)
{
	enum gpio_level gpio_level = GPIO_LEVEL_LOW;
	enum gpio_dir gpio_dir = GPIO_DIR_IN;
	struct regulator *regu_test1 = NULL;
	struct regulator *regu_fixed = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint64_t timeout = 0;
	int min_level_uv = 0;
	int max_level_uv = 0;
	int level_uv = 0;

	res = regulator_dt_get_supply(fdt, node, "test1", &regu_test1);
	if (res)
		return res;

	/* Check voltage level for regulator test1 */
	regulator_get_range(regu_test1, &min_level_uv, &max_level_uv);
	if (min_level_uv != 100 || max_level_uv != 1000000) {
		EMSG("Unexpected range [%d %d] for regulator test1",
		     min_level_uv, max_level_uv);
		return TEE_ERROR_GENERIC;
	}

	level_uv = regulator_get_voltage(regu_test1);
	if (level_uv != 100) {
		EMSG("Unexpected voltage level %d for regulator test1",
		     level_uv);
		return TEE_ERROR_GENERIC;
	}

	res = regulator_set_voltage(regu_test1, 1);
	if (!res) {
		EMSG("Setting voltage to 1uV should fail for regulator test1");
		return TEE_ERROR_GENERIC;
	}

	res = regulator_set_voltage(regu_test1, 2000000);
	if (!res) {
		EMSG("Setting voltage to 2V should fail for regulator test1");
		return TEE_ERROR_GENERIC;
	}

	res = regulator_set_voltage(regu_test1, 500000);
	if (res) {
		EMSG("Set voltage failed for regulator test1: %#"PRIx32, res);
		return res;
	}

	/* Voltage level for regulator test1 supply (is a regulator-fixed) */
	regu_fixed = regu_test1->supply;
	if (!regu_fixed) {
		EMSG("Regulator test1 should have a supply");
		return TEE_ERROR_GENERIC;
	}

	regulator_get_range(regu_test1->supply, &min_level_uv, &max_level_uv);
	if (min_level_uv != 1000000 || max_level_uv != 1000000) {
		EMSG("Unexpected range [%d %d] for regulator test1",
		     min_level_uv, max_level_uv);
		return TEE_ERROR_GENERIC;
	}

	level_uv = regulator_get_voltage(regu_test1->supply);
	if (level_uv != 1000000) {
		EMSG("Unexpected voltage level %duV for regulator test1",
		     level_uv);
		return TEE_ERROR_GENERIC;
	}

	/* Tests below expect GPIO are supported */
	if (!IS_ENABLED(CFG_DRIVERS_GPIO))
		return TEE_SUCCESS;

	/*
	 * Enabling regulator test1 should last at least 20ms due
	 * to supply enable delay (only when CFG_DRIVERS_GPIO is enabled)
	 */
	timeout = timeout_init_us(20000);

	res = regulator_enable(regu_test1);
	if (res) {
		EMSG("Enable failed for regulator test1: %#"PRIx32, res);
		return res;
	}

	if (!timeout_elapsed(timeout)) {
		EMSG("Set test1 voltage is too fast: %dus < 20ms",
		     timeout_elapsed_us(timeout) + 20000);
		return TEE_ERROR_GENERIC;
	}

	/*
	 * Re-enabling regulator test1 after it's been disabled should last
	 * 30ms (10ms off/on delay + 20ms enable delay)
	 */
	res = regulator_disable(regu_test1);
	if (res) {
		EMSG("Disable failed for regulator test1: %#"PRIx32, res);
		return res;
	}

	/*
	 * Give 10us tolerance to compensate time between regulator_disable()
	 * completion and timeout_init_us() completion.
	 */
	timeout = timeout_init_us(30000 - 10);

	res = regulator_enable(regu_test1);
	if (res) {
		EMSG("Enable failed for regulator test1: %#"PRIx32, res);
		return res;
	}

	if (!timeout_elapsed(timeout)) {
		EMSG("Enable regulator test1 is too fast: %dus < 30ms",
		     timeout_elapsed_us(timeout) + 30000);
		return TEE_ERROR_GENERIC;
	}

	/*
	 * Check GPIO level when test1 and its supply are enabled and disable.
	 * Note the GPIO used is active low.
	 */
	gpio4regu_get_state(DT_TEST_GPIO4REGU_FIXED_ENABLE, &gpio_dir, NULL);
	if (gpio_dir != GPIO_DIR_OUT) {
		EMSG("Unexpected state of GPIO used for test1 supply");
		return TEE_ERROR_GENERIC;
	}

	res = regulator_disable(regu_test1);
	if (res) {
		EMSG("Disable failed for regulator test1: %#"PRIx32, res);
		return res;
	}

	gpio4regu_get_state(DT_TEST_GPIO4REGU_FIXED_ENABLE, NULL, &gpio_level);
	if (gpio_level != GPIO_LEVEL_HIGH) {
		EMSG("GPIO used for regulator test1 supply should be high");
		return TEE_ERROR_GENERIC;
	}

	res = regulator_enable(regu_test1);
	if (res) {
		EMSG("Enable failed for regulator test1: %#"PRIx32, res);
		return res;
	}

	gpio4regu_get_state(DT_TEST_GPIO4REGU_FIXED_ENABLE, NULL, &gpio_level);
	if (gpio_level != GPIO_LEVEL_LOW) {
		EMSG("GPIO used for regulator test1 supply should be low");
		return TEE_ERROR_GENERIC;
	}

	res = regulator_disable(regu_test1);
	if (res) {
		EMSG("Disable failed for regulator test1: %#"PRIx32, res);
		return res;
	}

	gpio4regu_get_state(DT_TEST_GPIO4REGU_FIXED_ENABLE, NULL, &gpio_level);
	if (gpio_level != GPIO_LEVEL_HIGH) {
		EMSG("GPIO used for regulator test1 supply should be high");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result probe_test_regulator_test2(const void *fdt, int node)
{
	enum gpio_level gpio_level = GPIO_LEVEL_LOW;
	enum gpio_dir gpio_dir = GPIO_DIR_IN;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct regulator *regu_test2 = NULL;
	uint64_t timeout = 0;
	int min_level_uv = 0;
	int max_level_uv = 0;
	int level_uv = 0;

	/*
	 * Test regulator test2 and its regulator GPIO supply
	 */
	res = regulator_dt_get_supply(fdt, node, "test2", &regu_test2);
	if (res)
		return res;

	gpio4regu_get_state(DT_TEST_GPIO4REGU_GPIO_ENABLE, &gpio_dir, NULL);
	if (gpio_dir != GPIO_DIR_OUT) {
		EMSG("Unexpected direction of GPIO used for test2 supply");
		return TEE_ERROR_GENERIC;
	}

	/* Check voltage level for regulator test2 */
	regulator_get_range(regu_test2, &min_level_uv, &max_level_uv);
	if (min_level_uv != 300000 || max_level_uv != 700000) {
		EMSG("Unexpected range [%d %d] for regulator test2",
		     min_level_uv, max_level_uv);
		return TEE_ERROR_GENERIC;
	}

	level_uv = regulator_get_voltage(regu_test2);
	if (level_uv != 300000) {
		EMSG("Unexpected voltage level %d for regulator test2",
		     level_uv);
		return TEE_ERROR_GENERIC;
	}

	res = regulator_set_voltage(regu_test2, 200000);
	if (!res) {
		EMSG("Setting voltage to 1uV should fail for regulator test2");
		return TEE_ERROR_GENERIC;
	}

	res = regulator_set_voltage(regu_test2, 500000);
	if (res) {
		EMSG("Set voltage failed for regulator test2: %#"PRIx32, res);
		return res;
	}

	level_uv = regulator_get_voltage(regu_test2);
	if (level_uv != 500000) {
		EMSG("Unexpected voltage level %duV for regulator test2",
		     level_uv);
		return TEE_ERROR_GENERIC;
	}

	/* Enabling regulator test2 should last at least 15ms */
	timeout = timeout_init_us(15000);

	res = regulator_enable(regu_test2);
	if (res) {
		EMSG("Enable failed for regulator gpio: %#"PRIx32, res);
		return res;
	}

	if (!timeout_elapsed(timeout)) {
		EMSG("Set regulator voltage level is too fast: %dus < 15ms",
		     timeout_elapsed_us(timeout) + 15000);
		return TEE_ERROR_GENERIC;
	}

	/* Supply enable GPIO absolute level shall be low (it's active-high) */
	gpio4regu_get_state(DT_TEST_GPIO4REGU_GPIO_ENABLE, NULL, &gpio_level);
	if (gpio_level != GPIO_LEVEL_HIGH) {
		EMSG("GPIO used for test2 supply should be high");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result probe_test_regulator_gpio(const void *fdt, int node)
{
	enum gpio_level gpio_level = GPIO_LEVEL_LOW;
	enum gpio_dir gpio_dir = GPIO_DIR_IN;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct regulator *regu_gpio = NULL;
	int min_level_uv = 0;
	int max_level_uv = 0;
	int level_uv = 0;

	/*
	 * Test regulator test2 and its regulator GPIO supply
	 */
	res = regulator_dt_get_supply(fdt, node, "regu_gpio", &regu_gpio);
	if (res)
		return res;

	gpio4regu_get_state(DT_TEST_GPIO4REGU_GPIO_VOLTAGE, &gpio_dir, NULL);
	if (gpio_dir != GPIO_DIR_OUT) {
		EMSG("Bad direction of GPIO for regulator enable");
		return TEE_ERROR_GENERIC;
	}

	/* Check voltage level for regulator test2 */
	regulator_get_range(regu_gpio, &min_level_uv, &max_level_uv);
	if (min_level_uv != 400000 || max_level_uv != 800000) {
		EMSG("Unexpected range [%d %d] for regulator gpio",
		     min_level_uv, max_level_uv);
		return TEE_ERROR_GENERIC;
	}

	level_uv = regulator_get_voltage(regu_gpio);
	if (level_uv != 400000 && level_uv != 800000) {
		EMSG("Unexpected voltage level %d for regulator gpio",
		     level_uv);
		return TEE_ERROR_GENERIC;
	}

	gpio4regu_get_state(DT_TEST_GPIO4REGU_GPIO_VOLTAGE, NULL, &gpio_level);
	if (gpio_level != GPIO_LEVEL_LOW) {
		EMSG("Unexpected state of regulator GPIO, should be low");
		return TEE_ERROR_GENERIC;
	}

	res = regulator_set_voltage(regu_gpio, 200000);
	if (!res) {
		EMSG("Set voltage level to 1uV should fail for regulator gpio");
		return TEE_ERROR_GENERIC;
	}

	res = regulator_set_voltage(regu_gpio, 800000);
	if (res) {
		EMSG("Set voltage failed for regulator gpio: %#"PRIx32, res);
		return res;
	}

	level_uv = regulator_get_voltage(regu_gpio);
	if (level_uv != 800000) {
		EMSG("Unexpected voltage %duV for regulator gpio", level_uv);
		return TEE_ERROR_GENERIC;
	}

	gpio4regu_get_state(DT_TEST_GPIO4REGU_GPIO_VOLTAGE, NULL, &gpio_level);
	if (gpio_level != GPIO_LEVEL_LOW) {
		EMSG("Unexpected state of regulator GPIO, should be low");
		return TEE_ERROR_GENERIC;
	}

	res = regulator_set_voltage(regu_gpio, 400000);
	if (res) {
		EMSG("Set voltage failed for regulator gpio: %#"PRIx32, res);
		return res;
	}

	level_uv = regulator_get_voltage(regu_gpio);
	if (level_uv != 400000) {
		EMSG("Unexpected voltage %duV for regulator gpio", level_uv);
		return TEE_ERROR_GENERIC;
	}

	gpio4regu_get_state(DT_TEST_GPIO4REGU_GPIO_VOLTAGE, NULL, &gpio_level);
	if (gpio_level != GPIO_LEVEL_HIGH) {
		EMSG("Unexpected state of regulator GPIO, should be high");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result probe_test_regulators(const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct regulator __maybe_unused *regulator = NULL;

	DT_TEST_MSG("Probe regulator test");

	dt_test_state.probe_regulators = IN_PROGRESS;

	/* First probe both test regualtors */
	res = regulator_dt_get_supply(fdt, node, "test1", &regulator);
	if (res)
		goto err_or_defer;

	if (IS_ENABLED(CFG_REGULATOR_GPIO)) {
		res = regulator_dt_get_supply(fdt, node, "test2", &regulator);
		if (res)
			goto err_or_defer;
	}

	res = probe_test_regulator_test1(fdt, node);
	if (res)
		goto err;

	if (IS_ENABLED(CFG_REGULATOR_GPIO)) {
		res = probe_test_regulator_test2(fdt, node);
		if (res)
			goto err;

		res = probe_test_regulator_gpio(fdt, node);
		if (res)
			goto err;
	}

	dt_test_state.probe_regulators = SUCCESS;

	return TEE_SUCCESS;

err:
	if (res == TEE_ERROR_DEFER_DRIVER_INIT) {
		EMSG("Unexpected driver initialization deferral");
		res = TEE_ERROR_GENERIC;
	}
err_or_defer:
	if (res != TEE_ERROR_DEFER_DRIVER_INIT)
		dt_test_state.probe_regulators = FAILED;

	return res;
}

/*
 * Consumer test driver: instance probed from the compatible
 * node parsed in the DT. It consumes emulated resource obtained
 * from DT references. Probe shall succeed only once all resources
 * are found.
 */
static TEE_Result dt_test_consumer_probe(const void *fdt, int node,
					 const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (IS_ENABLED(CFG_DRIVERS_CLK)) {
		res = probe_test_clocks(fdt, node);
		if (res)
			goto err_probe;
	}

	if (IS_ENABLED(CFG_DRIVERS_RSTCTRL)) {
		res = probe_test_resets(fdt, node);
		if (res)
			goto err_probe;
	}

	if (IS_ENABLED(CFG_DRIVERS_GPIO)) {
		res = probe_test_gpios(fdt, node);
		if (res)
			goto err_probe;
	}

	if (IS_ENABLED(CFG_DRIVERS_REGULATOR)) {
		res = probe_test_regulators(fdt, node);
		if (res)
			goto err_probe;
	}

	if (dt_test_state.probe_deferral != IN_PROGRESS) {
		dt_test_state.probe_deferral = FAILED;
		return TEE_ERROR_GENERIC;
	}

	dt_test_state.probe_deferral = SUCCESS;

	return TEE_SUCCESS;

err_probe:
	assert(res);

	if (res == TEE_ERROR_DEFER_DRIVER_INIT &&
	    dt_test_state.probe_deferral == DEFAULT) {
		/* We expect at least a probe deferral */
		dt_test_state.probe_deferral = IN_PROGRESS;
	}

	return res;
}

static const struct dt_device_match dt_test_consumer_match_table[] = {
	{ .compatible = "linaro,dt-test-consumer", },
	{ }
};

DEFINE_DT_DRIVER(dt_test_consumer_driver) = {
	.name = "dt-test-consumer",
	.match_table = dt_test_consumer_match_table,
	.probe = dt_test_consumer_probe,
};

static TEE_Result dt_test_crypt_consumer_probe(const void *fdt __unused,
					       int node __unused,
					       const void *compat_data __unused)
{
	TEE_Result res = dt_driver_get_crypto();
	uint8_t __maybe_unused byte = 0;

	if (res == TEE_ERROR_DEFER_DRIVER_INIT &&
	    dt_test_state.crypto_dependencies == DEFAULT) {
		/* We expect to be deferred */
		dt_test_state.crypto_dependencies = IN_PROGRESS;
	}

	if (res)
		return res;

	if (dt_test_state.crypto_dependencies == DEFAULT) {
		EMSG("Test expects at least a driver probe deferral");
		dt_test_state.crypto_dependencies = FAILED;
		return TEE_ERROR_GENERIC;
	}

	if (crypto_rng_read(&byte, sizeof(byte))) {
		dt_test_state.crypto_dependencies = FAILED;
		return TEE_ERROR_GENERIC;
	}

	dt_test_state.crypto_dependencies = SUCCESS;
	return TEE_SUCCESS;
}

static const struct dt_device_match dt_test_crypt_consumer_match_table[] = {
	{ .compatible = "linaro,dt-test-crypt-consumer", },
	{ }
};

DEFINE_DT_DRIVER(dt_test_consumer_driver) = {
	.name = "dt-test-crypt-consumer",
	.match_table = dt_test_crypt_consumer_match_table,
	.probe = dt_test_crypt_consumer_probe,
};

#ifdef CFG_DRIVERS_CLK
#define DT_TEST_CLK_COUNT		2

#define DT_TEST_CLK0_BINDING_ID		3
#define DT_TEST_CLK1_BINDING_ID		7

static const char *dt_test_clk_name[DT_TEST_CLK_COUNT] = {
	"dt_test-clk3",
	"dt_test-clk7",
};

/* Emulating a clock does not require operators */
static const struct clk_ops dt_test_clock_provider_ops;

static TEE_Result dt_test_get_clk(struct dt_pargs *args, void *data,
				  struct clk **out_device)
{
	struct clk *clk_ref = data;
	struct clk *clk = NULL;

	if (args->args_count != 1)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (args->args[0]) {
	case DT_TEST_CLK0_BINDING_ID:
		clk = clk_ref;
		break;
	case DT_TEST_CLK1_BINDING_ID:
		clk = clk_ref + 1;
		break;
	default:
		EMSG("Unexpected binding ID %"PRIu32, args->args[0]);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	DT_TEST_MSG("Providing clock %s", clk_get_name(clk));

	*out_device = clk;
	return TEE_SUCCESS;
}

static TEE_Result dt_test_clock_provider_probe(const void *fdt, int node,
					       const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct clk *clk = NULL;
	size_t n = 0;

	DT_TEST_MSG("Register clocks");

	clk = dt_test_alloc(DT_TEST_CLK_COUNT * sizeof(*clk));
	if (!clk)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (n = 0; n < DT_TEST_CLK_COUNT; n++) {
		clk[n].ops = &dt_test_clock_provider_ops;
		clk[n].name = dt_test_clk_name[n];

		res = clk_register(clk + n);
		if (res)
			goto err;
	}

	res = clk_dt_register_clk_provider(fdt, node, dt_test_get_clk, clk);
	if (res)
		goto err;

	return TEE_SUCCESS;

err:
	dt_test_free(clk);
	return res;
}

CLK_DT_DECLARE(dt_test_clock_provider, "linaro,dt-test-provider",
	       dt_test_clock_provider_probe);
#endif /* CFG_DRIVERS_CLK */

#ifdef CFG_DRIVERS_RSTCTRL
#define DT_TEST_RSTCTRL_COUNT		2

#define DT_TEST_RSTCTRL0_BINDING_ID	5
#define DT_TEST_RSTCTRL1_BINDING_ID	35

struct dt_test_rstctrl {
	unsigned int dt_binding;
	struct rstctrl rstctrl;
};

static struct dt_test_rstctrl *to_test_rstctrl(struct rstctrl *rstctrl)
{
	return container_of(rstctrl, struct dt_test_rstctrl, rstctrl);
}

static TEE_Result dt_test_rstctrl_stub(struct rstctrl *rstctrl __maybe_unused,
				       unsigned int to_us __unused)
{
	struct dt_test_rstctrl *dev = to_test_rstctrl(rstctrl);

	switch (dev->dt_binding) {
	case DT_TEST_RSTCTRL0_BINDING_ID:
	case DT_TEST_RSTCTRL1_BINDING_ID:
		return TEE_SUCCESS;
	default:
		EMSG("Unexpected rstctrl reference");
		return TEE_ERROR_GENERIC;
	}
}

static const char *dt_test_rstctrl_name(struct rstctrl *rstctrl __maybe_unused)
{
	static const char *rstctrl_name[DT_TEST_RSTCTRL_COUNT] = {
		"dt_test-rstctrl5",
		"dt_test-rstctrl35",
	};
	struct dt_test_rstctrl *dev = to_test_rstctrl(rstctrl);

	switch (dev->dt_binding) {
	case DT_TEST_RSTCTRL0_BINDING_ID:
		return rstctrl_name[0];
	case DT_TEST_RSTCTRL1_BINDING_ID:
		return rstctrl_name[1];
	default:
		EMSG("Unexpected rstctrl reference");
		return NULL;
	}
}

const struct rstctrl_ops dt_test_rstctrl_ops = {
	.assert_level = dt_test_rstctrl_stub,
	.deassert_level = dt_test_rstctrl_stub,
	.get_name = dt_test_rstctrl_name,
};

static TEE_Result dt_test_get_rstctrl(struct dt_pargs *args, void *data,
				      struct rstctrl **out_device)
{
	struct dt_test_rstctrl *ref = data;
	struct rstctrl *rstctrl = NULL;

	if (args->args_count != 1)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (args->args[0]) {
	case DT_TEST_RSTCTRL0_BINDING_ID:
		rstctrl = &ref[0].rstctrl;
		break;
	case DT_TEST_RSTCTRL1_BINDING_ID:
		rstctrl = &ref[1].rstctrl;
		break;
	default:
		EMSG("Unexpected binding ID %"PRIu32, args->args[0]);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	DT_TEST_MSG("Providing reset controller %s", rstctrl_name(rstctrl));

	*out_device = rstctrl;

	return TEE_SUCCESS;
}

static TEE_Result dt_test_rstctrl_provider_probe(const void *fdt, int offs,
						 const void *data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dt_test_rstctrl *devices = NULL;

	DT_TEST_MSG("Register reset controllers");

	assert(rstctrl_ops_is_valid(&dt_test_rstctrl_ops));

	devices = dt_test_alloc(DT_TEST_RSTCTRL_COUNT * sizeof(*devices));
	if (!devices)
		return TEE_ERROR_OUT_OF_MEMORY;

	devices[0].rstctrl.ops = &dt_test_rstctrl_ops;
	devices[0].dt_binding = DT_TEST_RSTCTRL0_BINDING_ID;

	devices[1].rstctrl.ops = &dt_test_rstctrl_ops;
	devices[1].dt_binding = DT_TEST_RSTCTRL1_BINDING_ID;

	res = rstctrl_register_provider(fdt, offs, dt_test_get_rstctrl,
					devices);
	if (res) {
		dt_test_free(devices);
		return res;
	}

	return TEE_SUCCESS;
}

RSTCTRL_DT_DECLARE(dt_test_rstctrl_provider, "linaro,dt-test-provider",
		   dt_test_rstctrl_provider_probe);
#endif /* CFG_DRIVERS_RSTCTRL */

#ifdef CFG_DRIVERS_GPIO
#define DT_TEST_GPIO_COUNT	2

#define DT_TEST_GPIO0_PIN	1
#define DT_TEST_GPIO0_FLAGS	GPIO_ACTIVE_LOW
#define DT_TEST_GPIO1_PIN	2
#define DT_TEST_GPIO1_FLAGS	GPIO_PULL_UP

struct dt_test_gpio {
	unsigned int pin;
	unsigned int flags;
	struct gpio_chip gpio_chip;
};

static struct dt_test_gpio *to_test_gpio(struct gpio_chip *chip)
{
	return container_of(chip, struct dt_test_gpio, gpio_chip);
}

static enum gpio_dir dt_test_gpio_get_direction(struct gpio_chip *chip,
						unsigned int gpio_pin)
{
	struct dt_test_gpio *dtg = to_test_gpio(chip);

	if (dtg->pin != gpio_pin)
		panic("Invalid GPIO number");

	return GPIO_DIR_IN;
}

static void dt_test_gpio_set_direction(struct gpio_chip *chip,
				       unsigned int gpio_pin,
				       enum gpio_dir direction __unused)
{
	struct dt_test_gpio *dtg = to_test_gpio(chip);

	if (dtg->pin != gpio_pin)
		panic("Invalid GPIO number");
}

static enum gpio_level dt_test_gpio_get_value(struct gpio_chip *chip,
					      unsigned int gpio_pin)
{
	struct dt_test_gpio *dtg = to_test_gpio(chip);

	if (dtg->pin != gpio_pin)
		panic("Invalid GPIO number");

	return GPIO_LEVEL_HIGH;
}

static void dt_test_gpio_set_value(struct gpio_chip *chip,
				   unsigned int gpio_pin,
				   enum gpio_level value __unused)
{
	struct dt_test_gpio *dtg = to_test_gpio(chip);

	if (dtg->pin != gpio_pin)
		panic("Invalid GPIO number");
}

static const struct gpio_ops dt_test_gpio_ops = {
	.get_direction = dt_test_gpio_get_direction,
	.set_direction = dt_test_gpio_set_direction,
	.get_value = dt_test_gpio_get_value,
	.set_value = dt_test_gpio_set_value,
};

static TEE_Result dt_test_gpio_get_dt(struct dt_pargs *args, void *data,
				      struct gpio **out_device)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct gpio *gpio = NULL;
	struct dt_test_gpio *gpios = (struct dt_test_gpio *)data;

	res = gpio_dt_alloc_pin(args, &gpio);
	if (res)
		return res;

	switch (gpio->pin) {
	case DT_TEST_GPIO0_PIN:
		gpio->chip = &gpios[0].gpio_chip;
		if (gpio->dt_flags != gpios[0].flags) {
			EMSG("Unexpected dt_flags %#"PRIx32, gpio->dt_flags);
			free(gpio);
			return TEE_ERROR_GENERIC;
		}
		break;
	case DT_TEST_GPIO1_PIN:
		gpio->chip = &gpios[1].gpio_chip;
		if (gpio->dt_flags != gpios[1].flags) {
			EMSG("Unexpected dt_flags %#"PRIx32, gpio->dt_flags);
			free(gpio);
			return TEE_ERROR_GENERIC;
		}
		break;
	default:
		EMSG("Unexpected pin ID %u", gpio->pin);
		free(gpio);
		return TEE_ERROR_BAD_PARAMETERS;
	};

	*out_device = gpio;

	return TEE_SUCCESS;
}

static TEE_Result dt_test_gpio_provider_probe(const void *fdt, int offs,
					      const void *data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dt_test_gpio *gpios = NULL;

	DT_TEST_MSG("Register GPIO controllers");

	assert(gpio_ops_is_valid(&dt_test_gpio_ops));

	gpios = dt_test_alloc(DT_TEST_GPIO_COUNT * sizeof(*gpios));
	if (!gpios)
		return TEE_ERROR_OUT_OF_MEMORY;

	gpios[0].gpio_chip.ops = &dt_test_gpio_ops;
	gpios[0].pin = DT_TEST_GPIO0_PIN;
	gpios[0].flags = DT_TEST_GPIO0_FLAGS;

	gpios[1].gpio_chip.ops = &dt_test_gpio_ops;
	gpios[1].pin = DT_TEST_GPIO1_PIN;
	gpios[1].flags = DT_TEST_GPIO1_FLAGS;

	res = gpio_register_provider(fdt, offs, dt_test_gpio_get_dt, gpios);
	if (res) {
		dt_test_free(gpios);
		return res;
	}

	return TEE_SUCCESS;
}

GPIO_DT_DECLARE(dt_test_gpio_provider, "linaro,dt-test-provider",
		dt_test_gpio_provider_probe);
#endif /* CFG_DRIVERS_GPIO */

#ifdef CFG_DRIVERS_REGULATOR

/* Testing regulator-gpio and regulator-fixed drivers depend on GPIO support */
#ifdef CFG_DRIVERS_GPIO
struct dt_test_gpio4regu_pin {
	enum gpio_level level;
	enum gpio_dir dir;
};

struct dt_test_gpio4regu_chip {
	struct dt_test_gpio4regu_pin pin[DT_TEST_GPIO4REGU_PIN_COUNT];
	struct gpio_chip gpio_chip;
};

static struct dt_test_gpio4regu_chip *gpio4regu_chip;

static void gpio4regu_get_state(unsigned int pin_id, enum gpio_dir *direction,
				enum gpio_level *level)
{
	if (!gpio4regu_chip || pin_id >= DT_TEST_GPIO4REGU_PIN_COUNT)
		panic();

	if (direction)
		*direction = gpio4regu_chip->pin[pin_id].dir;
	if (level)
		*level = gpio4regu_chip->pin[pin_id].level;
}

static struct dt_test_gpio4regu_pin *to_gpio4regu_pin(struct gpio_chip *chip,
						      unsigned int gpio_pin)
{
	struct dt_test_gpio4regu_chip *dev = NULL;

	if (gpio_pin >= DT_TEST_GPIO4REGU_PIN_COUNT)
		panic("Invalid GPIO pin");

	dev = container_of(chip, struct dt_test_gpio4regu_chip, gpio_chip);

	return dev->pin + gpio_pin;
}

static enum gpio_dir dt_test_gpio4regu_get_dir(struct gpio_chip *chip,
					       unsigned int gpio_pin)
{
	struct dt_test_gpio4regu_pin *dtg = to_gpio4regu_pin(chip, gpio_pin);

	return dtg->dir;
}

static void dt_test_gpio4regu_set_dir(struct gpio_chip *chip,
				      unsigned int gpio_pin,
				      enum gpio_dir direction)
{
	struct dt_test_gpio4regu_pin *dtg = to_gpio4regu_pin(chip, gpio_pin);

	dtg->dir = direction;
}

static enum gpio_level dt_test_gpio4regu_get_value(struct gpio_chip *chip,
						   unsigned int gpio_pin)
{
	struct dt_test_gpio4regu_pin *dtg = to_gpio4regu_pin(chip, gpio_pin);

	return dtg->level;
}

static void dt_test_gpio4regu_set_value(struct gpio_chip *chip,
					unsigned int gpio_pin,
					enum gpio_level value)
{
	struct dt_test_gpio4regu_pin *dtg = to_gpio4regu_pin(chip, gpio_pin);

	dtg->level = value;
}

static const struct gpio_ops dt_test_gpio4regu_ops = {
	.get_direction = dt_test_gpio4regu_get_dir,
	.set_direction = dt_test_gpio4regu_set_dir,
	.get_value = dt_test_gpio4regu_get_value,
	.set_value = dt_test_gpio4regu_set_value,
};

static TEE_Result dt_test_gpio4regu_get_dt(struct dt_pargs *args, void *data,
					   struct gpio **out_device)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dt_test_gpio4regu_chip *chip = data;
	struct gpio *gpio = NULL;

	res = gpio_dt_alloc_pin(args, &gpio);
	if (res)
		return res;

	if (gpio->pin > DT_TEST_GPIO4REGU_PIN_COUNT) {
		EMSG("Unexpected pin value %u", gpio->pin);
		return TEE_ERROR_GENERIC;
	}

	gpio->chip = &chip->gpio_chip;

	*out_device = gpio;

	return TEE_SUCCESS;
}

static TEE_Result dt_test_gpio4regu_provider_probe(const void *fdt, int offs,
						   const void *data __unused)
{
	struct dt_test_gpio4regu_chip *chip = NULL;

	DT_TEST_MSG("Register GPIO chip for regulators");

	chip = dt_test_alloc(sizeof(*chip));
	if (!chip)
		return TEE_ERROR_OUT_OF_MEMORY;

	chip->gpio_chip.ops = &dt_test_gpio4regu_ops;

	/* Save reference to ease test implementation */
	gpio4regu_chip = chip;

	return gpio_register_provider(fdt, offs, dt_test_gpio4regu_get_dt,
				      chip);
}

GPIO_DT_DECLARE(dt_test_gpio4regu_provider, "linaro,dt-test-gpio4regu",
		dt_test_gpio4regu_provider_probe);
#endif /* CFG_DRIVERS_GPIO */

struct dt_test_regulator {
	bool enabled;
	int level_uv;
};

static TEE_Result dt_test_regulator_set_state(struct regulator *regulator,
					      bool enable)
{
	struct dt_test_regulator *regu = regulator->priv;

	regu->enabled = enable;

	return TEE_SUCCESS;
}

static TEE_Result dt_test_regulator_read_state(struct regulator *regulator,
					       bool *enabled)
{
	struct dt_test_regulator *regu = regulator->priv;

	*enabled = regu->enabled;

	return TEE_SUCCESS;
}

static TEE_Result dt_test_regulator_set_voltage(struct regulator *regulator,
						int level_uv)
{
	struct dt_test_regulator *regu = regulator->priv;

	regu->level_uv = level_uv;

	return TEE_SUCCESS;
}

static TEE_Result dt_test_regulator_read_voltage(struct regulator *regulator,
						 int *level_uv)
{
	struct dt_test_regulator *regu = regulator->priv;

	*level_uv = regu->level_uv;

	return TEE_SUCCESS;
}

static const struct regulator_ops dt_test_regulator_ops = {
	.set_state = dt_test_regulator_set_state,
	.get_state = dt_test_regulator_read_state,
	.set_voltage = dt_test_regulator_set_voltage,
	.get_voltage = dt_test_regulator_read_voltage,
};

static TEE_Result dt_test_regulator_probe(const void *fdt, int offs,
					  const void *data __unused)
{
	struct dt_test_regulator *test_regulator = NULL;
	struct regu_dt_desc desc = { };

	DT_TEST_MSG("Register regulators");

	test_regulator = dt_test_alloc(sizeof(*test_regulator));
	if (!test_regulator)
		return TEE_ERROR_OUT_OF_MEMORY;

	desc = (struct regu_dt_desc){
		.ops = &dt_test_regulator_ops,
		.supply_name = "test",
		.priv = test_regulator,
	};

	return regulator_dt_register(fdt, offs, offs, &desc);
}

static const struct dt_device_match dt_test_regulator_match_table[] = {
	{ .compatible = "linaro,dt-test-regulator" },
	{ }
};

DEFINE_DT_DRIVER(dt_test_regulator_dt_driver) = {
	.name = "dt-test-regulator-provider",
	.match_table = dt_test_regulator_match_table,
	.probe = dt_test_regulator_probe,
};
#endif /* CFG_DRIVERS_REGULATOR */
