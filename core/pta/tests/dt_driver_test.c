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
#include <drivers/rstctrl.h>
#include <initcall.h>
#include <kernel/dt_driver.h>
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
