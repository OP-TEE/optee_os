// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024-2025, NVIDIA CORPORATION
 */

#include <compiler.h>
#include <console.h>
#include <ffa.h>
#include <string.h>
#include <drivers/serial.h>
#include <drivers/ffa_console.h>
#include <kernel/dt_driver.h>
#include <kernel/thread_arch.h>

struct ffa_console_data {
	struct serial_chip chip;
	char buf[FFA_CONSOLE_LOG_64_MAX_MSG_LEN];
	size_t pos;
};

static struct ffa_console_data ffa_console __nex_bss;

static void copy_buf_to_args(struct thread_smc_args *args,
			     const char *buf, size_t len,
			     size_t reg_size)
{
	size_t i = 0;
	size_t j = 0;

	args->a1 = len;

	for (i = 0, j = 0; j < len; i++, j += reg_size)
		memcpy(&args->a2 + i, buf + j, MIN(len - j, reg_size));
}

static void ffa_console_32_flush(struct serial_chip *chip)
{
	struct ffa_console_data *pd =
		container_of(chip, struct ffa_console_data, chip);
	struct thread_smc_args args = {
		.a0 = FFA_CONSOLE_LOG_32
	};

	copy_buf_to_args(&args, pd->buf, pd->pos, sizeof(uint32_t));
	thread_smccc(&args);
	pd->pos = 0;
}

static void ffa_console_32_putc(struct serial_chip *chip, int ch)
{
	struct ffa_console_data *pd =
		container_of(chip, struct ffa_console_data, chip);

	pd->buf[pd->pos++] = ch;

	if (pd->pos == FFA_CONSOLE_LOG_32_MAX_MSG_LEN)
		ffa_console_32_flush(chip);
}

static const struct serial_ops ffa_console_32_ops = {
	.putc = ffa_console_32_putc,
	.flush = ffa_console_32_flush,
};

static void ffa_console_64_flush(struct serial_chip *chip)
{
	struct ffa_console_data *pd =
		container_of(chip, struct ffa_console_data, chip);
	struct thread_smc_args args = {
		.a0 = FFA_CONSOLE_LOG_64
	};

	copy_buf_to_args(&args, pd->buf, pd->pos, sizeof(uint64_t));
	thread_smccc(&args);
	pd->pos = 0;
}

static void ffa_console_64_putc(struct serial_chip *chip, int ch)
{
	struct ffa_console_data *pd =
		container_of(chip, struct ffa_console_data, chip);

	pd->buf[pd->pos++] = ch;

	if (pd->pos == FFA_CONSOLE_LOG_64_V1_1_MAX_MSG_LEN)
		ffa_console_64_flush(chip);
}

static const struct serial_ops ffa_console_64_ops = {
	.putc = ffa_console_64_putc,
	.flush = ffa_console_64_flush,
};

static bool ffa_feature_console_64bit(void)
{
	struct thread_smc_args args = {
		.a0 = FFA_FEATURES,
		.a1 = FFA_CONSOLE_LOG_64
	};

	thread_smccc(&args);

	return args.a0 == FFA_SUCCESS_64 || args.a0 == FFA_SUCCESS_32;
}

void ffa_console_init(void)
{
	if (ffa_feature_console_64bit())
		ffa_console.chip.ops = &ffa_console_64_ops;
	else
		ffa_console.chip.ops = &ffa_console_32_ops;

	ffa_console.pos = 0;

	register_serial_console(&ffa_console.chip);
}

#ifdef CFG_DT

static struct serial_chip *ffa_console_dev_alloc(void)
{
	return &ffa_console.chip;
}

static int ffa_console_dev_init(struct serial_chip *chip __unused,
				const void *fdt __unused, int offs __unused,
				const char *params __unused)
{
	return 0;
}

static void ffa_console_dev_free(struct serial_chip *chip __unused)
{
}

static const struct serial_driver ffa_console_driver = {
	.dev_alloc = ffa_console_dev_alloc,
	.dev_init = ffa_console_dev_init,
	.dev_free = ffa_console_dev_free,
};

static const struct dt_device_match ffa_console_match_table[] = {
	{ .compatible = "arm,ffa-console" },
	{ }
};

DEFINE_DT_DRIVER(ffa_console_dt_driver) = {
	.name = "ffa-console",
	.type = DT_DRIVER_UART,
	.match_table = ffa_console_match_table,
	.driver = &ffa_console_driver,
};

#endif /* CFG_DT */
