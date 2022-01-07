// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 *
 */

#include <drivers/tpm2_mmio.h>
#include <io.h>
#include <trace.h>

static vaddr_t tpm2_chip_to_base(struct tpm2_chip *chip)
{
	struct tpm2_mmio_data *md =
		container_of(chip, struct tpm2_mmio_data, chip);

	return md->base.va;
}

static enum tpm2_result tpm2_mmio_rx32(struct tpm2_chip *chip, uint32_t adr,
				       uint32_t *buf)
{
	vaddr_t base = tpm2_chip_to_base(chip);

	*buf = io_read32(base + adr);

	return TPM2_OK;
}

static enum tpm2_result tpm2_mmio_tx32(struct tpm2_chip *chip, uint32_t adr,
				       uint32_t val)
{
	vaddr_t base = tpm2_chip_to_base(chip);

	io_write32(base + adr, val);

	return TPM2_OK;
}

static enum tpm2_result tpm2_mmio_rx8(struct tpm2_chip *chip, uint32_t adr,
				      uint16_t len, uint8_t *buf)
{
	vaddr_t base = tpm2_chip_to_base(chip);

	while (len--)
		*buf++ = io_read8(base + adr);

	return TPM2_OK;
}

static enum tpm2_result tpm2_mmio_tx8(struct tpm2_chip *chip, uint32_t adr,
				      uint16_t len, uint8_t *buf)
{
	vaddr_t base = tpm2_chip_to_base(chip);

	while (len--)
		io_write8(base + adr, *buf++);

	return TPM2_OK;
}

static struct tpm2_ops tpm2_mmio_ops = {
	.rx32 = tpm2_mmio_rx32,
	.tx32 = tpm2_mmio_tx32,
	.rx8 = tpm2_mmio_rx8,
	.tx8 = tpm2_mmio_tx8,
};
DECLARE_KEEP_PAGER(tpm2_mmio_ops);

enum tpm2_result tpm2_mmio_init(struct tpm2_mmio_data *md, paddr_t pbase)
{
	md->base.pa = pbase;
	md->chip.ops = &tpm2_mmio_ops;

	md->base.va = io_pa_or_va(&md->base, TPM2_REG_SIZE);
	DMSG("TPM2 MMIO pbase: 0x%" PRIxVA, md->base.pa);
	DMSG("TPM2 MMIO vbase: 0x%" PRIxVA, md->base.va);

	if (tpm2_init(&md->chip)) {
		EMSG("Init failed");
		return TPM2_ERR_INIT;
	}

	if (tpm2_open(&md->chip)) {
		EMSG("Open failed");
		return TPM2_ERR_INIT;
	}

	DMSG("Init and open ok");
	return TPM2_OK;
}

