// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <drivers/tpm2_mmio.h>
#include <drivers/tpm2_ptp_fifo.h>
#include <io.h>
#include <kernel/dt.h>
#include <trace.h>

static vaddr_t tpm2_mmio_base;

static enum tpm2_result tpm2_mmio_rx32(struct tpm2_chip *chip __unused,
				       uint32_t adr, uint32_t *buf)
{
	*buf = io_read32(tpm2_mmio_base + adr);

	return TPM2_OK;
}

static enum tpm2_result tpm2_mmio_tx32(struct tpm2_chip *chip __unused,
				       uint32_t adr, uint32_t val)
{
	io_write32(tpm2_mmio_base + adr, val);

	return TPM2_OK;
}

static enum tpm2_result tpm2_mmio_rx8(struct tpm2_chip *chip __unused,
				      uint32_t adr, uint16_t len, uint8_t *buf)
{
	unsigned int n = 0;

	for (n = 0; n < len; n++)
		buf[n] = io_read8(tpm2_mmio_base + adr);

	return TPM2_OK;
}

static enum tpm2_result tpm2_mmio_tx8(struct tpm2_chip *chip __unused,
				      uint32_t adr, uint16_t len, uint8_t *buf)
{
	while (len--)
		io_write8(tpm2_mmio_base + adr, *buf++);

	return TPM2_OK;
}

static const struct tpm2_ptp_phy_ops tpm2_mmio_ops = {
	.rx32 = tpm2_mmio_rx32,
	.tx32 = tpm2_mmio_tx32,
	.rx8 = tpm2_mmio_rx8,
	.tx8 = tpm2_mmio_tx8,
};

static const struct tpm2_ptp_ops tpm2_fifo_ops = {
	.init = tpm2_fifo_init,
	.end = tpm2_fifo_end,
	.send = tpm2_fifo_send,
	.recv = tpm2_fifo_recv,
};

static struct tpm2_chip tpm2_mmio_chip = {
	.phy_ops = &tpm2_mmio_ops,
	.ops = &tpm2_fifo_ops,
};

enum tpm2_result tpm2_mmio_init(paddr_t pbase)
{
	enum tpm2_result ret = TPM2_OK;
	struct io_pa_va base = { };

	base.pa = pbase;

	tpm2_mmio_base = io_pa_or_va_secure(&base, TPM2_REG_SIZE);
	assert(tpm2_mmio_base);

	DMSG("TPM2 MMIO pbase: 0x%" PRIxPA, base.pa);
	DMSG("TPM2 MMIO vbase: 0x%" PRIxVA, base.va);

	ret = tpm2_chip_register(&tpm2_mmio_chip);
	if (ret) {
		EMSG("Init failed");
		return ret;
	}

	return TPM2_OK;
}
