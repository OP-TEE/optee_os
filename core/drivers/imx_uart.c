// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 * Copyright 2018 NXP.
 *
 */

#include <assert.h>
#include <drivers/driver.h>
#include <drivers/imx_uart.h>
#include <io.h>
#include <keep.h>
#include <util.h>
#include <kernel/dt.h>

/* Register definitions */
#define URXD  0x0  /* Receiver Register */
#define UTXD  0x40 /* Transmitter Register */
#define UCR1  0x80 /* Control Register 1 */
#define UCR2  0x84 /* Control Register 2 */
#define UCR3  0x88 /* Control Register 3 */
#define UCR4  0x8c /* Control Register 4 */
#define UFCR  0x90 /* FIFO Control Register */
#define USR1  0x94 /* Status Register 1 */
#define USR2  0x98 /* Status Register 2 */
#define UESC  0x9c /* Escape Character Register */
#define UTIM  0xa0 /* Escape Timer Register */
#define UBIR  0xa4 /* BRM Incremental Register */
#define UBMR  0xa8 /* BRM Modulator Register */
#define UBRC  0xac /* Baud Rate Count Register */
#define UTS   0xb4 /* UART Test Register (mx31) */


/* UART Control Register Bit Fields.*/
#define  URXD_CHARRDY    (1<<15)
#define  URXD_ERR        (1<<14)
#define  URXD_OVRRUN     (1<<13)
#define  URXD_FRMERR     (1<<12)
#define  URXD_BRK        (1<<11)
#define  URXD_PRERR      (1<<10)
#define  URXD_RX_DATA    (0xFF)
#define  UCR1_ADEN       (1<<15) /* Auto dectect interrupt */
#define  UCR1_ADBR       (1<<14) /* Auto detect baud rate */
#define  UCR1_TRDYEN     (1<<13) /* Transmitter ready interrupt enable */
#define  UCR1_IDEN       (1<<12) /* Idle condition interrupt */
#define  UCR1_RRDYEN     (1<<9)	 /* Recv ready interrupt enable */
#define  UCR1_RDMAEN     (1<<8)	 /* Recv ready DMA enable */
#define  UCR1_IREN       (1<<7)	 /* Infrared interface enable */
#define  UCR1_TXMPTYEN   (1<<6)	 /* Transimitter empty interrupt enable */
#define  UCR1_RTSDEN     (1<<5)	 /* RTS delta interrupt enable */
#define  UCR1_SNDBRK     (1<<4)	 /* Send break */
#define  UCR1_TDMAEN     (1<<3)	 /* Transmitter ready DMA enable */
#define  UCR1_UARTCLKEN  (1<<2)	 /* UART clock enabled */
#define  UCR1_DOZE       (1<<1)	 /* Doze */
#define  UCR1_UARTEN     (1<<0)	 /* UART enabled */

#define  UTS_FRCPERR	 (1<<13) /* Force parity error */
#define  UTS_LOOP        (1<<12) /* Loop tx and rx */
#define  UTS_TXEMPTY	 (1<<6)	 /* TxFIFO empty */
#define  UTS_RXEMPTY	 (1<<5)	 /* RxFIFO empty */
#define  UTS_TXFULL	 (1<<4)	 /* TxFIFO full */
#define  UTS_RXFULL	 (1<<3)	 /* RxFIFO full */
#define  UTS_SOFTRST	 (1<<0)	 /* Software reset */

/*
 * UART data for power transition
 */
static struct uart_data {
	struct serial_chip *chip;
	bool               enabled;
} uart_data;

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct imx_uart_data *pd =
		container_of(chip, struct imx_uart_data, chip);

	return io_pa_or_va(&pd->base);
}

static void imx_uart_flush(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	if (uart_data.enabled)
		while (!(read32(base + UTS) & UTS_TXEMPTY))
			;
}

static int imx_uart_getchar(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	if (uart_data.enabled) {
		while (read32(base + UTS) & UTS_RXEMPTY)
			;

		return (read32(base + URXD) & URXD_RX_DATA);
	}

	return 0;
}

static void imx_uart_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = chip_to_base(chip);

	if (uart_data.enabled) {
		write32(ch, base + UTXD);

		/* Wait until sent */
		while (!(read32(base + UTS) & UTS_TXEMPTY))
			;
	}
}

static const struct serial_ops imx_uart_ops = {
	.flush = imx_uart_flush,
	.getchar = imx_uart_getchar,
	.putc = imx_uart_putc,
};
KEEP_PAGER(imx_uart_ops);

void imx_uart_init(struct imx_uart_data *pd, paddr_t pbase)
{
	pd->base.pa = pbase;
	pd->base.va = 0;
	pd->chip.ops = &imx_uart_ops;

	/*
	 * Do nothing, debug uart(uart0) share with normal world,
	 * everything for uart0 initialization is done in bootloader.
	 */

	/* Keep the uart data information for the power transition */
	uart_data.chip    = &pd->chip;
	uart_data.enabled = true;
}

#ifdef CFG_DT

static struct serial_chip *imx_uart_dev_alloc(void)
{
	struct imx_uart_data *pd = malloc(sizeof(*pd));

	if (!pd)
		return NULL;
	return &pd->chip;
}

static int imx_uart_dev_init(struct serial_chip *chip,
			       const void *fdt,
			       int offs,
			       const char *parms)
{
	struct imx_uart_data *pd =
		container_of(chip, struct imx_uart_data, chip);
	vaddr_t vbase;
	paddr_t pbase;
	size_t size;

	if (parms && parms[0])
		IMSG("imx_uart: device parameters ignored (%s)", parms);

	if (dt_map_dev(fdt, offs, &vbase, &size) < 0)
		return -1;
	pbase = virt_to_phys((void *)vbase);
	imx_uart_init(pd, pbase);

	return 0;
}

static void imx_uart_dev_free(struct serial_chip *chip)
{
	struct imx_uart_data *pd =
	  container_of(chip,  struct imx_uart_data, chip);

	free(pd);
}

static const struct serial_driver imx_uart_driver = {
	.dev_alloc = imx_uart_dev_alloc,
	.dev_init = imx_uart_dev_init,
	.dev_free = imx_uart_dev_free,
};

static const struct dt_device_match imx_match_table[] = {
	{ .compatible = "fsl,imx6q-uart" },
	{ 0 }
};

const struct dt_driver imx_dt_driver __dt_driver = {
	.name = "imx_uart",
	.match_table = imx_match_table,
	.driver = &imx_uart_driver,
};


#endif /* CFG_DT */


static TEE_Result init(void)
{
	DMSG("UART driver initialization");
	return TEE_SUCCESS;
}

/*
 * brief   UART Power state preparation/entry
 *
 * inputs:
 * mode    Power mode to reach
 * wait    wait until power state is ready
 *
 * return
 * TEE_SUCCESS       Success
 */
static TEE_Result pm_enter(enum drv_pwrmode mode, bool wait)
{
	vaddr_t base = chip_to_base(uart_data.chip);

	DMSG("UART power mode [%d] entry (wait %s)",
			mode, (wait) ? "true" : "false");

	if (mode == STATE_SUSPEND) {
		if (wait) {
			/* Flush UART */
			imx_uart_flush(uart_data.chip);
		}

		/* Disable UART clocks */
		io_mask32(base + UCR1, 0, UCR1_UARTEN);
		uart_data.enabled = false;
	}

	return TEE_SUCCESS;
}

/*
 * brief   UART Power state resume
 *
 * input:
 * mode    Power mode to resume from
 *
 */
static void pm_resume(enum drv_pwrmode mode)
{
	vaddr_t base = chip_to_base(uart_data.chip);

	DMSG("CAAM power mode [%d] resume", mode);
	if (mode == STATE_SUSPEND) {
		/* Re-enable UART clocks */
		io_mask32(base + UCR1, 1, UCR1_UARTEN);
		uart_data.enabled = true;
	}
}

/*
 * UART driver power operations
 */
const struct driver_ops uart_ops = {
	.init      = init,
	.pm_enter  = pm_enter,
	.pm_resume = pm_resume,
};

/* Register the UART driver in the system */
REGISTER_DRIVER(uart, &uart_ops);

