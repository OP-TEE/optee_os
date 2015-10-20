/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <platform_config.h>

#include <stdint.h>
#include <string.h>

#include <drivers/gic.h>
#include <drivers/pl011.h>

#include <arm.h>
#include <kernel/generic_boot.h>
#include <kernel/pm_stubs.h>
#include <trace.h>
#include <kernel/misc.h>
#include <kernel/tee_time.h>
#include <mm/tee_pager.h>
#include <tee/entry.h>
#include <tee/arch_svc.h>
#include <console.h>

#ifdef CFG_PLATFORM_SPECIFIC_PROPERTIES
#include <tee/tee_svc.h>
#include <platform_properties.h>
#include <kernel/tee_ta_manager_unpg.h>
#include <kernel/tee_common_otp.h>
#include <tee/tee_cryp_utl.h>
#endif

static void main_fiq(void);

static const struct thread_handlers handlers = {
	.std_smc = tee_entry,
	.fast_smc = tee_entry,
	.fiq = main_fiq,
	.svc = tee_svc_handler,
	.abort = tee_pager_abort_handler,
#if defined(CFG_WITH_ARM_TRUSTED_FW)
	.cpu_on = cpu_on_handler,
	.cpu_off = pm_do_nothing,
	.cpu_suspend = pm_do_nothing,
	.cpu_resume = pm_do_nothing,
	.system_off = pm_do_nothing,
	.system_reset = pm_do_nothing,
#else
	.cpu_on = pm_panic,
	.cpu_off = pm_panic,
	.cpu_suspend = pm_panic,
	.cpu_resume = pm_panic,
	.system_off = pm_panic,
	.system_reset = pm_panic,
#endif
};

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

#if PLATFORM_FLAVOR_IS(fvp) || PLATFORM_FLAVOR_IS(juno)
void main_init_gic(void)
{
	/*
	 * On ARMv8, GIC configuration is initialized in ARM-TF,
	 */
	gic_init_base_addr(GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
	gic_it_add(IT_CONSOLE_UART);
	/* Route FIQ to primary CPU */
	gic_it_set_cpu_mask(IT_CONSOLE_UART, gic_it_get_target(0));
	gic_it_set_prio(IT_CONSOLE_UART, 0x1);
	gic_it_enable(IT_CONSOLE_UART);

}
#elif PLATFORM_FLAVOR_IS(qemu)
void main_init_gic(void)
{
	/* Initialize GIC */
	gic_init(GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
	gic_it_add(IT_CONSOLE_UART);
	gic_it_set_cpu_mask(IT_CONSOLE_UART, 0x1);
	gic_it_set_prio(IT_CONSOLE_UART, 0xff);
	gic_it_enable(IT_CONSOLE_UART);
}
#elif PLATFORM_FLAVOR_IS(qemu_virt)
void main_init_gic(void)
{
	/* Initialize GIC */
	gic_init(GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
}
#endif

static void main_fiq(void)
{
	uint32_t iar;

	DMSG("enter");

	iar = gic_read_iar();

	while (pl011_have_rx_data(CONSOLE_UART_BASE)) {
		DMSG("cpu %zu: got 0x%x",
		     get_core_pos(), pl011_getchar(CONSOLE_UART_BASE));
	}

	gic_write_eoir(iar);

	DMSG("return");
}

void console_init(void)
{
	pl011_init(CONSOLE_UART_BASE,
		   CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_BAUDRATE);
}

void console_putc(int ch)
{
	pl011_putc(ch, CONSOLE_UART_BASE);
	if (ch == '\n')
		pl011_putc('\r', CONSOLE_UART_BASE);
}

void console_flush(void)
{
	pl011_flush(CONSOLE_UART_BASE);
}

#ifdef CFG_PLATFORM_SPECIFIC_PROPERTIES
TEE_Result tee_svc_sys_get_property_platform(uint32_t prop,
					     tee_uaddr_t buf, size_t blen,
					     struct tee_ta_session *sess)
{
	static const size_t ta_endorsement_seed_size = 32;
	TEE_Result res;

	switch (prop) {
	case UTEE_PROP_TA_ENDORSEMENT_SEED:
		{
			/*
			 * The data to hash is 48 bytes made up of:
			 * - 16 bytes: the UUID of the calling TA.
			 * - 32 bytes: the hardware device ID
			 * The resulting endorsement seed is 32 bytes.
			 *
			 * The output buffer is the "binary" struct defined in
			 * the "prop_value" union and therefore comprises:
			 * -  4 bytes: the size of the binary value data (32)
			 * - 32 bytes: the binary value data (endorsement seed)
			 *
			 * Note that this code assumes an endoresement seed
			 * size == device ID size for convenience.
			 */
			uint8_t data[sizeof(TEE_UUID)
				+ ta_endorsement_seed_size];

			size_t bin[1
				+ ta_endorsement_seed_size / sizeof(size_t)];

			size_t *bin_len = (size_t *)(vaddr_t)(bin);
			uint8_t *bin_val = (uint8_t *)(&bin[1]);

			if (blen < sizeof(bin))
				return TEE_ERROR_SHORT_BUFFER;

			memcpy(&data[0], &sess->ctx->head->uuid,
				sizeof(TEE_UUID));

			if (tee_otp_get_die_id(&data[sizeof(TEE_UUID)],
					       ta_endorsement_seed_size))
				return TEE_ERROR_BAD_STATE;

			res = tee_hash_createdigest(TEE_ALG_SHA256, data,
					sizeof(data),
					bin_val,
					ta_endorsement_seed_size);
			if (res != TEE_SUCCESS)
				return TEE_ERROR_BAD_STATE;

			*bin_len = ta_endorsement_seed_size;

			return tee_svc_copy_to_user(sess, (void *)buf, bin,
					sizeof(bin));
		}
		break;

	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}
#endif
