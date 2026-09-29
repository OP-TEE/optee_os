// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Arm Limited.
 */

#include <arm64.h>
#include <ffa.h>
#include <initcall.h>
#include <inttypes.h>
#include <kernel/thread_spmc.h>
#include <sm/optee_smc.h>
#include <trace.h>
#include <util.h>

#define CORE_RAM_ERR_RECORD	    U(1)
#define ERXPFGCDN_CDN		    U(0xF)

/* Predefined ERXMISC0 value for CE (correctable error) injection */
#define ERX_MISC0_CE_INJ	    0x200810000000001ULL

/* Supported RAS components */
#define RAS_COMPONENT_CPU	    U(0x01)

/*
 * ACPI EINJ error types are encoded as a bitmap.
 * Firmware-communication and deferred-error are local extensions.
 */
#define RAS_ERROR_PROCESSOR_CORRECTABLE			    BIT32(0)
#define RAS_ERROR_PROCESSOR_UNCORRECTABLE_NONFATAL	BIT32(1)
#define RAS_ERROR_PROCESSOR_UNCORRECTABLE_FATAL		BIT32(2)
#define RAS_ERROR_MEMORY_CORRECTABLE			    BIT32(3)
#define RAS_ERROR_MEMORY_UNCORRECTABLE_NONFATAL		BIT32(4)
#define RAS_ERROR_MEMORY_UNCORRECTABLE_FATAL		BIT32(5)
#define RAS_ERROR_PCI_CORRECTABLE			        BIT32(6)
#define RAS_ERROR_PCI_UNCORRECTABLE_NONFATAL		BIT32(7)
#define RAS_ERROR_PCI_UNCORRECTABLE_FATAL		    BIT32(8)
#define RAS_ERROR_PLATFORM_CORRECTABLE			    BIT32(9)
#define RAS_ERROR_PLATFORM_UNCORRECTABLE_NONFATAL	BIT32(10)
#define RAS_ERROR_PLATFORM_UNCORRECTABLE_FATAL		BIT32(11)
#define RAS_ERROR_VENDOR_DEFINED_START			    BIT32(31)

/*
 * Program a CPU RAS error record for later error injection.
 *
 * This is an internal direct request ABI used by SP clients of the RAS LSP.
 *
 * error_type selects the processor error class to arm.
 * The current supported values are:
 * - RAS_ERROR_PROCESSOR_CORRECTABLE
 * - RAS_ERROR_PROCESSOR_UNCORRECTABLE_NONFATAL
 * - RAS_ERROR_PROCESSOR_UNCORRECTABLE_FATAL
 *
 * component selects the target component.
 * Only RAS_COMPONENT_CPU is currently supported.
 *
 * data is currently unused.
 *
 * The handler selects the Core RAM error record and programs the associated
 * RAS Error Record and PFG registers for the requested injection type.
 * The direct response reports only whether this programming step succeeded.
 *
 * The actual error is expected to be observed later, when the programmed
 * condition is triggered and the CPU reports it through
 * the RAS handling path. This handler does not consume that exception
 * and does not return it synchronously to the caller.
 */
static TEE_Result ras_injection_handler(uint32_t error_type, uint32_t component,
					uint32_t data __unused)
{
	TEE_Result ret = TEE_ERROR_NOT_SUPPORTED;
	uint64_t erx_status;
	uint64_t v = 0;

	FMSG("RAS LSP: error_type: %"PRIx32" component: %"PRIx32
	     " data: %"PRIx32, error_type, component, data);

	if (component != RAS_COMPONENT_CPU)
		return TEE_ERROR_NOT_SUPPORTED;

	/* Select error record 1, which contains Core RAM errors. */
	write_errselr_el1(CORE_RAM_ERR_RECORD);
	write_erxpfgctl_el1(0);

	/* Clear any sticky status bits in the selected error record. */
	erx_status = read_erxstatus_el1();
	write_erxstatus_el1(erx_status);
	write_erxpfgcdn_el1(ERXPFGCDN_CDN);

	switch (error_type) {
	case RAS_ERROR_PROCESSOR_CORRECTABLE:
		v = read_erxmisc0_el1();
		write_erxmisc0_el1(v | ERX_MISC0_CE_INJ);
		v = read_erxpfgctl_el1();
		v |= ERXPFGCTL_CDNEN_BIT | ERXPFGCTL_R_BIT |
		     ERXPFGCTL_CE_BIT;
		write_erxpfgctl_el1(v);
		return TEE_SUCCESS;
	case RAS_ERROR_PROCESSOR_UNCORRECTABLE_NONFATAL:
		v = read_erxpfgctl_el1();
		v |= ERXPFGCTL_CDNEN_BIT | ERXPFGCTL_DE_BIT;
		write_erxpfgctl_el1(v);
		return TEE_SUCCESS;
	case RAS_ERROR_PROCESSOR_UNCORRECTABLE_FATAL:
		v = read_erxpfgctl_el1();
		v |= ERXPFGCTL_CDNEN_BIT | ERXPFGCTL_UC_BIT;
		write_erxpfgctl_el1(v);
		return TEE_SUCCESS;
	default:
		EMSG("RAS LSP: Unsupported error type: 0x%"PRIx32,
		     error_type);
	}

	return ret;
}

static void ras_direct_req_handler(struct thread_smc_1_2_regs *args,
				   struct sp_session *caller_sp __unused)
{
	TEE_Result ret = TEE_ERROR_NOT_SUPPORTED;
	uint32_t error_type = args->a5;
	uint32_t component = args->a6;
	uint32_t data = args->a7;

	ret = ras_injection_handler(error_type, component, data);

	if (OPTEE_SMC_IS_64(args->a0))
		args->a0 = FFA_MSG_SEND_DIRECT_RESP_64;
	else
		args->a0 = FFA_MSG_SEND_DIRECT_RESP_32;

	args->a2 = FFA_DST(args->a1);
	args->a3 = ret;
}

static struct spmc_lsp_desc ras_lsp __nex_data = {
	.name = "ras_lsp",
	.direct_req = ras_direct_req_handler,
	.properties = FFA_PART_PROP_DIRECT_REQ_RECV |
		      FFA_PART_PROP_DIRECT_REQ_SEND,
	.uuid_words = { 0x7011a688, 0x4dde4053, 0xa5a97bac, 0xf13b8cd4 },
};

static TEE_Result ras_lsp_init(void)
{
	uint64_t pfr0 = read_id_aa64pfr0_el1();

	/* Register the LSP only when the CPU advertises architectural RAS. */
	if (!((pfr0 >> ID_AA64PFR0_EL1_RAS_SHIFT) &
	      ID_AA64PFR0_EL1_RAS_MASK))
		return TEE_ERROR_NOT_SUPPORTED;

	return spmc_register_lsp(&ras_lsp);
}

nex_service_init_late(ras_lsp_init);
