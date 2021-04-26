#include <kernel/thread.h>
#include <sm/sm.h>
#include <stdint.h>

#define PSCI_VERSION_0_2		U(0x00000002)
#define PSCI_VERSION_1_0		U(0x00010000)
#define PSCI_VERSION_1_1		U(0x00010001)
#define PSCI_VERSION			U(0x84000000)
#define PSCI_CPU_SUSPEND		U(0x84000001)
#define PSCI_CPU_OFF			U(0x84000002)
#define PSCI_CPU_ON			U(0x84000003)
#define PSCI_CPU_ON_SMC64		(PSCI_CPU_ON | U(0x40000000))
#define PSCI_AFFINITY_INFO		U(0x84000004)
#define PSCI_MIGRATE			U(0x84000005)
#define PSCI_MIGRATE_INFO_TYPE		U(0x84000006)
#define PSCI_MIGRATE_INFO_UP_CPU	U(0x84000007)
#define PSCI_SYSTEM_OFF			U(0x84000008)
#define PSCI_SYSTEM_RESET		U(0x84000009)
#define PSCI_PSCI_FEATURES		U(0x8400000a)
#define PSCI_CPU_FREEZE			U(0x8400000b)
#define PSCI_CPU_DEFAULT_SUSPEND	U(0x8400000c)
#define PSCI_NODE_HW_STATE		U(0x8400000d)
#define PSCI_SYSTEM_SUSPEND		U(0x8400000e)
#define PSCI_PSCI_SET_SUSPEND_MODE	U(0x8400000f)
#define PSCI_FN_STAT_RESIDENCY		U(0x84000010)
#define PSCI_FN_STAT_COUNT		U(0x84000011)
#define PSCI_SYSTEM_RESET2		U(0x84000012)
#define PSCI_MEM_PROTECT		U(0x84000013)
#define PSCI_MEM_PROTECT_CHECK_RANGE	U(0x84000014)

#define PSCI_NUM_CALLS			U(21)

#define PSCI_AFFINITY_LEVEL_ON		U(0)
#define PSCI_AFFINITY_LEVEL_OFF		U(1)
#define PSCI_AFFINITY_LEVEL_ON_PENDING	U(2)

#define PSCI_POWER_STATE_ID_MASK	U(0xffff)
#define PSCI_POWER_STATE_ID_SHIFT	U(0)
#define PSCI_POWER_STATE_TYPE_SHIFT	U(16)
#define PSCI_POWER_STATE_TYPE_MASK	BIT32(PSCI_POWER_STATE_TYPE_SHIFT)
#define PSCI_POWER_STATE_AFFL_SHIFT	U(24)
#define PSCI_POWER_STATE_AFFL_MASK	SHIFT_U32(0x3, \
						  PSCI_POWER_STATE_AFFL_SHIFT)

#define PSCI_POWER_STATE_TYPE_STANDBY		U(0)
#define PSCI_POWER_STATE_TYPE_POWER_DOWN	U(1)

#define PSCI_RET_SUCCESS		(0)
#define PSCI_RET_NOT_SUPPORTED		(-1)
#define PSCI_RET_INVALID_PARAMETERS	(-2)
#define PSCI_RET_DENIED			(-3)
#define PSCI_RET_ALREADY_ON		(-4)
#define PSCI_RET_ON_PENDING		(-5)
#define PSCI_RET_INTERNAL_FAILURE	(-6)
#define PSCI_RET_NOT_PRESENT		(-7)
#define PSCI_RET_DISABLED		(-8)
#define PSCI_RET_INVALID_ADDRESS	(-9)

uint32_t psci_version(void);
int psci_cpu_suspend(uint32_t power_state, uintptr_t entry,
		     uint32_t context_id, struct sm_nsec_ctx *nsec);
int psci_cpu_off(void);
int psci_cpu_on(uint32_t cpu_id, uint32_t entry, uint32_t context_id);
int psci_affinity_info(uint32_t affinity, uint32_t lowest_affnity_level);
int psci_migrate(uint32_t cpu_id);
int psci_migrate_info_type(void);
int psci_migrate_info_up_cpu(void);
void psci_system_off(void);
void psci_system_reset(void);
int psci_features(uint32_t psci_fid);
int psci_system_reset2(uint32_t reset_type, uint32_t cookie);
int psci_mem_protect(uint32_t enable);
int psci_mem_chk_range(paddr_t base, size_t length);
int psci_node_hw_state(uint32_t cpu_id, uint32_t power_level);
int psci_system_suspend(uintptr_t entry, uint32_t context_id,
			struct sm_nsec_ctx *nsec);
int psci_stat_residency(uint32_t cpu_id, uint32_t power_state);
int psci_stat_count(uint32_t cpu_id, uint32_t power_state);
void tee_psci_handler(struct thread_smc_args *args, struct sm_nsec_ctx *nsec);

void psci_armv7_cpu_off(void);
