# WARNS from undefined, 1, 2 and 3. 3 means we have the most warning messages
WARNS ?= 3

# Define NOWERROR=1 so that warnings are not treated as errors 
# NOWERROR=1

# Define DEBUG=1 to compile with -g option
# DEBUG=1

# CFG_TEE_FW_DEBUG
#   If 1, debug mode of the tee firmware (CPU restart, Core Status)
CFG_TEE_FW_DEBUG?=0

# CFG_TEE_CORE_LOG_LEVEL
#   Max level of the tee core traces. 0 means disable, 4 is max.
#   Supported values: 0 (no traces) to 4 (all traces)
#   If CFG_TEE_DRV_DEBUGFS is set, the level of traces to print can be
#   dynamically changes via debugfs in the range 1 => CFG_TEE_CORE_LOG_LEVEL
CFG_TEE_CORE_LOG_LEVEL?=1

# CFG_TEE_TA_LOG_LEVEL
#   TA and TEECore log level
#   Supported values: 0 (no traces) to 4 (all traces)
#   If CFG_TEE_DRV_DEBUGFS is set, the level of traces to print can be
#   dynamically changes via debugfs in the range 1 => CFG_TEE_TA_LOG_LEVEL
CFG_TEE_TA_LOG_LEVEL?=1


#   If 1, enable debug features of the user mem module. This module track memory
#   allocation of the user ta.
#   Debug features include check of buffer overflow, statistics,
#   marck/check heap feature
#   Enabling this could decrease efficiency
CFG_TEE_CORE_USER_MEM_DEBUG?=1

# CFG_TEE_TRACE_PERFORMANCE
#   If 'y', TEECore will print CNTVCT (virtual counter) register values to console
#   after receiving SMC call and before returning to normal world
CFG_TEE_TRACE_PERFORMANCE?=n
