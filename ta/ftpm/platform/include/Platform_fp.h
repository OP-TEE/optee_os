/* Microsoft Reference Implementation for TPM 2.0
 *
 *  The copyright in this software is being made available under the BSD License,
 *  included below. This software may be subject to other third party and
 *  contributor rights, including patent rights, and no such rights are granted
 *  under this license.
 *
 *  Copyright (c) Microsoft Corporation
 *
 *  All rights reserved.
 *
 *  BSD License
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS IS""
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Aug  7, 2018  Time: 03:39:35PM
 */

#ifndef    _PLATFORM_FP_H_
#define    _PLATFORM_FP_H_

//** From EPS.c

LIB_EXPORT void
_plat__GetEPS(UINT16 Size, uint8_t *EndorsementSeed);

//** From Cancel.c

//***_plat__IsCanceled()
// Check if the cancel flag is set
// return type: BOOL
//      TRUE(1)      if cancel flag is set
//      FALSE(0)     if cancel flag is not set
LIB_EXPORT int
_plat__IsCanceled(
    void
    );

// Set cancel flag.
LIB_EXPORT void
_plat__SetCancel(
    void
    );

//***_plat__ClearCancel()
// Clear cancel flag
LIB_EXPORT void
_plat__ClearCancel(
    void
    );


//** From Clock.c

//***_plat__TimerReset()
// This function sets current system clock time as t0 for counting TPM time.
// This function is called at a power on event to reset the clock. When the clock
// is reset, the indication that the clock was stopped is also set.
LIB_EXPORT void
_plat__TimerReset(
    void
    );

//*** _plat__TimerRestart()
// This function should be called in order to simulate the restart of the timer
// should it be stopped while power is still applied.
LIB_EXPORT void
_plat__TimerRestart(
    void
    );

//*** _plat__RealTime()
// This is another, probably futile, attempt to define a portable function
// that will return a 64-bit clock value that has mSec resolution.
uint64_t
_plat__RealTime(
    void
);

//***_plat__TimerRead()
// This function provides access to the tick timer of the platform. The TPM code
// uses this value to drive the TPM Clock.
//
// The tick timer is supposed to run when power is applied to the device. This timer
// should not be reset by time events including _TPM_Init. It should only be reset
// when TPM power is re-applied.
//
// If the TPM is run in a protected environment, that environment may provide the
// tick time to the TPM as long as the time provided by the environment is not
// allowed to go backwards. If the time provided by the system can go backwards
// during a power discontinuity, then the _plat__Signal_PowerOn should call
// _plat__TimerReset().
LIB_EXPORT uint64_t
_plat__TimerRead(
    void
    );

//*** _plat__TimerWasReset()
// This function is used to interrogate the flag indicating if the tick timer has
// been reset.
//
// If the resetFlag parameter is SET, then the flag will be CLEAR before the
// function returns.
LIB_EXPORT BOOL
_plat__TimerWasReset(
   void
    );

//*** _plat__TimerWasStopped()
// This function is used to interrogate the flag indicating if the tick timer has
// been stopped. If so, this is typically a reason to roll the nonce.
//
// This function will CLEAR the s_timerStopped flag before returning. This provides
// functionality that is similar to status register that is cleared when read. This
// is the model used here because it is the one that has the most impact on the TPM
// code as the flag can only be accessed by one entity in the TPM. Any other
// implementation of the hardware can be made to look like a read-once register.
LIB_EXPORT BOOL
_plat__TimerWasStopped(
    void
    );

//***_plat__ClockAdjustRate()
// Adjust the clock rate
LIB_EXPORT void
_plat__ClockAdjustRate(
    int              adjust         // IN: the adjust number.  It could be positive
                                    //     or negative
    );


//** From Entropy.c

//** _plat__GetEntropy()
// This function is used to get available hardware entropy. In a hardware
// implementation of this function, there would be no call to the system
// to get entropy.
// return type: int32_t
//  < 0        hardware failure of the entropy generator, this is sticky
// >= 0        the returned amount of entropy (bytes)
//
LIB_EXPORT int32_t
_plat__GetEntropy(
    unsigned char       *entropy,           // output buffer
    uint32_t             amount             // amount requested
    );


//** From LocalityPlat.c

//***_plat__LocalityGet()
// Get the most recent command locality in locality value form.
// This is an integer value for locality and not a locality structure
// The locality can be 0-4 or 32-255. 5-31 is not allowed.
LIB_EXPORT unsigned char
_plat__LocalityGet(
    void
    );

//***_plat__LocalitySet()
// Set the most recent command locality in locality value form
LIB_EXPORT void
_plat__LocalitySet(
    unsigned char    locality
    );


//** From NVMem.c

//*** _plat__NvErrors()
// This function is used by the simulator to set the error flags in the NV
// subsystem to simulate an error in the NV loading process
LIB_EXPORT void
_plat__NvErrors(
    int              recoverable,
    int              unrecoverable
    );

//***_plat__NVEnable()
// Enable NV memory.
//
// This version just pulls in data from a file. In a real TPM, with NV on chip,
// this function would verify the integrity of the saved context. If the NV
// memory was not on chip but was in something like RPMB, the NV state would be
// read in, decrypted and integrity checked.
//
// The recovery from an integrity failure depends on where the error occurred. It
// it was in the state that is discarded by TPM Reset, then the error is
// recoverable if the TPM is reset. Otherwise, the TPM must go into failure mode.
// return type: int
//      0           if success
//      > 0         if receive recoverable error
//      <0          if unrecoverable error
LIB_EXPORT int
_plat__NVEnable(
    void            *platParameter  // IN: platform specific parameters
    );

//***_plat__NVDisable()
// Disable NV memory
LIB_EXPORT void
_plat__NVDisable(
    void
    );

//***_plat__IsNvAvailable()
// Check if NV is available
// return type: int
//      0               NV is available
//      1               NV is not available due to write failure
//      2               NV is not available due to rate limit
LIB_EXPORT int
_plat__IsNvAvailable(
    void
    );

//***_plat__NvMemoryRead()
// Function: Read a chunk of NV memory
LIB_EXPORT void
_plat__NvMemoryRead(
    unsigned int     startOffset,   // IN: read start
    unsigned int     size,          // IN: size of bytes to read
    void            *data           // OUT: data buffer
    );

//*** _plat__NvIsDifferent()
// This function checks to see if the NV is different from the test value. This is
// so that NV will not be written if it has not changed.
// return value: int
//  TRUE(1)    the NV location is different from the test value
//  FALSE(0)   the NV location is the same as the test value
LIB_EXPORT int
_plat__NvIsDifferent(
    unsigned int     startOffset,   // IN: read start
    unsigned int     size,          // IN: size of bytes to read
    void            *data           // IN: data buffer
    );

//***_plat__NvMemoryWrite()
// This function is used to update NV memory. The "write" is to a memory copy of
// NV. At the end of the current command, any changes are written to
// the actual NV memory.
// NOTE: A useful optimization would be for this code to compare the current
// contents of NV with the local copy and note the blocks that have changed. Then
// only write those blocks when _plat__NvCommit() is called.
LIB_EXPORT int
_plat__NvMemoryWrite(
    unsigned int     startOffset,   // IN: write start
    unsigned int     size,          // IN: size of bytes to write
    void            *data           // OUT: data buffer
    );

//***_plat__NvMemoryClear()
// Function is used to set a range of NV memory bytes to an implementation-dependent
// value. The value represents the erase state of the memory.
LIB_EXPORT void
_plat__NvMemoryClear(
    unsigned int     start,         // IN: clear start
    unsigned int     size           // IN: number of bytes to clear
    );

//***_plat__NvMemoryMove()
// Function: Move a chunk of NV memory from source to destination
//      This function should ensure that if there overlap, the original data is
//      copied before it is written
LIB_EXPORT void
_plat__NvMemoryMove(
    unsigned int     sourceOffset,  // IN: source offset
    unsigned int     destOffset,    // IN: destination offset
    unsigned int     size           // IN: size of data being moved
    );

//***_plat__NvCommit()
// This function writes the local copy of NV to NV for permanent store. It will write
// NV_MEMORY_SIZE bytes to NV. If a file is use, the entire file is written.
// return type: int
//  0       NV write success
//  non-0   NV write fail
LIB_EXPORT int
_plat__NvCommit(
    void
    );

//***_plat__SetNvAvail()
// Set the current NV state to available.  This function is for testing purpose
// only.  It is not part of the platform NV logic
LIB_EXPORT void
_plat__SetNvAvail(
    void
    );

//***_plat__ClearNvAvail()
// Set the current NV state to unavailable.  This function is for testing purpose
// only.  It is not part of the platform NV logic
LIB_EXPORT void
_plat__ClearNvAvail(
    void
    );


//** From PowerPlat.c

//***_plat__Signal_PowerOn()
// Signal platform power on
LIB_EXPORT int
_plat__Signal_PowerOn(
    void
    );

//*** _plat__WasPowerLost()
// Test whether power was lost before a _TPM_Init.
//
// This function will clear the "hardware" indication of power loss before return.
// This means that there can only be one spot in the TPM code where this value
// gets read. This method is used here as it is the most difficult to manage in the
// TPM code and, if the hardware actually works this way, it is hard to make it
// look like anything else. So, the burden is placed on the TPM code rather than the
// platform code
// return type: int
//  TRUE(1)     power was lost
//  FALSE(0)    power was not lost
LIB_EXPORT int
_plat__WasPowerLost(
    void
    );

//*** _plat_Signal_Reset()
// This a TPM reset without a power loss.
LIB_EXPORT int
_plat__Signal_Reset(
    void
    );

//***_plat__Signal_PowerOff()
// Signal platform power off
LIB_EXPORT void
_plat__Signal_PowerOff(
    void
    );


//** From PPPlat.c

//***_plat__PhysicalPresenceAsserted()
// Check if physical presence is signaled
// return type: int
//      TRUE(1)          if physical presence is signaled
//      FALSE(0)         if physical presence is not signaled
LIB_EXPORT int
_plat__PhysicalPresenceAsserted(
    void
    );

//***_plat__Signal_PhysicalPresenceOn()
// Signal physical presence on
LIB_EXPORT void
_plat__Signal_PhysicalPresenceOn(
    void
    );

//***_plat__Signal_PhysicalPresenceOff()
// Signal physical presence off
LIB_EXPORT void
_plat__Signal_PhysicalPresenceOff(
    void
    );


//*** _plat__ACT_UpdateCounter()
// This function is used to write the newValue for the counter. If an update is
// pending, then no update occurs and the function returns FALSE. If 'setSignaled'
// is TRUE, then the ACT signaled state is SET and if 'newValue' is 0, nothing
// is posted.
LIB_EXPORT int
_plat__ACT_UpdateCounter(
    uint32_t            act,        // IN: ACT to update
    uint32_t            newValue   // IN: the value to post
);

//*** _plat__ACT_SetSignaled()
LIB_EXPORT void
_plat__ACT_SetSignaled(
    uint32_t            act,
    int                 on
);

//***_plat__ACT_Initialize()
// This function initializes the ACT hardware and data structures
LIB_EXPORT int
_plat__ACT_Initialize(
    void
);

//***_plat__ACT_EnableTicks()
// This enables and disables the processing of the once-per-second ticks. This should
// be turned off ('enable' = FALSE) by _TPM_Init and turned on ('enable' = TRUE) by
// TPM2_Startup() after all the initializations have completed.
LIB_EXPORT void
_plat__ACT_EnableTicks(
    int             enable
);

//*** _plat__ACT_GetRemaining()
// This function returns the remaining time. If an update is pending, 'newValue' is
// returned. Otherwise, the current counter value is returned. Note that since the
// timers keep running, the returned value can get stale immediately. The actual count
// value will be no greater than the returned value.
LIB_EXPORT uint32_t
_plat__ACT_GetRemaining(
    uint32_t            act             //IN: the ACT selector
);

//*** _plat__ACT_GetSignaled()
LIB_EXPORT int
_plat__ACT_GetSignaled(
    uint32_t            act         //IN: number of ACT to check
);

//*** _plat__ACT_GetImplemented()
// This function tests to see if an ACT is implemented. It is a belt and suspenders
// function because the TPM should not be calling to manipulate an ACT that is not
// implemented. However, this could help the simulator code which doesn't necessarily
// know if an ACT is implemented or not.
LIB_EXPORT int
_plat__ACT_GetImplemented(
    uint32_t            act
);

//** From RunCommand.c

//***_plat__RunCommand()
// This version of RunCommand will set up a jum_buf and call ExecuteCommand(). If
// the command executes without failing, it will return and RunCommand will return.
// If there is a failure in the command, then _plat__Fail() is called and it will
// longjump back to RunCommand which will call ExecuteCommand again. However, this
// time, the TPM will be in failure mode so ExecuteCommand will simply build
// a failure response and return.
LIB_EXPORT void
_plat__RunCommand(
    uint32_t         requestSize,   // IN: command buffer size
    unsigned char   *request,       // IN: command buffer
    uint32_t        *responseSize,  // IN/OUT: response buffer size
    unsigned char   **response      // IN/OUT: response buffer
    );

//***_plat__Fail()
// This is the platform depended failure exit for the TPM.
LIB_EXPORT NORETURN void
_plat__Fail(
    void
    );


//** From Unique.c

//** _plat__GetUnique()
// This function is used to access the platform-specific unique value.
// This function places the unique value in the provided buffer ('b')
// and returns the number of bytes transferred. The function will not
// copy more data than 'bSize'.
// NOTE: If a platform unique value has unequal distribution of uniqueness
// and 'bSize' is smaller than the size of the unique value, the 'bSize'
// portion with the most uniqueness should be returned.
LIB_EXPORT uint32_t
_plat__GetUnique(
    uint32_t             which,         // authorities (0) or details
    uint32_t             bSize,         // size of the buffer
    unsigned char       *b              // output buffer
    );

#endif  // _PLATFORM_FP_H_
