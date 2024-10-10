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
//** Includes
#include "Platform.h"

//** Global variables
#define DEFINE_ACT(N)  ACT_DATA ACT_##N;
FOR_EACH_ACT(DEFINE_ACT)

int actTicksAllowed;

//** Functions

//*** ActSignal()
// Function called when there is an ACT event to signal or unsignal
static void
ActSignal(
    P_ACT_DATA          actData,
    int                 on
)
{
    if(actData == NULL)
        return;
    // If this is to turn a signal on, don't do anything if it is already on. If this
    // is to turn the signal off, do it anyway because this might be for
    // initialization.
    if(on && (actData->signaled == TRUE))
        return;
    actData->signaled = (uint8_t)on;

    // If there is an action, then replace the "Do something" with the correct action.
    // It should test 'on' to see if it is turning the signal on or off.
    switch(actData->number)
    {
#if RH_ACT_0
        case 0: // Do something
            return;
#endif
#if RH_ACT_1
        case 1: // Do something
            return;
#endif
#if RH_ACT_2
        case 2: // Do something
            return;
#endif
#if RH_ACT_3
        case 3: // Do something
            return;
#endif
#if RH_ACT_4
        case 4: // Do something
            return;
#endif
#if RH_ACT_5
        case 5: // Do something
            return;
#endif
#if RH_ACT_6
        case 6: // Do something
            return;
#endif
#if RH_ACT_7
        case 7: // Do something
            return;
#endif
#if RH_ACT_8
        case 8: // Do something
            return;
#endif
#if RH_ACT_9
        case 9: // Do something
            return;
#endif
#if RH_ACT_A
        case 0xA: // Do something
            return;
#endif
#if RH_ACT_B
        case 0xB:
            // Do something
            return;
#endif
#if RH_ACT_C
        case 0xC: // Do something
            return;
#endif
#if RH_ACT_D
        case 0xD: // Do something
            return;
#endif
#if RH_ACT_E
        case 0xE: // Do something
            return;
#endif
#if RH_ACT_F
        case 0xF: // Do something
            return;
#endif
        default:
            return;
    }
}

//*** ActGetDataPointer()
static P_ACT_DATA
ActGetDataPointer(
    uint32_t            act
)
{

#define RETURN_ACT_POINTER(N)  if(0x##N == act) return &ACT_##N;

    FOR_EACH_ACT(RETURN_ACT_POINTER)

    return (P_ACT_DATA)NULL;
}

//*** _plat__ACT_GetImplemented()
// This function tests to see if an ACT is implemented. It is a belt and suspenders
// function because the TPM should not be calling to manipulate an ACT that is not
// implemented. However, this could help the simulator code which doesn't necessarily
// know if an ACT is implemented or not.
LIB_EXPORT int
_plat__ACT_GetImplemented(
    uint32_t            act
)
{
    return (ActGetDataPointer(act) != NULL);
}

//*** _plat__ACT_GetRemaining()
// This function returns the remaining time. If an update is pending, 'newValue' is
// returned. Otherwise, the current counter value is returned. Note that since the
// timers keep running, the returned value can get stale immediately. The actual count
// value will be no greater than the returned value.
LIB_EXPORT uint32_t
_plat__ACT_GetRemaining(
    uint32_t            act             //IN: the ACT selector
)
{
    P_ACT_DATA              actData = ActGetDataPointer(act);
    uint32_t                remain;
//
    if(actData == NULL)
        return 0;
    remain = actData->remaining;
    if(actData->pending)
        remain = actData->newValue;
    return remain;
}

//*** _plat__ACT_GetSignaled()
LIB_EXPORT int
_plat__ACT_GetSignaled(
    uint32_t            act         //IN: number of ACT to check
)
{
    P_ACT_DATA              actData = ActGetDataPointer(act);
//
    if(actData == NULL)
        return 0;
    return (int )actData->signaled;
}

//*** _plat__ACT_SetSignaled()
LIB_EXPORT void
_plat__ACT_SetSignaled(
    uint32_t            act,
    int                 on
)
{
    ActSignal(ActGetDataPointer(act), on);
}

//*** _plat__ACT_GetPending()
LIB_EXPORT int
_plat__ACT_GetPending(
    uint32_t            act         //IN: number of ACT to check
)
{
    P_ACT_DATA              actData = ActGetDataPointer(act);
//
    if(actData == NULL)
        return 0;
    return (int )actData->pending;
}


//*** _plat__ACT_UpdateCounter()
// This function is used to write the newValue for the counter. If an update is
// pending, then no update occurs and the function returns FALSE. If 'setSignaled'
// is TRUE, then the ACT signaled state is SET and if 'newValue' is 0, nothing
// is posted.
LIB_EXPORT int
_plat__ACT_UpdateCounter(
    uint32_t            act,        // IN: ACT to update
    uint32_t            newValue   // IN: the value to post
)
{
    P_ACT_DATA          actData = ActGetDataPointer(act);
 //
    if(actData == NULL)
        // actData doesn't exist but pretend update is pending rather than indicate
        // that a retry is necessary.
        return TRUE;
    // if an update is pending then return FALSE so that there will be a retry
    if(actData->pending != 0)
        return FALSE;
    actData->newValue = newValue;
    actData->pending = TRUE;

    return TRUE;
}

//***_plat__ACT_EnableTicks()
// This enables and disables the processing of the once-per-second ticks. This should
// be turned off ('enable' = FALSE) by _TPM_Init and turned on ('enable' = TRUE) by
// TPM2_Startup() after all the initializations have completed.
LIB_EXPORT void
_plat__ACT_EnableTicks(
    int             enable
)
{
    actTicksAllowed = enable;
}

//*** ActDecrement()
// If 'newValue' is non-zero it is copied to 'remaining' and then 'newValue' is
// set to zero. Then 'remaining' is decremented by one if it is not already zero. If
// the value is decremented to zero, then the associated event is signaled. If setting
// 'remaining' causes it to be greater than 1, then the signal associated with the ACT
// is turned off.
static void
ActDecrement(
    P_ACT_DATA            actData
)
{
    // Check to see if there is an update pending
    if(actData->pending)
    {
        // If this update will cause the count to go from non-zero to zero, set
        // the newValue to 1 so that it will timeout when decremented below.
        if((actData->newValue == 0) && (actData->remaining != 0))
           actData->newValue = 1;
        actData->remaining = actData->newValue;

        // Update processed
        actData->pending = 0;
    }
    // no update so countdown if the count is non-zero but not max
    if((actData->remaining != 0) && (actData->remaining != UINT32_MAX))
    {
        // If this countdown causes the count to go to zero, then turn the signal for
        // the ACT on.
        if((actData->remaining -= 1) == 0)
            ActSignal(actData, TRUE);
    }
    // If the current value of the counter is non-zero, then the signal should be
    // off.
    if(actData->signaled && (actData->remaining > 0))
            ActSignal(actData, FALSE);
}

//*** _plat__ACT_Tick()
// This processes the once-per-second clock tick from the hardware. This is set up
// for the simulator to use the control interface to send ticks to the TPM. These
// ticks do not have to be on a per second basis. They can be as slow or as fast as
// desired so that the simulation can be tested.
LIB_EXPORT void
_plat__ACT_Tick(
    void
)
{
    // Ticks processing is turned off at certain times just to make sure that nothing
    // strange is happening before pointers and things are
    if(actTicksAllowed)
    {
        // Handle the update for each counter.
#define DECREMENT_COUNT(N)   ActDecrement(&ACT_##N);

        FOR_EACH_ACT(DECREMENT_COUNT)
    }
}

//*** ActZero()
// This function initializes a single ACT
static void
ActZero(
    uint32_t        act,
    P_ACT_DATA      actData
)
{
    actData->remaining = 0;
    actData->newValue = 0;
    actData->pending = 0;
    actData->number = (uint8_t)act;
    ActSignal(actData, FALSE);
}

//***_plat__ACT_Initialize()
// This function initializes the ACT hardware and data structures
LIB_EXPORT int
_plat__ACT_Initialize(
    void
)
{
    actTicksAllowed = 0;
#define ZERO_ACT(N)  ActZero(0x##N, &ACT_##N);
    FOR_EACH_ACT(ZERO_ACT)

    return TRUE;
}
