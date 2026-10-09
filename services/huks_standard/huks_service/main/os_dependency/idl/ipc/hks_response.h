/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HKS_RESPONSE_H
#define HKS_RESPONSE_H

#include "hks_type_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

void HksSendResponse(const uint8_t *context, int32_t result, const struct HksBlob *response);

int32_t HksGetProcessInfoForIPC(const struct HksParamSet *paramSet,
    const uint8_t *context, struct HksProcessInfo *processInfo);

int32_t HksGetRelatedFrontUserId(const struct HksParamSet *paramSet, int32_t ipcCallerUserId, int32_t *outId);

int32_t HksCheckIsFrontUser(int32_t userId, bool *isFrontUser);

int HksGetOsAccountIdFromUid(int uid);

/*
 * ukey async refactor: thread-local async result slot (temporarily stores the response while
 * a worker thread runs a task). The worker enables the slot before running the task and calls
 * HksIpcServiceXxx with context=nullptr — HksSendResponse copies result/response into the slot
 * instead of writing a parcel when it sees the null context; the task then takes the real
 * result from the slot and returns it via the callback object. The slot is reused per thread
 * and cleared before every task.
 */
struct HksAsyncResultSlot {
    bool enabled;   // whether this thread is in async-task execution mode
    bool captured;  // whether the result has been captured this run (HksSendResponse may be
                    // called multiple times; the first one wins)
    int32_t result; // client-visible error code (second argument of HksSendResponse)
    struct HksBlob response; // output data (deep-copied, allocated by HksMalloc; data=NULL/size=0
                             // for empty output)
};

// enables/disables the current thread's result slot (before/after task Run); disabling does
// not release captured data (held until TakeOwned)
void HksAsyncResultSlotSetEnabled(bool enabled);

// takes the current thread's captured result (ownership transfer: response.data is released by
// the caller); when nothing was captured, result is set to fallback and response to empty. The
// slot is reset after the call.
void HksAsyncResultSlotTake(int32_t *result, struct HksBlob *response);

// ukey async refactor: thread identity slot — while a worker executes a task, make
// HksGetProcessInfoForIPC take the identity carried by the task (resolved and deep-copied by
// the IPC thread) instead of the IPC context (untrustworthy on the worker). processInfo points
// at a task member, valid during task Run; must be set to nullptr after Run.
void HksSetThreadIdentityOverride(const struct HksProcessInfo *processInfo);
// reads the current thread's identity slot (nullptr when unset); used by permission-check
// logic to obtain the caller's real uid (e.g. trusted-SA judgement)
const struct HksProcessInfo *HksGetThreadIdentityOverride();

// ukey async refactor: thread full-token slot — worker threads have no IPC context, so
// IPCSkeleton::GetCallingFullTokenID() falls back to GetSelfTokenID() (the service's own
// token), making token-type checks (e.g. CheckUkeyAuthPinType) misjudge the caller. The IPC
// thread captures the caller's full tokenIDEx on admission and injects it into the task; the
// worker reads it through this slot during execution; 0 means not injected (IPC-thread sync
// path, the caller falls back to IPCSkeleton).
void HksSetThreadFullTokenIdOverride(uint64_t fullTokenId);
uint64_t HksGetThreadFullTokenIdOverride();

#ifdef __cplusplus
}
#endif

#endif
