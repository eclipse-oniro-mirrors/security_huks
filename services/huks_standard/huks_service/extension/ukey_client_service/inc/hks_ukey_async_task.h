/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef HKS_UKEY_ASYNC_TASK_H
#define HKS_UKEY_ASYNC_TASK_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <utility>

#include "hks_async_task.h"
#include "hks_ukey_provider_proxy_resolver.h"
#include "ihuks_access_ext_base.h"
#include "hks_ext_error_info.h" // HksExternalErrorInfoIdl (IDL-generated)
#include "hks_external_error_info.h" // HksExternalErrorInfo (thread-local extended error, sent back to the client)
#include "iremote_object.h"
#include "hks_plugin_def.h"
#include "hks_message_handler.h"  // HksIpcHandlerFuncProc / HksIpcThreeStageHandlerFuncProc (table lookup types)
#include "hks_type.h"

namespace OHOS {
namespace Security {
namespace Hks {

/*
 * Client death recipient: registered on the task's clientStub_, only sets a cancel flag and
 * never holds a back-reference to the task. OnRemoteDied is invoked on the binder death
 * notification thread and can race with the worker thread's Run/OnDone and the task
 * destructor; the flag is shared with the task via shared_ptr, so its lifetime is independent
 * of the recipient object itself — no UAF/dangling.
 */
class HksUkeyDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit HksUkeyDeathRecipient(std::shared_ptr<std::atomic<bool>> cancelled)
        : cancelled_(std::move(cancelled)) {}
    ~HksUkeyDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject> &remoteObject) override
    {
        if (cancelled_ != nullptr) {
            cancelled_->store(true, std::memory_order_relaxed);
        }
    }

private:
    std::shared_ptr<std::atomic<bool>> cancelled_;
};

// Aggregated task-construction parameters (ukey request -> task construction). The original
// constructor/factory took 10 parameters, exceeding the "at most 5 function parameters" coding
// rule, so they are bundled into a struct (constructor 2 params, factory 2 params).
// The submit side assembles this struct (identity/token already resolved on the IPC thread);
// the constructor deep-copies the data and takes ownership.
struct HksUkeyTaskParams {
    uint32_t msgCode = 0;
    // Single-argument handler (extension codes + reused standard single-arg codes).
    HksIpcHandlerFuncProc handler = nullptr;
    // Three-stage handler (INIT/UPDATE/FINISH/ABORT).
    HksIpcThreeStageHandlerFuncProc threeStageHandler = nullptr;
    // Deep-copied (embedded blobs self-owned).
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    // Deep-copied.
    struct HksBlob srcData = { 0, nullptr };
    uint32_t timeoutMs = 0;
    // Client-reported output buffer size.
    uint32_t outSize = 0;
    // Caller's full tokenIDEx (captured on the IPC thread).
    uint64_t fullTokenId = 0;
    // Client callback object (refcounted).
    OHOS::sptr<OHOS::IRemoteObject> clientStub;
};

/*
 * ukey admission task:
 * One request maps to one task instance; all inputs are deep-copied at construction (the
 * parcel buffer is invalid after the IPC thread returns). The task object owns the data and
 * releases it all at destruction with zeroing (including sensitive data).
 */
class HksUkeyAsyncTask : public HksAsyncTask {
public:
    // The constructor deep-copies srcData (including paramSet) and the processInfo embedded
    // blobs (processName/userId). The dispatch target is injected as a function pointer (looked
    // up by the submit side — single source of truth; the task library does not depend on the
    // IDL layer, avoiding a circular dependency). handler and threeStageHandler are mutually
    // exclusive (exactly one is non-null); outSize is the client-reported output buffer size
    // (used by the three-stage path). On a deep-copy failure the object takes over no pointers
    // (construction failure = the submit side gets the error code and no task is created).
    // Parameters are aggregated via HksUkeyTaskParams (the original 10 parameters exceeded the
    // "at most 5 function parameters" coding rule).
    HksUkeyAsyncTask(const HksUkeyTaskParams &params,
        std::shared_ptr<Huks::IHksProviderProxyResolver> proxyResolver);
    ~HksUkeyAsyncTask() override;

    // Worker thread: dispatches via function pointer to the existing orchestration and
    // captures the result slot.
    int32_t Run() override;
    // Worker thread: delivers the result via the client callback object.
    void OnDone(int32_t ret) override;
    uint32_t DeadlineMs() const override  // Milliseconds (the submit side already converted seconds x 1000)
    {
        return timeoutMs_;
    }
    // Deep-copy failure flag from construction (checked by the factory; on failure the object
    // takes over no pointers and is destroyed directly).
    int32_t GetDeepCopyErr() const
    {
        return deepCopyErr_;
    }

private:
    // Zeros and releases deep-copied data (shared by the destructor and the
    // construction-failure path).
    void ReleaseData();
    // Dispatches to the single-arg / three-stage handler (enables the result slot and
    // preallocates the three-stage output; called by Run).
    int32_t RunHandler();

    uint32_t msgCode_ = 0;
    // Single-argument handler (extension codes + reused standard single-arg codes).
    HksIpcHandlerFuncProc handler_ = nullptr;
    // Three-stage handler (INIT/UPDATE/FINISH/ABORT).
    HksIpcThreeStageHandlerFuncProc threeStageHandler_ = nullptr;
    // Deep-copied (embedded blobs self-owned).
    struct HksProcessInfo processInfo_ = { { 0, nullptr }, { 0, nullptr }, 0, 0, 0, 0 };
    // Caller's full tokenIDEx (captured on the IPC thread, used by worker-side checks).
    uint64_t fullTokenId_ = 0;
    // Deep-copied.
    struct HksBlob srcData_ = { 0, nullptr };
    uint32_t timeoutMs_ = 0;
    // Client-reported output buffer size.
    uint32_t outSize_ = 0;
    // Deep-copy failure flag from construction.
    int32_t deepCopyErr_ = 0;
    // Client callback object (refcounted).
    OHOS::sptr<OHOS::IRemoteObject> clientStub_;
    // Set on client death (written by OnRemoteDied, read by Run/OnDone; null = never cancelled).
    std::shared_ptr<std::atomic<bool>> cancelled_;
    // Death recipient (registered on clientStub_ in the constructor, unregistered in the
    // destructor).
    sptr<HksUkeyDeathRecipient> deathRecipient_;
    std::shared_ptr<Huks::IHksProviderProxyResolver> proxyResolver_;
    // Output captured during Run (HksMalloc family; released via HKS_FREE in the
    // destructor, paired with the allocator).
    uint8_t *outDataRaw_ = nullptr;
    // Extended detailed error (IDL struct, OHOS::Security::Huks).
    struct Huks::HksExternalErrorInfoIdl errInfo_ = { 0, "", false };
    // Thread-local extended error (captured at the end of Run, carried out with the
    // reply in OnDone; freed after SendAsyncReply).
    struct HksExternalErrorInfo *extErrInfo_ = nullptr;
};

// Construction helper: deep-copies and creates the task; returns nullptr on failure (the error
// code is returned via errOut). Task-construction parameters are aggregated via
// HksUkeyTaskParams (the original 10 parameters exceeded the "at most 5 function parameters"
// coding rule).
HksUkeyAsyncTask *HksCreateUkeyAsyncTask(const HksUkeyTaskParams &params, int32_t *errOut);

} // namespace Hks
} // namespace Security
} // namespace OHOS

#endif // HKS_UKEY_ASYNC_TASK_H
