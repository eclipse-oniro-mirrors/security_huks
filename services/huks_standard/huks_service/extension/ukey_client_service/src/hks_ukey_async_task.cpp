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

#include "hks_ukey_async_task.h"

#include <cstring>
#include <utility>

#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_util.h"
#include <cinttypes>
#include "hks_sa_interface.h"
#include "hks_response.h"
#include "hks_message_handler.h"
#include "hks_template.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace Hks {

namespace {
// Deep-copies a HksBlob (allocated with HksMalloc; sensitive-data zeroing and release are
// uniformly handled by ReleaseData)
struct HksBlob DeepCopyBlob(const struct HksBlob &src, int32_t *errOut)
{
    struct HksBlob dst = { 0, nullptr };
    if (src.size == 0 || src.data == nullptr) {
        return dst; // An empty blob is valid (size 0)
    }
    dst.data = static_cast<uint8_t *>(HksMalloc(src.size));
    if (dst.data == nullptr) {
        *errOut = HKS_ERROR_MALLOC_FAIL;
        return dst;
    }
    (void)memcpy_s(dst.data, src.size, src.data, src.size);
    dst.size = src.size;
    return dst;
}
} // namespace

HksUkeyAsyncTask::HksUkeyAsyncTask(const HksUkeyTaskParams &params,
    std::shared_ptr<Huks::IHksProviderProxyResolver> proxyResolver)
    : msgCode_(params.msgCode), handler_(params.handler), threeStageHandler_(params.threeStageHandler),
      fullTokenId_(params.fullTokenId), timeoutMs_(params.timeoutMs), outSize_(params.outSize),
      clientStub_(params.clientStub), proxyResolver_(proxyResolver)
{
    // Deep-copy the three items: srcData + processInfo embedded blobs; identity integer values
    // are copied directly.
    srcData_ = DeepCopyBlob(params.srcData, &deepCopyErr_);
    processInfo_.userId = DeepCopyBlob(params.processInfo.userId, &deepCopyErr_);
    processInfo_.processName = DeepCopyBlob(params.processInfo.processName, &deepCopyErr_);
    processInfo_.userIdInt = params.processInfo.userIdInt;
    processInfo_.uidInt = params.processInfo.uidInt;
    processInfo_.accessTokenId = params.processInfo.accessTokenId;
    processInfo_.pid = params.processInfo.pid;
    // Client-death cancellation: register a death recipient (best effort — if registration
    // fails, degrade to no-cancellation, same as the pre-refactor behavior). AddDeathRecipient
    // is a local registration on the proxy with no blocking IPC round-trip.
    cancelled_ = std::make_shared<std::atomic<bool>>(false);
    deathRecipient_ = new (std::nothrow) HksUkeyDeathRecipient(cancelled_);
    if (deathRecipient_ != nullptr) {
        (void)clientStub_->AddDeathRecipient(deathRecipient_);
    }
}

HksUkeyAsyncTask::~HksUkeyAsyncTask()
{
    // Unregister the death recipient before member destruction (OnRemoteDied will no longer
    // call this recipient afterwards; any concurrent in-flight callback only writes the shared
    // flag, whose lifetime is guaranteed by the sptr copy on the notification side).
    if (clientStub_ != nullptr && deathRecipient_ != nullptr) {
        (void)clientStub_->RemoveDeathRecipient(deathRecipient_);
    }
    ReleaseData(); // zeros deep-copied data, including sensitive content
}

void HksUkeyAsyncTask::ReleaseData()
{
    if (srcData_.data != nullptr) {
        (void)memset_s(srcData_.data, srcData_.size, 0, srcData_.size);
        HKS_FREE_BLOB(srcData_);
    }
    if (processInfo_.userId.data != nullptr) {
        (void)memset_s(processInfo_.userId.data, processInfo_.userId.size, 0, processInfo_.userId.size);
        HKS_FREE_BLOB(processInfo_.userId);
    }
    if (processInfo_.processName.data != nullptr) {
        (void)memset_s(processInfo_.processName.data, processInfo_.processName.size, 0,
            processInfo_.processName.size);
        HKS_FREE_BLOB(processInfo_.processName);
    }
    if (outDataRaw_ != nullptr) {
        // The output may contain sensitive data (certificates/PIN-related); zero it before
        // release (HksFree pairs with HksMalloc).
        if (outSize_ > 0) {
            (void)memset_s(outDataRaw_, outSize_, 0, outSize_);
        }
        HKS_FREE(outDataRaw_);
    }
}

int32_t HksUkeyAsyncTask::Run()
{
    // Dispatch target (function pointer, injected by the submit side's table lookup — single
    // source of truth HKS_IPC_MESSAGE_HANDLER / HKS_IPC_THREE_STAGE_HANDLER; the task library
    // does not depend on the IDL layer, avoiding a circular dependency).
    // The business orchestration (unpack/identity/adapter/error handling/DFX reporting) fully
    // reuses HksIpcServiceXxx: context is passed as nullptr and the thread result slot captures
    // the real ret/outBlob (hks_response.h).
    HKS_LOG_I("ukey async task begin, msgCode=%{public}u outSize=%{public}u timeout=%{public}ums",
        msgCode_, outSize_, timeoutMs_);
    uint64_t runStart = 0;
    // DFX: execution duration (compared against DeadlineMs to spot unreasonable settings).
    (void)HksElapsedRealTime(&runStart);
    // Early-exit checks precede identity injection (prevent an override from pointing at an
    // already-destroyed task).
    if (handler_ == nullptr && threeStageHandler_ == nullptr) {
        return HKS_ERROR_INVALID_ARGUMENT; // The submit side did not inject a dispatch target (should not happen)
    }
    // Client already dead: skip business execution (deep-copied sensitive data is zeroed and
    // released as soon as the task is destroyed; OnDone also skips the reply).
    if (cancelled_ != nullptr && cancelled_->load(std::memory_order_relaxed)) {
        return HKS_ERROR_BAD_STATE;
    }
    // Identity slot: during worker execution HksGetProcessInfoForIPC reads the identity held by
    // the task (pre-resolved on the IPC thread). Full-token slot: on the worker,
    // IPCSkeleton::GetCallingFullTokenID() falls back to the service's own token, so token-type
    // checks (CheckUkeyAuthPinType etc.) must read this slot for the caller's real tokenIDEx.
    // Both slots are reset together at the end of the function (no early-return path afterwards).
    HksSetThreadIdentityOverride(&processInfo_);
    HksSetThreadFullTokenIdOverride(fullTokenId_);
    int32_t ret = RunHandler();

    // Fetch the real result (ret = second argument of HksSendResponse; response = output data
    // ownership transfer).
    int32_t slotRet = 0;
    struct HksBlob slotResponse = { 0, nullptr };
    HksAsyncResultSlotTake(&slotRet, &slotResponse);
    if (ret == HKS_SUCCESS) {
        ret = slotRet;
    }
    if (slotResponse.data != nullptr) {
        outDataRaw_ = slotResponse.data;
        outSize_ = slotResponse.size;
    }
    HksSetThreadIdentityOverride(nullptr); // Reset the identity slot (prevent cross-identity reuse)
    HksSetThreadFullTokenIdOverride(0);    // Reset the token slot accordingly
    // Capture the thread-local extended error (written by the adapter via
    // HksAppendThreadExtErrMsg while the handler runs, on the same worker thread as Run; OnDone
    // reads it on the same thread and carries it out with the reply, freeing it after SendAsyncReply).
    extErrInfo_ = HksGetAndClearThreadExtErrMsg();
    uint64_t runEnd = 0;
    (void)HksElapsedRealTime(&runEnd);
    HKS_LOG_I("ukey async task done, msgCode=%{public}u ret=%{public}d cost=%{public}" PRIu64
        "ms deadline=%{public}ums", msgCode_, ret, runEnd - runStart, timeoutMs_);
    return ret;
}

int32_t HksUkeyAsyncTask::RunHandler()
{
    // Enable the result slot, then dispatch; single-arg / three-stage, exactly one (the
    // early-exit check guarantees at least one is non-null).
    HksAsyncResultSlotSetEnabled(true);
    if (handler_ != nullptr) {
        handler_(&srcData_, nullptr);
        return HKS_SUCCESS;
    }
    // Three-stage: preallocate outData per the client-reported outSize (read from the parcel at
    // admission, injected at construction).
    struct HksBlob outData = { 0, nullptr };
    if (outSize_ > 0) {
        outData.data = static_cast<uint8_t *>(HksMalloc(outSize_));
        if (outData.data == nullptr) {
            return HKS_ERROR_MALLOC_FAIL;
        }
        outData.size = outSize_;
    }
    threeStageHandler_(&srcData_, &outData, nullptr);
    if (outData.data != nullptr) {
        HKS_FREE_BLOB(outData); // The result slot has captured the real output; release the local buffer as a fallback
    }
    return HKS_SUCCESS;
}

void HksUkeyAsyncTask::OnDone(int32_t ret)
{
    // Client already dead: skip the reply (the proxy is invalid, SendRequest would necessarily
    // fail; saves one pointless IPC).
    if (cancelled_ != nullptr && cancelled_->load(std::memory_order_relaxed)) {
        return;
    }
    // Reply via the client callback object (wire code = original request code, errCode = real
    // result code). SendAsyncReply only reads the data into the parcel (does not move or take
    // over) — a temporary unique_ptr is lent out and released back to the raw pointer afterwards:
    // ownership stays with the task (HksMalloc family, uniformly released via HKS_FREE in the
    // destructor, paired with the allocator).
    auto hksExtProxy = OHOS::iface_cast<OHOS::Security::Hks::IHksExtService>(clientStub_);
    HKS_IF_NULL_LOGE_RETURN_VOID(hksExtProxy, "hksExtProxy null, drop reply");
    HKS_LOG_I("ukey async task ondone begin, msgCode=%{public}u ret=%{public}d outSize=%{public}u",
        msgCode_, ret, outSize_);
    std::unique_ptr<uint8_t[]> sendData(outDataRaw_);
    hksExtProxy->SendAsyncReply(static_cast<uint32_t>(ret), sendData, outSize_, msgCode_, extErrInfo_);
    (void)sendData.release(); // Ownership returns to the task (released via HKS_FREE in the destructor)
    // The thread-local error was carried out with the reply; release it (HksMalloc family).
    HksFreeExternalErrorInfo(extErrInfo_);
    extErrInfo_ = nullptr;
}

HksUkeyAsyncTask *HksCreateUkeyAsyncTask(const HksUkeyTaskParams &params, int32_t *errOut)
{
    if (errOut == nullptr) {
        return nullptr;
    }
    *errOut = HKS_SUCCESS;
    auto task = new (std::nothrow) HksUkeyAsyncTask(params, Huks::HksGetProviderProxyResolver());
    if (task == nullptr) {
        *errOut = HKS_ERROR_MALLOC_FAIL;
        return nullptr;
    }
    if (task->GetDeepCopyErr() != HKS_SUCCESS) {
        *errOut = task->GetDeepCopyErr();
        delete task;
        return nullptr;
    }
    return task;
}

} // namespace Hks
} // namespace Security
} // namespace OHOS
