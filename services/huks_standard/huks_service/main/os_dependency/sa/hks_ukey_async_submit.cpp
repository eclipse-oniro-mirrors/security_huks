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

#include "hks_ukey_async_submit.h"

#include <memory>
#include <mutex>
#include <unordered_map>

#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_sa_interface.h"
#include "hks_template.h"
#include "hks_type_inner.h"
#include "hks_ukey_async_task.h"
#include "hks_ukey_check.h"
#include "hks_ukey_common.h"
#include "hks_message_handler.h"
#include "hks_ipc_service.h"
#include <ipc_skeleton.h> // IPCSkeleton::GetCallingFullTokenID (caller token on the IPC thread)
#include "hks_response.h"                 // HksGetProcessInfoForIPC (identity resolution)
#include "hks_service_ipc_serialization.h" // HksParamSetToParams (embedded paramSet parsing)
#include "hks_task_executor.h"
#include "hks_plugin_loader.h"
#include "hks_permission_check.h"          // CheckUkeyAuthPinType, CheckUkeyCertCaller, HksCheckAcrossAccountsPermission
#include "securec.h"

// The whole server-side submit module serves the ukey async path only (its helper functions
// reference HksCheckIsUkeyOperation / HksUkeyTimeoutTagByMsgCode from hks_ukey_check.cpp, which
// is compiled only when ukey is enabled); on non-ukey products nothing references it.
#ifdef HKS_UKEY_EXTENSION_CRYPTO
namespace OHOS {
namespace Security {
namespace Hks {

namespace {
// Skips a leading blob (the client packs with 4-byte ALIGN_SIZE alignment —
// CopyBlobToBuffer/CopyParamSetToBuffer; 8-byte alignment was once misused, and when a blob
// size was not a multiple of 8 the offset ran ahead and misaligned the paramSet — openHandle
// reported "HksCheckParamSet: invalid param set!")
bool SkipBlobInRaw(const uint8_t *p, uint32_t remain, uint32_t &off)
{
    if (remain - off < sizeof(uint32_t)) {
        return false;
    }
    uint32_t blobLen = 0;
    (void)memcpy_s(&blobLen, sizeof(blobLen), p + off, sizeof(uint32_t));
    off += sizeof(uint32_t);
    if (remain - off < ALIGN_SIZE(blobLen)) {
        return false; // bounds check
    }
    off += ALIGN_SIZE(blobLen);
    return true;
}

bool SkipUint32InRaw(uint32_t remain, uint32_t &off)
{
    if (remain - off < sizeof(uint32_t)) {
        return false;
    }
    off += sizeof(uint32_t);
    return true;
}

// Three-stage (INIT/UPDATE/FINISH/ABORT): srcData itself is a wrapper paramSet (the real
// paramSet is inside the HKS_TAG_PARAM0/1_BUFFER blob — INIT=PARAM1, UPDATE/FINISH/ABORT=PARAM0)
struct HksParamSet *ParseThreeStageInnerParamSet(enum HksIpcInterfaceCode code, uint32_t msgCode,
    const uint8_t *p, uint32_t remain)
{
    struct HksParamSet *wrapper = nullptr;
    if (HksGetParamSet(reinterpret_cast<const struct HksParamSet *>(p), remain, &wrapper) != HKS_SUCCESS) {
        HKS_LOG_E("ukey unpack three-stage wrapper fail, msgCode=%" LOG_PUBLIC "u size=%" LOG_PUBLIC "u",
            msgCode, remain);
        return nullptr;
    }
    struct HksBlob param0 = { 0, nullptr };
    struct HksBlob param1 = { 0, nullptr };
    struct HksParamOut params[] = {
        { .tag = HKS_TAG_PARAM0_BUFFER, .blob = &param0 },
        { .tag = HKS_TAG_PARAM1_BUFFER, .blob = &param1 },
    };
    struct HksParamSet *inner = nullptr;
    do {
        if (HksParamSetToParams(wrapper, params, HKS_ARRAY_SIZE(params)) != HKS_SUCCESS) {
            break;
        }
        // INIT: PARAM1 = the real paramSet; UPDATE/FINISH/ABORT: PARAM0 = the real paramSet
        const struct HksBlob *real = (code == HKS_MSG_INIT) ?
            ((param1.size > 0) ? &param1 : &param0) : &param0;
        if (real->size == 0 || real->data == nullptr) {
            break;
        }
        (void)HksGetParamSet(reinterpret_cast<const struct HksParamSet *>(real->data), real->size, &inner);
    } while (false);
    HksFreeParamSet(&wrapper);
    HKS_LOG_I("ukey unpack three-stage inner %" LOG_PUBLIC "s, msgCode=%" LOG_PUBLIC "u",
        (inner == nullptr) ? "fail" : "ok", msgCode);
    return inner;
}

// Non-three-stage codes: parse the paramSet after skipping the leading fields per the code layout.
//   Extension codes (GeneralPack family): [uint32 len|blob(4-aligned)][paramSet(4-aligned)]
//   GEN_KEY:                             [keyAlias][paramSet][keyOutSize]  -> skip 1 blob
//   EXPORT_PUBLIC_KEY:                   [keyAlias][keyOutSize(u32)][paramSet] -> skip 1 blob + u32
//   IMPORT_WRAPPED_KEY:                  [alias][wrapAlias][paramSet][data] -> skip 2 blobs
// Operations without a paramSet (e.g. CLEAR_PIN_AUTH_STATE) return NULL (valid; timeout uses
// the default and identity goes through the thread context).
struct HksParamSet *ParseRawParamSet(enum HksIpcInterfaceCode code, uint32_t msgCode,
    const uint8_t *p, uint32_t remain)
{
    // Default layout: blob first (1 for extension codes and GEN_KEY; 2 for IMPORT_WRAPPED_KEY)
    uint32_t offset = 0;
    uint32_t skipBlobs = (code == HKS_MSG_IMPORT_WRAPPED_KEY) ? 2 : 1;
    switch (code) {
        case HKS_MSG_EXT_CLEAR_PIN_AUTH_STATE:
            // [index blob][paramSet] — BuildParamSetNotNull always creates a paramSet.
            skipBlobs = 1;
            break;
        case HKS_MSG_EXT_QUERY_ABILITY_INFO:
            // [blob1][blob2][blob3][paramSet?] — paramSet absent when paramSetIn is NULL
            // (HksBlob3ParamSetPack omits it); the tail check below returns nullptr in that case.
            skipBlobs = 3;
            break;
        case HKS_MSG_EXPORT_PUBLIC_KEY: // [keyAlias][keyOutSize(u32)][paramSet]
            if (!SkipBlobInRaw(p, remain, offset) || !SkipUint32InRaw(remain, offset)) {
                HKS_LOG_E("ukey unpack export_pub_key skip fail, msgCode=%" LOG_PUBLIC "u offset=%" LOG_PUBLIC "u",
                    msgCode, offset);
                return nullptr;
            }
            skipBlobs = 0; // custom skip already advanced offset
            break;
        case HKS_MSG_EXT_IMPORT_CERTIFICATE: // [resourceId][purpose(i32)][index][cert][paramSet]
            if (!SkipBlobInRaw(p, remain, offset) || !SkipUint32InRaw(remain, offset) ||
                !SkipBlobInRaw(p, remain, offset) || !SkipBlobInRaw(p, remain, offset)) {
                HKS_LOG_E("ukey unpack import_cert skip fail, msgCode=%" LOG_PUBLIC "u offset=%" LOG_PUBLIC "u",
                    msgCode, offset);
                return nullptr;
            }
            skipBlobs = 0; // custom skip already advanced offset
            break;
        default:
            // Extension codes/GEN_KEY/IMPORT_WRAPPED_KEY: blob first (IMPORT_WRAPPED_KEY has 2)
            for (uint32_t i = 0; i < skipBlobs; ++i) {
                if (!SkipBlobInRaw(p, remain, offset)) {
                    HKS_LOG_E("ukey unpack skip blob fail, msgCode=%" LOG_PUBLIC "u offset=%" LOG_PUBLIC "u",
                        msgCode, offset);
                    return nullptr;
                }
            }
            break;
    }
    if (remain - offset < sizeof(struct HksParamSet)) {
        HKS_LOG_E("ukey unpack paramSet too short, msgCode=%" LOG_PUBLIC "u offset=%" LOG_PUBLIC "u remain=%" LOG_PUBLIC "u",
            msgCode, offset, remain);
        return nullptr;
    }
    // The paramSet has no length prefix and is written raw with 4-byte padding. HksCheckParamSet
    // requires paramSetSize == size; since the tail carries alignment padding, remain-offset
    // cannot be passed directly as size — parse exactly by the header-declared paramSetSize
    // (first verify the aligned size stays in bounds).
    const struct HksParamSet *header = reinterpret_cast<const struct HksParamSet *>(p + offset);
    if (IsAdditionOverflow(header->paramSetSize, DEFAULT_ALIGN_MASK_SIZE) ||
        ALIGN_SIZE(header->paramSetSize) > (remain - offset)) {
        return nullptr;
    }
    struct HksParamSet *paramSet = nullptr;
    (void)HksGetParamSet(header, header->paramSetSize, &paramSet);
    HKS_LOG_I("ukey unpack paramSet %" LOG_PUBLIC "s, msgCode=%" LOG_PUBLIC "u offset=%" LOG_PUBLIC "u paramSetSize=%" LOG_PUBLIC "u",
        (paramSet == nullptr) ? "fail" : "ok", msgCode, offset, header->paramSetSize);
    return paramSet;
}

// Extracts the embedded paramSet from the client-packed buffer. Returns a malloc'd paramSet
// (the caller frees it with HksFreeParamSet).
struct HksParamSet *UnpackParamSetFromSrcData(uint32_t msgCode, const struct HksBlob &srcData)
{
    const uint8_t *p = srcData.data;
    uint32_t remain = srcData.size;
    if (p == nullptr || remain < sizeof(uint32_t)) {
        HKS_LOG_E("ukey unpack srcData invalid, msgCode=%" LOG_PUBLIC "u size=%" LOG_PUBLIC "u",
            msgCode, remain);
        return nullptr;
    }
    enum HksIpcInterfaceCode code = static_cast<enum HksIpcInterfaceCode>(msgCode);
    HKS_LOG_I("ukey unpack srcData begin, msgCode=%" LOG_PUBLIC "u size=%" LOG_PUBLIC "u",
        msgCode, remain);
    if (code == HKS_MSG_INIT || code == HKS_MSG_UPDATE || code == HKS_MSG_FINISH || code == HKS_MSG_ABORT) {
        return ParseThreeStageInnerParamSet(code, msgCode, p, remain);
    }
    return ParseRawParamSet(code, msgCode, p, remain);
}

// Server-side timeout readout (same rule as the client; tag seconds -> task milliseconds,
// explicit x1000). The tag is selected per code layout (same source as the client's
// HksUkeyParseTimeout): the 7 standard codes read HKS_TAG_TIMEOUT(529), extension codes read
// HKS_EXT_CRYPTO_TAG_TIMEOUT(200006) — HksUkeyTimeoutTagByMsgCode is the single source of truth.
constexpr uint32_t UKEY_ASYNC_MAX_TIMEOUT_SEC = 900; // 15-minute cap, consistent with the client
constexpr uint32_t UKEY_ASYNC_DEFAULT_SEC = 60;      // Uniform default when no tag is set, consistent with the client
constexpr uint32_t UKEY_ASYNC_MS_PER_SEC = 1000;     // seconds -> milliseconds conversion

int32_t ParseTimeoutMs(uint32_t msgCode, const struct HksParamSet *paramSet, uint32_t *timeoutMs)
{
    uint32_t timeoutSec = UKEY_ASYNC_DEFAULT_SEC;
    struct HksParam *timeoutParam = nullptr;
    enum HksTag timeoutTag = HksUkeyTimeoutTagByMsgCode(msgCode);
    if (HksGetParam(paramSet, timeoutTag, &timeoutParam) == HKS_SUCCESS) {
        HKS_IF_TRUE_LOGE_RETURN(GetTagType((enum HksTag)timeoutParam->tag) != HKS_TAG_TYPE_UINT,
            HKS_ERROR_INVALID_ARGUMENT, "timeout tag type invalid");
        uint32_t val = timeoutParam->uint32Param;
        HKS_IF_TRUE_LOGE_RETURN(val == 0 || val > UKEY_ASYNC_MAX_TIMEOUT_SEC, HKS_ERROR_INVALID_ARGUMENT,
            "timeout %" LOG_PUBLIC "u not supported, must be in [1, %" LOG_PUBLIC "u]",
            val, UKEY_ASYNC_MAX_TIMEOUT_SEC);
        timeoutSec = val;
    }
    *timeoutMs = timeoutSec * UKEY_ASYNC_MS_PER_SEC;
    return HKS_SUCCESS;
}
} // namespace

// ==================== handle → providerName routing (per-provider executor) ====================

// The INIT operation receives resourceId as input and returns a handle to the client.
// UPDATE/FINISH/ABORT only carry the handle — no resourceId. To route three-stage operations
// to the correct per-provider executor, INIT's OnDone writes handle→providerName into this map;
// UPDATE/FINISH/ABORT look it up by handle at submit time.
//
// Cleanup: FINISH/ABORT OnDone removes the entry. If the client crashes, the
// HandleRoutingDeathRecipient (registered on the client's callback stub) fires and removes
// the entry automatically — no timeout, no polling.

struct HandleRoutingEntry {
    std::string providerName;
    sptr<IRemoteObject::DeathRecipient> deathRecipient;
};

static std::mutex g_handleRoutingMutex;
static std::unordered_map<uint64_t, HandleRoutingEntry> g_handleRouting;

// Death recipient registered on the client's callback stub during INIT OnDone. When the client
// process dies, binder fires OnRemoteDied and the entry is removed. Does NOT call
// RemoveDeathRecipient (the client is dead, binder auto-cleans). Only holds the handle value;
// no pointers to task objects (no UAF risk).
class HandleRoutingDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit HandleRoutingDeathRecipient(uint64_t handle) : handle_(handle) {}
    ~HandleRoutingDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        std::lock_guard<std::mutex> lock(g_handleRoutingMutex);
        g_handleRouting.erase(handle_);
        HKS_LOG_I("handle routing cleaned by client death, handle=%" LOG_PUBLIC "llu",
            static_cast<unsigned long long>(handle_));
    }

private:
    uint64_t handle_;
};

void RegisterHandleRouting(uint64_t handle, const std::string &providerName,
    const sptr<IRemoteObject> &clientStub)
{
    auto dr = sptr<HandleRoutingDeathRecipient>(new (std::nothrow) HandleRoutingDeathRecipient(handle));
    if (dr == nullptr) {
        HKS_LOG_E("handle routing: alloc death recipient fail, handle=%" LOG_PUBLIC "llu",
            static_cast<unsigned long long>(handle));
        return;
    }
    if (clientStub != nullptr) {
        (void)clientStub->AddDeathRecipient(dr);
    }
    std::lock_guard<std::mutex> lock(g_handleRoutingMutex);
    g_handleRouting[handle] = { providerName, dr };
}

void UnregisterHandleRouting(uint64_t handle)
{
    std::lock_guard<std::mutex> lock(g_handleRoutingMutex);
    g_handleRouting.erase(handle);
}

std::string LookupHandleRouting(uint64_t handle)
{
    std::lock_guard<std::mutex> lock(g_handleRoutingMutex);
    auto it = g_handleRouting.find(handle);
    if (it != g_handleRouting.end()) {
        return it->second.providerName;
    }
    return ""; // not found → fallback to global executor
}

// Extracts providerName from srcData for routing purposes.
// - Non-three-stage codes: the first blob is resourceId JSON (or providerName for
//   EXPORT_PROVIDER_CERTIFICATES / GET_RESOURCE_ID).
// - INIT: the wrapper paramSet's PARAM0_BUFFER = keyAlias (= resourceId JSON).
// - UPDATE/FINISH/ABORT: PARAM1_BUFFER = handle (uint64_t) → lookup g_handleRouting.
// Returns "" on failure (the task falls back to the global executor; business-layer
// error handling is unchanged — the handler itself re-parses resourceId and returns
// the original error code if the format is invalid).
static std::string ExtractProviderName(uint32_t msgCode, const struct HksBlob &srcData)
{
    const uint8_t *p = srcData.data;
    uint32_t remain = srcData.size;
    if (p == nullptr || remain < sizeof(uint32_t)) {
        return "";
    }
    enum HksIpcInterfaceCode code = static_cast<enum HksIpcInterfaceCode>(msgCode);

    // Three-stage codes: srcData is a wrapper paramSet
    if (code == HKS_MSG_INIT || code == HKS_MSG_UPDATE ||
        code == HKS_MSG_FINISH || code == HKS_MSG_ABORT) {
        struct HksParamSet *wrapper = nullptr;
        if (HksGetParamSet(reinterpret_cast<const struct HksParamSet *>(p), remain, &wrapper) != HKS_SUCCESS) {
            return "";
        }
        struct HksBlob param0 = { 0, nullptr };
        struct HksBlob param1 = { 0, nullptr };
        struct HksParamOut params[] = {
            { .tag = HKS_TAG_PARAM0_BUFFER, .blob = &param0 },
            { .tag = HKS_TAG_PARAM1_BUFFER, .blob = &param1 },
        };
        std::string result;
        do {
            if (HksParamSetToParams(wrapper, params, HKS_ARRAY_SIZE(params)) != HKS_SUCCESS) {
                break;
            }
            if (code == HKS_MSG_INIT) {
                // INIT: PARAM0 = keyAlias (= resourceId JSON)
                const struct HksBlob *real = (param0.size > 0) ? &param0 : &param1;
                if (real->data == nullptr || real->size == 0) {
                    break;
                }
                std::string resourceId(reinterpret_cast<const char *>(real->data), real->size);
                OHOS::Security::Huks::ProviderInfo info;
                std::string newIndex;
                if (OHOS::Security::Huks::GetProviderInfoAndIndex(resourceId, info, newIndex) == HKS_SUCCESS) {
                    result = info.m_providerName;
                }
            } else {
                // UPDATE/FINISH/ABORT: PARAM1 = handle (uint64_t)
                if (param1.data == nullptr || param1.size < sizeof(uint64_t)) {
                    break;
                }
                uint64_t handle = 0;
                (void)memcpy_s(&handle, sizeof(handle), param1.data, sizeof(uint64_t));
                result = LookupHandleRouting(handle);
            }
        } while (false);
        HksFreeParamSet(&wrapper);
        return result;
    }

    // Non-three-stage: first blob is resourceId JSON or providerName string.
    // Layout: [uint32 len | blob(4-aligned)] [paramSet]
    uint32_t blobLen = 0;
    if (remain < sizeof(uint32_t)) {
        return "";
    }
    (void)memcpy_s(&blobLen, sizeof(blobLen), p, sizeof(uint32_t));
    if (remain - sizeof(uint32_t) < blobLen) {
        return "";
    }
    std::string firstBlob(reinterpret_cast<const char *>(p + sizeof(uint32_t)), blobLen);

    // EXPORT_PROVIDER_CERTIFICATES and GET_RESOURCE_ID: first blob is providerName directly
    if (code == HKS_MSG_EXT_EXPORT_PROVIDER_CERTIFICATES || code == HKS_MSG_EXT_GET_RESOURCE_ID) {
        return firstBlob;
    }

    // Other codes: first blob is resourceId JSON
    OHOS::Security::Huks::ProviderInfo info;
    std::string newIndex;
    if (OHOS::Security::Huks::GetProviderInfoAndIndex(firstBlob, info, newIndex) == HKS_SUCCESS) {
        return info.m_providerName;
    }
    return "";
}

// Extracts the handle (uint64_t) from UPDATE/FINISH/ABORT srcData for routing table cleanup.
// PARAM1_BUFFER carries the handle. Returns 0 on failure (OnDone skips cleanup).
static uint64_t ExtractHandleFromSrcData(uint32_t msgCode, const struct HksBlob &srcData)
{
    enum HksIpcInterfaceCode code = static_cast<enum HksIpcInterfaceCode>(msgCode);
    if (code != HKS_MSG_UPDATE && code != HKS_MSG_FINISH && code != HKS_MSG_ABORT) {
        return 0;
    }
    const uint8_t *p = srcData.data;
    uint32_t remain = srcData.size;
    if (p == nullptr || remain < sizeof(uint32_t)) {
        return 0;
    }
    struct HksParamSet *wrapper = nullptr;
    if (HksGetParamSet(reinterpret_cast<const struct HksParamSet *>(p), remain, &wrapper) != HKS_SUCCESS) {
        return 0;
    }
    struct HksBlob param0 = { 0, nullptr };
    struct HksBlob param1 = { 0, nullptr };
    struct HksParamOut params[] = {
        { .tag = HKS_TAG_PARAM0_BUFFER, .blob = &param0 },
        { .tag = HKS_TAG_PARAM1_BUFFER, .blob = &param1 },
    };
    uint64_t handle = 0;
    do {
        if (HksParamSetToParams(wrapper, params, HKS_ARRAY_SIZE(params)) != HKS_SUCCESS) {
            break;
        }
        if (param1.data == nullptr || param1.size < sizeof(uint64_t)) {
            break;
        }
        (void)memcpy_s(&handle, sizeof(handle), param1.data, sizeof(uint64_t));
    } while (false);
    HksFreeParamSet(&wrapper);
    return handle;
}

// Submit-request parameter bundle (ukey async admission inputs): HksSubmitUkeyAsyncTask's
// original 6 parameters exceeded the "at most 5 function parameters" coding rule, so they are
// bundled into a struct (context is passed separately as the IPC-thread context).
struct HksUkeySubmitParams {
    uint32_t msgCode = 0;
    const struct HksParamSet *paramSet = nullptr;  // Unpacked embedded paramSet (for timeout parsing)
    struct HksBlob srcData = { 0, nullptr };       // Client-packed buffer (deep-copied at task construction)
    uint32_t outSize = 0;                          // Client-reported output buffer size
    sptr<IRemoteObject> clientStub;                // Client callback object (refcounted)
    std::string routingKey;                        // providerName for per-provider executor routing
    uint64_t handleAtSubmit = 0;                    // handle for FINISH/ABORT routing table cleanup
};

bool HksIsUkeyStandardMsgCode(uint32_t code, const struct HksBlob &srcData)
{
    if (code != HKS_MSG_GEN_KEY && code != HKS_MSG_EXPORT_PUBLIC_KEY &&
        code != HKS_MSG_IMPORT_WRAPPED_KEY && code != HKS_MSG_INIT && code != HKS_MSG_UPDATE &&
        code != HKS_MSG_FINISH && code != HKS_MSG_ABORT) {
        return false;
    }
    // Handle the srcData packing layout correctly ([uint32 len|blob(4-aligned)][paramSet(4-aligned)],
    // not a raw paramSet).
    struct HksParamSet *paramSet = UnpackParamSetFromSrcData(code, srcData);
    if (paramSet == nullptr) {
        HKS_LOG_E("ukey standard msg unpack fail, msgCode=%" LOG_PUBLIC "u size=%" LOG_PUBLIC "u -> not ukey",
            code, srcData.size);
        return false; // Parse failure is treated as non-ukey (falls back to the legacy path with the original error)
    }
    int32_t ukeyRet = 0;
    bool isUkey = (HksCheckIsUkeyOperation(paramSet, &ukeyRet) == HKS_SUCCESS);
    if (isUkey) {
        HKS_LOG_I("ukey standard msg, code=%" LOG_PUBLIC "u", code);
    }
    HksFreeParamSet(&paramSet);
    return isUkey;
}

// Unified reply helper: every failure path (pre-checks/deep-copy/Submit rejection) informs the
// client via the callback — the admission reply is always SUCCESS (the client does not read the
// admission reply content; if failures only went through the admission reply, the client would
// wait for a full timeout).
static int32_t RejectUkeyAsync(const sptr<IRemoteObject> &clientStub, uint32_t msgCode, int32_t err)
{
    auto extProxy = OHOS::iface_cast<OHOS::Security::Hks::IHksExtService>(clientStub);
    HKS_LOG_I("ukey submit reject, msgCode=%" LOG_PUBLIC "u err=%" LOG_PUBLIC "d proxy=%" LOG_PUBLIC "s",
        msgCode, err, (extProxy == nullptr) ? "null" : "ok");
    if (extProxy != nullptr) {
        std::unique_ptr<uint8_t[]> emptyData(nullptr); // empty output (size=0)
        extProxy->SendAsyncReply(static_cast<uint32_t>(err), emptyData, 0, msgCode, nullptr);
    }
    return HKS_SUCCESS;
}

// Submission-result handling: logs on acceptance (OK); rejections (BUSY/STOPPED/INVALID/SO
// unavailable) are replied immediately via the callback — the client does not wait.
static void HandleSubmitAccept(const sptr<IRemoteObject> &clientStub, uint32_t msgCode,
    uint32_t timeoutMs, int32_t acceptRaw)
{
    if (acceptRaw < 0) {
        RejectUkeyAsync(clientStub, msgCode, HKS_ERROR_BAD_STATE); // SO not loaded / executor unavailable
        return;
    }
    HksTaskAccept accept = static_cast<HksTaskAccept>(acceptRaw);
    if (accept == HksTaskAccept::OK) {
        // DFX logging: accepted + timeout value (the pending watermark is observed via thread-pool logs)
        HKS_LOG_I("ukey async task accepted, msgCode=%{public}u timeout=%{public}ums", msgCode, timeoutMs);
        return;
    }
    int32_t err = (accept == HksTaskAccept::BUSY) ? HUKS_ERR_CODE_BUSY
        : ((accept == HksTaskAccept::STOPPED) ? HKS_ERROR_BAD_STATE : HKS_ERROR_INTERNAL_ERROR);
    RejectUkeyAsync(clientStub, msgCode, err);
    HKS_LOG_E("Submit ukey task rejected, accept=%{public}d", static_cast<int>(accept));
}

// Permission pre-check: runs on the IPC thread before the SO/executor availability check so
static bool HksUkeyAsyncPreCheckPermission(uint32_t code, const struct HksParamSet *paramSet,
    const uint8_t *context, const sptr<IRemoteObject> &clientStub)
{
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("ukey pre-check get process info fail, code=%" LOG_PUBLIC "u ret=%" LOG_PUBLIC "d", code, ret);
        RejectUkeyAsync(clientStub, code, ret);
        return false;
    }

    if (paramSet != nullptr) {
        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("ukey pre-check across-accounts fail, code=%" LOG_PUBLIC "u ret=%" LOG_PUBLIC "d", code, ret);
            HKS_FREE_BLOB(processInfo.processName);
            HKS_FREE_BLOB(processInfo.userId);
            RejectUkeyAsync(clientStub, code, ret);
            return false;
        }
    }

    switch (code) {
        case HKS_MSG_EXT_AUTH_UKEY_PIN:
            ret = CheckUkeyAuthPinType();
            break;
        case HKS_MSG_EXT_EXPORT_PROVIDER_CERTIFICATES:
        case HKS_MSG_EXT_EXPORT_CERTIFICATE:
        case HKS_MSG_EXT_IMPORT_CERTIFICATE:
            ret = CheckUkeyCertCaller(&processInfo);
            break;
        default:
            ret = HKS_SUCCESS;
            break;
    }

    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("ukey pre-check permission fail, code=%" LOG_PUBLIC "u ret=%" LOG_PUBLIC "d", code, ret);
        HKS_FREE_BLOB(processInfo.processName);
        HKS_FREE_BLOB(processInfo.userId);
        RejectUkeyAsync(clientStub, code, ret);
        return false;
    }

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
    return true;
}

int32_t HksSubmitUkeyAsyncTask(const HksUkeySubmitParams &request, const uint8_t *context)
{
    // Thread-pool submission goes through the loader's lock-protected channel (Get+Submit inside
    // the libMutex critical section, preventing a dlclose race); the return value is the
    // HksTaskAccept enum (static_cast<int32_t>), -1 meaning the SO is not loaded / executor
    // unavailable.
    auto pluginLoader = OHOS::Security::Huks::HuksPluginLoader::GetInstanceWrapper();
    if (pluginLoader == nullptr) {
        return RejectUkeyAsync(request.clientStub, request.msgCode, HKS_ERROR_BAD_STATE);
    }

    // Pre-check: read the timeout (server-side independent validation, last line of defense) —
    // failures are replied via the callback.
    uint32_t timeoutMs = 0;
    int32_t ret = ParseTimeoutMs(request.msgCode, request.paramSet, &timeoutMs);
    if (ret != HKS_SUCCESS) {
        return RejectUkeyAsync(request.clientStub, request.msgCode, ret);
    }

    // Identity pre-check: IPCSkeleton is only valid on the IPC thread; build the processInfo
    // (HksGetProcessInfoForIPC reads the caller identity internally and deep-copies
    // processName/userId — released uniformly at task destruction). Capture the caller's full
    // tokenIDEx synchronously (on the worker thread IPCSkeleton falls back to the service's own
    // token, so token-type checks such as CheckUkeyAuthPinType must use this value).
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    ret = HksGetProcessInfoForIPC(request.paramSet, context, &processInfo); // resolve the real caller identity
    if (ret != HKS_SUCCESS) {
        return RejectUkeyAsync(request.clientStub, request.msgCode, ret);
    }
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    HKS_IF_TRUE_LOGE(fullTokenId == 0, "ukey submit calling full tokenId is zero, msgCode=%" LOG_PUBLIC "u",
        request.msgCode)

    // Inject the dispatch target via table lookup (single source of truth): extension codes +
    // reused standard single-arg codes -> MESSAGE_HANDLER table; three-stage codes -> THREE_STAGE
    // table. The task library does not depend on the IDL layer (function-pointer injection avoids
    // a circular dependency); the worker thread invokes it. SET_OR_GET_REMOTE_PROPERTY is not in
    // the async coverage set (excluded; it keeps its existing dedicated path).
    HksIpcHandlerFuncProc handler = HksFindMessageHandler(
        static_cast<enum HksIpcInterfaceCode>(request.msgCode));
    HksIpcThreeStageHandlerFuncProc threeStage = HksFindThreeStageHandler(
        static_cast<enum HksIpcInterfaceCode>(request.msgCode));
    if (handler == nullptr && threeStage == nullptr) {
        HKS_FREE_BLOB(processInfo.processName);
        HKS_FREE_BLOB(processInfo.userId);
        // Outside the coverage set (defensive).
        return RejectUkeyAsync(request.clientStub, request.msgCode, HKS_ERROR_INVALID_ARGUMENT);
    }

    // Assemble the task-construction parameters (constructor/factory originally took 10
    // parameters, over the 5-parameter rule -> bundled into a struct). processInfo/srcData are
    // shallow copies: the factory deep-copies them during construction and the original blobs
    // are released before this function returns, so there is no dangling.
    HksUkeyTaskParams taskParams;
    taskParams.msgCode = request.msgCode;
    taskParams.handler = handler;
    taskParams.threeStageHandler = threeStage;
    taskParams.processInfo = processInfo;
    taskParams.srcData = request.srcData;
    taskParams.timeoutMs = timeoutMs;
    taskParams.outSize = request.outSize;
    taskParams.fullTokenId = fullTokenId;
    taskParams.clientStub = request.clientStub;
    taskParams.routingKey = request.routingKey;
    taskParams.handleAtSubmit = request.handleAtSubmit;

    // Construct the task (the constructor deep-copies srcData + the processInfo embedded blobs;
    // on failure the processInfo is released).
    int32_t taskErr = HKS_SUCCESS;
    HksUkeyAsyncTask *rawTask = HksCreateUkeyAsyncTask(taskParams, &taskErr);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
    if (rawTask == nullptr) {
        return RejectUkeyAsync(request.clientStub, request.msgCode,
            taskErr != HKS_SUCCESS ? taskErr : HKS_ERROR_MALLOC_FAIL);
    }
    std::unique_ptr<HksAsyncTask> task(rawTask);

    // Submit (rejections BUSY/STOPPED/INVALID are all replied immediately via the callback —
    // the client does not wait). Per-provider routing: the routingKey (providerName) selects
    // the executor; empty routingKey falls back to the global executor.
    int32_t acceptRaw = pluginLoader->SubmitTaskExecutor(request.routingKey, std::move(task));
    HandleSubmitAccept(request.clientStub, request.msgCode, timeoutMs, acceptRaw);
    return HKS_SUCCESS; // admission receipt (always SUCCESS; the real result comes via the callback)
}

bool HksTrySubmitUkeyAsyncMsg(uint32_t code, MessageParcel &data, uint32_t outSize,
    const struct HksBlob &srcData, const uint8_t *context)
{
    // Two-mode decision: read the callback object — present -> async path; absent (legacy client)
    // -> legacy path. Note: this function is called only for codes in the ukey coverage set (the
    // caller has already done the message-code/KEY_CLASS decision) and must be invoked before the
    // legacy INIT block (otherwise the callback object would be consumed by the death-notification
    // logic).
    //
    // INIT special case: a sync INIT client writes a death-notification callback (HksStub) at the
    // same parcel position as the ukey async callback (HksExtStub). Reading it via
    // ReadRemoteObject() would consume the death-notification callback and misjudge it as an async
    // callback. To disambiguate, check the timeout tag before reading the callback: no tag → sync
    // client → return false without consuming the callback (the legacy INIT block reads it later).
    if (code == HKS_MSG_INIT) {
        struct HksParamSet *initParamSet = UnpackParamSetFromSrcData(code, srcData);
        bool hasTimeout = false;
        if (initParamSet != nullptr) {
            struct HksParam *timeoutParam = nullptr;
            hasTimeout = (HksGetParam(initParamSet, HksUkeyTimeoutTagByMsgCode(code), &timeoutParam)
                == HKS_SUCCESS);
        }
        HksFreeParamSet(&initParamSet);
        if (!hasTimeout) {
            HKS_LOG_I("ukey init sync path (no timeout tag), code=%" LOG_PUBLIC "u", code);
            return false; // sync INIT -> legacy path (callback not consumed)
        }
    }

    sptr<IRemoteObject> clientStub = data.ReadRemoteObject();
    if (clientStub == nullptr) {
        HKS_LOG_I("ukey try submit legacy path, code=%" LOG_PUBLIC "u (no callback object)", code);
        // Legacy client: no callback object written -> legacy sync path (the parcel
        // position is unconsumed; later logic reads no remote object).
        return false;
    }
    HKS_LOG_I("ukey try submit async path, code=%" LOG_PUBLIC "u", code);

    // Extract the embedded paramSet from the client-packed buffer (unpacked per code layout);
    // QUERY_ABILITY_INFO may leave paramSet == NULL when paramSetIn is NULL (no paramSet packed);
    // CLEAR_PIN_AUTH_STATE may also return NULL on parse failure. Both use default timeout and
    // identity through the thread context.
    struct HksParamSet *paramSet = UnpackParamSetFromSrcData(code, srcData);
    if (paramSet == nullptr && code != HKS_MSG_EXT_CLEAR_PIN_AUTH_STATE &&
        code != HKS_MSG_EXT_QUERY_ABILITY_INFO) {
        HKS_LOG_E("ukey try submit unpack paramSet null, code=%" LOG_PUBLIC "u -> reject", code);
        auto extProxy = OHOS::iface_cast<OHOS::Security::Hks::IHksExtService>(clientStub);
        if (extProxy != nullptr) {
            std::unique_ptr<uint8_t[]> emptyData(nullptr);
            extProxy->SendAsyncReply(HKS_ERROR_INVALID_ARGUMENT, emptyData, 0, code, nullptr);
        }
        // Request claimed: the error is replied via the callback; do not fall back to
        // the legacy path.
        return true;
    }
    if (!HksUkeyAsyncPreCheckPermission(code, paramSet, context, clientStub)) {
        HksFreeParamSet(&paramSet);
        return true;
    }
    HksUkeySubmitParams request;
    request.msgCode = code;
    request.paramSet = paramSet;
    request.srcData = srcData;
    request.outSize = outSize;
    request.clientStub = clientStub;
    request.routingKey = ExtractProviderName(code, srcData);
    request.handleAtSubmit = ExtractHandleFromSrcData(code, srcData);
    HksSubmitUkeyAsyncTask(request, context);
    HKS_LOG_I("ukey try submit done, code=%" LOG_PUBLIC "u (async accepted, reply via callback)", code);
    HksFreeParamSet(&paramSet);
    return true; // admitted (the async path is complete; the caller returns the admission receipt directly)
}

} // namespace Hks
} // namespace Security
} // namespace OHOS
#endif // HKS_UKEY_EXTENSION_CRYPTO
