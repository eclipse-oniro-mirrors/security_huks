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

#include "hks_response.h"

#include <cinttypes>
#include <dlfcn.h>
#include <securec.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "hks_at_api_wrap.h"
#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#ifdef HKS_SUPPORT_ACCESS_TOKEN
#include "accesstoken_kit.h"
#endif
#include "ipc_skeleton.h"

#include "hks_base_check.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type_inner.h"
#include "hks_util.h"
#include "hks_external_error_info.h"

#include "hap_token_info.h"
#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
#include "hks_bms_api_wrap.h"
#endif

#ifdef HAS_OS_ACCOUNT_PART
#include "os_account_manager.h"
#endif // HAS_OS_ACCOUNT_PART

using namespace OHOS;
#ifndef HAS_OS_ACCOUNT_PART
constexpr static int UID_TRANSFORM_DIVISOR = 200000;
#endif // HAS_OS_ACCOUNT_PART
int HksGetOsAccountIdFromUid(int uid)
{
#ifdef HAS_OS_ACCOUNT_PART
    int accountId = 0;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, accountId);
    return accountId;
#else // HAS_OS_ACCOUNT_PART
    return uid / UID_TRANSFORM_DIVISOR;
#endif // HAS_OS_ACCOUNT_PART
}

// ukey async refactor: thread-local async result slot (see the comment in hks_response.h)
static __thread struct HksAsyncResultSlot g_asyncResultSlot = { false, false, 0, { 0, nullptr } };

void HksAsyncResultSlotSetEnabled(bool enabled)
{
    if (enabled) {
        // new task begins: clear the previous task's residue (Take already resets on the normal
        // path; this is a defensive extra clear)
        if (g_asyncResultSlot.captured && g_asyncResultSlot.response.data != nullptr) {
            HKS_FREE_BLOB(g_asyncResultSlot.response);
        }
        g_asyncResultSlot.captured = false;
        g_asyncResultSlot.result = 0;
        g_asyncResultSlot.response.size = 0;
        g_asyncResultSlot.response.data = nullptr;
    }
    g_asyncResultSlot.enabled = enabled;
}

void HksAsyncResultSlotTake(int32_t *result, struct HksBlob *response)
{
    if (result != nullptr) {
        *result = g_asyncResultSlot.result;
    }
    if (response != nullptr) {
        *response = g_asyncResultSlot.response; // ownership transfer
    }
    // reset (response ownership has been transferred to the caller; nothing is released here)
    g_asyncResultSlot.captured = false;
    g_asyncResultSlot.enabled = false;
    g_asyncResultSlot.result = 0;
    g_asyncResultSlot.response.size = 0;
    g_asyncResultSlot.response.data = nullptr;
}

// sync path: writes the result into the IPC reply parcel (context is non-null, reachable only
// on the IPC thread)
static void HksWriteResponseToParcel(MessageParcel *reply, int32_t result, const struct HksBlob *response)
{
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteInt32(result), "reply->WriteInt32(result) failed");

    if (response == nullptr) {
        HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteUint32(0), "reply->WriteUint32(0) failed");
    } else {
        HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteUint32(response->size),
            "reply->WriteUint32(response->size) failed");
        HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteBuffer(response->data, static_cast<size_t>(response->size)),
            "reply->WriteBuffer failed");
    }
#ifdef L2_STANDARD
    uint32_t msgLen = HksGetThreadErrorMsgLen();
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteUint32(msgLen), "reply->WriteUint32(msgLen) failed");

    if (msgLen != 0) {
        const char *msg = HksGetThreadErrorMsg();
        if (!reply->WriteBuffer(msg, static_cast<size_t>(msgLen))) {
            HKS_LOG_E("WriteBuffer for errMsg fail!");
            return;
        }
    }

    const struct HksExternalErrorInfo *errInfo = HksGetThreadExtErrMsg();
    int32_t errVal = (errInfo != nullptr) ? errInfo->errVal : 0;
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteInt32(errVal), "WriteInt32 errVal failed");
    uint32_t descLen = (errInfo != nullptr && errInfo->errorDesc != nullptr) ? errInfo->errorDescLen + 1 : 0;
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteUint32(descLen), "WriteUint32 descLen failed");
    bool hasErrorInfo = (errInfo != nullptr) ? errInfo->hasErrorInfo : false;
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(reply->WriteBool(hasErrorInfo), "WriteBool hasErrorInfo failed");
    if (descLen != 0 && errInfo->errorDesc != nullptr) {
        if (!reply->WriteBuffer(errInfo->errorDesc, descLen)) {
            HKS_LOG_E("WriteBuffer errorDesc failed");
            return;
        }
    }
    HksClearThreadExtErrMsg();
#endif
}

// ukey async refactor: captures the worker thread's business-final result into the thread-local
// slot (the HksSendResponse null-context branch). The first capture wins: HksIpcServiceXxx may
// be called multiple times internally, so the first complete answer is taken; empty output does
// not write slot data (the slot keeps data=nullptr/size=0, consistent with HksAsyncResultSlotTake)
static void HksCaptureAsyncResult(int32_t result, const struct HksBlob *response)
{
    if (g_asyncResultSlot.captured) {
        return;
    }
    g_asyncResultSlot.captured = true;
    g_asyncResultSlot.result = result;
    if (response == nullptr || response->data == nullptr || response->size == 0) {
        return;
    }
    uint8_t *buf = static_cast<uint8_t *>(HksMalloc(response->size));
    if (buf == nullptr) {
        HKS_LOG_E("async result slot malloc fail, size=%" LOG_PUBLIC "u", response->size);
        return;
    }
    (void)memcpy_s(buf, response->size, response->data, response->size);
    g_asyncResultSlot.response.data = buf;
    g_asyncResultSlot.response.size = response->size;
}

void HksSendResponse(const uint8_t *context, int32_t result, const struct HksBlob *response)
{
    // ukey async refactor: when a worker thread runs the task, context is null — the result is
    // written into the thread-local slot instead of a parcel (the first capture wins: the
    // business-final first complete answer)
    if (context == nullptr) {
        if (g_asyncResultSlot.enabled) {
            HksCaptureAsyncResult(result, response);
        }
        return;
    }

    MessageParcel *reply = const_cast<MessageParcel *>(reinterpret_cast<const MessageParcel *>(context));
    HksWriteResponseToParcel(reply, result, response);
}

static int32_t GetUidAndUserId(const struct HksParamSet *paramSet, int &uid, int &userId)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    uid = callingUid;
    userId = HksGetOsAccountIdFromUid(callingUid);
    HKS_IF_NULL_RETURN(paramSet, HKS_SUCCESS)

    struct HksParam *ancoUidParam = nullptr;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ANCO_APP_UID, &ancoUidParam);
    if (callingUid == HKS_ANCO_BROKER_UID) {
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get HKS_TAG_ANCO_APP_UID failed, ret: %" LOG_PUBLIC "d", ret)
        HKS_IF_NOT_TRUE_LOGE_RETURN(ancoUidParam->blob.size == sizeof(int), HKS_ERROR_NEW_INVALID_ARGUMENT,
            "uid size should be sizeof(int)")
        // get anco user id
        struct HksParam *ancoUserIdParam = nullptr;
        ret = HksGetParam(paramSet, HKS_TAG_ANCO_USER_ID, &ancoUserIdParam);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get HKS_TAG_ANCO_USER_ID failed, ret: %" LOG_PUBLIC "d", ret)

        uid = *(int *)(ancoUidParam->blob.data);
        userId = static_cast<int>(ancoUserIdParam->uint32Param);
    } else {
        HKS_IF_TRUE_LOGE_RETURN(ret != HKS_ERROR_PARAM_NOT_EXIST, HKS_ERROR_NEW_INVALID_ARGUMENT,
            "not allowed to add anco tag for non-broker invoker, processName: %" LOG_PUBLIC "d", callingUid)
    }
    return HKS_SUCCESS;
}

// ukey async refactor: thread-local identity slot — when a worker thread runs a task, the task
// already carries the caller identity resolved in advance by the IPC thread (deep-copied);
// HksGetProcessInfoForIPC copies the identity from this slot when it detects the thread slot is
// online (the worker has no IPC context, so IPCSkeleton's thread-local is untrustworthy here)
static __thread const struct HksProcessInfo *g_threadIdentityOverride = nullptr;

// the caller's full tokenIDEx when a worker thread runs the task (captured and injected by the
// IPC thread on admission); 0 = not injected
static __thread uint64_t g_threadFullTokenIdOverride = 0;

void HksSetThreadFullTokenIdOverride(uint64_t fullTokenId)
{
    g_threadFullTokenIdOverride = fullTokenId;
}

uint64_t HksGetThreadFullTokenIdOverride()
{
    return g_threadFullTokenIdOverride;
}

void HksSetThreadIdentityOverride(const struct HksProcessInfo *processInfo)
{
    g_threadIdentityOverride = processInfo;
}

const struct HksProcessInfo *HksGetThreadIdentityOverride()
{
    return g_threadIdentityOverride;
}

// worker thread (during task execution): deep-copies the identity held by the task (malloc
// semantics match the IPC path below; the caller releases it with HKS_FREE_BLOB)
static int32_t HksGetProcessInfoFromThreadSlot(struct HksProcessInfo *processInfo)
{
    const struct HksProcessInfo *src = g_threadIdentityOverride;
    uint32_t uidLen = sizeof(int);
    uint8_t *uidName = static_cast<uint8_t *>(HksMalloc(uidLen));
    uint8_t *userName = nullptr;
    if (uidName == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(uidName, uidLen, src->processName.data, uidLen);
    uint32_t userSize = src->userId.size;
    userName = static_cast<uint8_t *>(HksMalloc(userSize > 0 ? userSize : 1));
    if (userName == nullptr) {
        HKS_FREE(uidName);
        return HKS_ERROR_MALLOC_FAIL;
    }
    if (userSize > 0) {
        (void)memcpy_s(userName, userSize, src->userId.data, userSize);
    }
    processInfo->processName.size = uidLen;
    processInfo->processName.data = uidName;
    processInfo->uidInt = src->uidInt;
    processInfo->userId.size = userSize;
    processInfo->userId.data = userName;
    processInfo->userIdInt = src->userIdInt;
    processInfo->accessTokenId = src->accessTokenId;
    processInfo->pid = src->pid;
    return HKS_SUCCESS;
}

// IPC thread: resolves the caller identity from IPCSkeleton (sync path; malloc semantics match
// the thread-slot path)
static int32_t HksGetProcessInfoFromIpc(const struct HksParamSet *paramSet, struct HksProcessInfo *processInfo)
{
    int uid = -1;
    int userId = -1;
    int32_t ret = GetUidAndUserId(paramSet, uid, userId);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get uid or user id failed")

    uint8_t *uidName = nullptr;
    uint8_t *userName = nullptr;
    uint32_t size = 0;
    ret = HKS_ERROR_MALLOC_FAIL;
    do {
        uidName = static_cast<uint8_t *>(HksMalloc(sizeof(uid)));
        HKS_IF_NULL_LOGE_BREAK(uidName, "malloc uid failed")

        size = userId == 0 ? strlen("0") : sizeof(userId);
        userName = static_cast<uint8_t *>(HksMalloc(size));
        HKS_IF_NULL_LOGE_BREAK(userName, "malloc userId failed")

        (void)memcpy_s(uidName, sizeof(uid), &uid, sizeof(uid));
        processInfo->processName.size = sizeof(uid);
        processInfo->processName.data = uidName;
        processInfo->uidInt = static_cast<uint32_t>(uid);

        if (userId == 0) {
            (void)memcpy_s(userName, size, "0", size); /* ignore \0 at the end */
        } else {
            (void)memcpy_s(userName, size, &userId, size);
        }

        processInfo->userId.size = size;
        processInfo->userId.data = userName;
        processInfo->userIdInt = userId;

#ifdef HKS_SUPPORT_ACCESS_TOKEN
        processInfo->accessTokenId = static_cast<uint64_t>(IPCSkeleton::GetCallingTokenID());
        HKS_IF_TRUE_LOGE(processInfo->accessTokenId == 0, "accessTokenId is zero")
#endif
        processInfo->pid = static_cast<int32_t>(IPCSkeleton::GetCallingPid());
        HKS_IF_TRUE_LOGE(processInfo->pid == 0, "GetCallingPID is zero")
        return HKS_SUCCESS;
    } while (0);

    HKS_FREE(uidName);
    HKS_FREE(userName);
    processInfo->processName.data = nullptr;
    return ret;
}

int32_t HksGetProcessInfoForIPC(const struct HksParamSet *paramSet,
    const uint8_t *context, struct HksProcessInfo *processInfo)
{
    HKS_IF_NULL_RETURN(processInfo, HKS_SUCCESS);
    // worker thread (during task execution): the identity slot is online (the task holds the
    // caller identity resolved in advance by the IPC thread). This function only transfers
    // pointer ownership to the out-param — malloc semantics match the IPC path below; the
    // caller releases it with HKS_FREE_BLOB
    if (g_threadIdentityOverride != nullptr) {
        return HksGetProcessInfoFromThreadSlot(processInfo);
    }
    HKS_IF_NULL_RETURN(context, HKS_SUCCESS);
    return HksGetProcessInfoFromIpc(paramSet, processInfo);
}

int32_t HksCheckIsFrontUser(int32_t userId, bool *isFrontUser)
{
#ifdef HAS_OS_ACCOUNT_PART
    int32_t ret = OHOS::AccountSA::OsAccountManager::IsOsAccountForeground(userId, *isFrontUser);
    HKS_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "IsOsAccountForeground failed, errCode: %" LOG_PUBLIC "d", ret)
    return HKS_SUCCESS;
#else
    (void)userId;
    *isFrontUser = false;
    return HKS_SUCCESS;
#endif
}

int32_t HksGetRelatedFrontUserId(const struct HksParamSet *paramSet, int32_t ipcCallerUserId, int32_t *outId)
{
#ifdef HAS_OS_ACCOUNT_PART
    if (ipcCallerUserId >= HKS_ROOT_USER_UPPERBOUND) {
        // a normal app returns the userid it belongs to
        *outId = ipcCallerUserId;
        return HKS_SUCCESS;
    }
    const static int32_t INVALID_USER_ID = -1;
    struct HksParam *specificUserId = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_SPECIFIC_USER_ID, &specificUserId);
    if (ret == HKS_SUCCESS) {
        *outId = specificUserId->int32Param;
        return HKS_SUCCESS;
    } else if (ret == HKS_ERROR_PARAM_NOT_EXIST) {
        // a system app returns the logical home-screen userid by default when it does not
        // specify a userid
        int32_t localId = INVALID_USER_ID;
        ret = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(localId);
        HKS_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret,
            "GetForegroundOsAccountLocalId fail, errCode : %" LOG_PUBLIC "d", ret)
        *outId = localId;
        HKS_LOG_I("HksGetRelatedFrontUserId: return front userid: %" LOG_PUBLIC "d", *outId);
        return HKS_SUCCESS;
    }
    HKS_LOG_E("HksGetRelatedFrontUserId HksGetParam fail, ret : %" LOG_PUBLIC "d", ret);
    return ret;
#else // HAS_OS_ACCOUNT_PART
    *outId = -1;
    HKS_LOG_I("QueryActiveOsAccountIds, no os account part, set FrontUserId= -1");
#endif // HAS_OS_ACCOUNT_PART

    return HKS_SUCCESS;
}
