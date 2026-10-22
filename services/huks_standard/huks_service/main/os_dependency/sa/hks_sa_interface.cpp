/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_sa_interface.h"

#include <errors.h>
#include <ipc_types.h>
#include <memory>
#include <mutex>
#include <securec.h>

#include "hks_dcm_callback_handler.h"
#include "hks_external_error_info.h"
#include "hks_log.h"
#include "hks_template.h"
#include "hks_type.h"
#include "huks_service_ipc_interface_code.h"
#include "hks_mem.h"

namespace OHOS {
namespace Security {
namespace Hks {

void HksStub::SendAsyncReply(uint32_t errCode, std::unique_ptr<uint8_t[]> &certChain, uint32_t sz)
{
    std::unique_lock<std::mutex> lck(mMutex);
    received = true;
    mErrCode = errCode;
    mAsyncReply = std::move(certChain);
    mSize = sz;
    mCv.notify_all();
}

int HksStub::ProcessAttestKeyAsyncReply(MessageParcel& data)
{
    std::unique_ptr<uint8_t[]> certChain{};
    uint32_t errCode = 1;
    if (!data.ReadUint32(errCode) || errCode != DCM_SUCCESS) {
        HKS_LOG_E("ipc client read errCode %" LOG_PUBLIC "u", errCode);
        SendAsyncReply(errCode, certChain, 0);
        return ERR_INVALID_DATA;
    }
    uint32_t certChainLen = 0;
    int err = ERR_INVALID_DATA;
    do {
        uint32_t sz = 0;
        HKS_IF_TRUE_LOGE_BREAK(!data.ReadUint32(sz) || sz == 0 || sz > MAX_OUT_BLOB_SIZE,
            "invalid sz %" LOG_PUBLIC "u", sz)
        const uint8_t *ptr = data.ReadBuffer(sz);
        HKS_IF_NULL_LOGE_BREAK(ptr, "ReadBuffer %" LOG_PUBLIC "u size ptr is nullptr", sz)
        auto receivedPtr = std::make_unique<uint8_t[]>(sz);
        if (receivedPtr == nullptr) {
            HKS_LOG_E("new receivedPtr failed");
            err = ERR_NO_MEMORY;
            break;
        }
        HKS_IF_NOT_EOK_LOGE_BREAK(memcpy_s(receivedPtr.get(), sz, ptr, sz), "memcpy_s receivedPtr failed");
        err = ERR_OK;
        certChain = std::move(receivedPtr);
        certChainLen = sz;
    } while (false);
    SendAsyncReply(errCode, certChain, certChainLen);
    return err;
}

int HksStub::OnRemoteRequest(uint32_t code,
    MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    HKS_IF_TRUE_LOGE_RETURN(data.ReadInterfaceToken() != GetDescriptor(), ERR_INVALID_DATA,
        "failed to check interface token! code %" LOG_PUBLIC "d", code)
    HKS_IF_TRUE_LOGE_RETURN(code != HKS_MSG_ATTEST_KEY_ASYNC_REPLY, ERR_TRANSACTION_FAILED,
        "unknown remote request code %" LOG_PUBLIC "u", code)
    return ProcessAttestKeyAsyncReply(data);
}

std::tuple<uint32_t, std::unique_ptr<uint8_t[]>, uint32_t> HksStub::WaitForAsyncReply(int timeout)
{
    std::unique_lock<std::mutex> lck(mMutex);
    if (received) {
        return {mErrCode, std::move(mAsyncReply), mSize};
    }
    mAsyncReply = nullptr;
    mSize = 0;
    mErrCode = DCM_SUCCESS;
    HKS_LOG_I("begin wait for async reply");
    if (mCv.wait_for(lck, std::chrono::seconds(timeout)) == std::cv_status::timeout) {
        HKS_LOG_E("WaitForAsyncReply timeout! %d seconds", timeout);
        return {HKS_ERROR_BAD_STATE, nullptr, 0};
    }
    return {mErrCode, std::move(mAsyncReply), mSize};
}

BrokerDelegator<HksProxy> HksProxy::delegator_;
HksProxy::HksProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IHksService>(impl)
{
}

void HksProxy::SendAsyncReply(uint32_t errCode, std::unique_ptr<uint8_t[]> &certChain, uint32_t sz)
{
    HKS_IF_NULL_LOGE_RETURN_VOID(Remote(), "Remote() is nullptr! Would not SendRequest!")
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = MessageOption::TF_ASYNC;
    bool writeResult = data.WriteInterfaceToken(GetDescriptor());
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult,
        "WriteInterfaceToken errCode %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d", errCode, writeResult)
    writeResult = data.WriteUint32(errCode);
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult, "WriteUint32 errCode %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d",
        errCode, writeResult)
    if (errCode != DCM_SUCCESS) {
        HKS_LOG_E("dcm callback fail errCode %" LOG_PUBLIC "u", errCode);
        int res = Remote()->SendRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
        HKS_IF_TRUE_LOGE(res != ERR_OK, "send fail reply errCode failed %" LOG_PUBLIC "d", res)
        return;
    }
    writeResult = data.WriteUint32(sz);
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult, "WriteUint32 sz %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d",
        sz, writeResult)
    if (sz == 0 || certChain == nullptr) {
        HKS_LOG_E("dcm reply success but empty certChain %" LOG_PUBLIC "u", sz);
        int res = Remote()->SendRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
        HKS_IF_TRUE_LOGE(res != ERR_OK,
            "Remote()->SendRequest HKS_MSG_ATTEST_KEY_ASYNC_REPLY failed %" LOG_PUBLIC "d", res)
        return;
    }
    writeResult = data.WriteBuffer(certChain.get(), sz);
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult, "WriteBuffer size %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d",
        sz, writeResult)
    int res = Remote()->SendRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    HKS_IF_TRUE_LOGE(res != ERR_OK,
        "Remote()->SendRequest HKS_MSG_ATTEST_KEY_ASYNC_REPLY failed %" LOG_PUBLIC "d", res)
}

HksExtStub::~HksExtStub()
{
    if (mErrInfo != nullptr) {
        HksFreeExternalErrorInfo(mErrInfo);
        mErrInfo = nullptr;
    }
}

void HksExtStub::SendAsyncReply(uint32_t errCode, std::unique_ptr<uint8_t[]> &sendData, uint32_t sendSize,
    uint32_t msgCode, const struct HksExternalErrorInfo *errInfo)
{
    HKS_LOG_I("ukey client stub got reply, msgCode=%{public}u errCode=%{public}u size=%{public}u",
        msgCode, errCode, sendSize);
    std::unique_lock<std::mutex> lck(mMutex);
    received = true;
    mErrCode = errCode;
    mMsgCode = msgCode;
    mAsyncReply = std::move(sendData);
    mSize = sendSize;
    if (mErrInfo != nullptr) {
        HksFreeExternalErrorInfo(mErrInfo);
        mErrInfo = nullptr;
    }
    HKS_IF_TRUE_EXCU(errInfo != nullptr,
        mErrInfo = HksCreateExternalErrorInfoWithFlag(errInfo->errVal, errInfo->errorDesc, errInfo->hasErrorInfo));
    mCv.notify_all();
}

// Unified reply success-path parsing (protocol: [errCode, size, data?, errVal, descLen,
// hasErrorInfo, desc]): size may be 0 (no-output operation); the server writes data with
// WriteBuffer and then 4-byte padding is added, so ReadUnpadBuffer must be used here to skip
// the padding, otherwise the subsequent errVal/descLen/hasErrorInfo parsing misaligns
static int32_t ReadAsyncReplyData(MessageParcel &data, std::unique_ptr<uint8_t[]> &receivedData,
    uint32_t &receivedSize)
{
    int err = ERR_OK;
    do {
        uint32_t size = 0;
        HKS_IF_TRUE_LOGE_BREAK(!data.ReadUint32(size) || size > MAX_OUT_BLOB_SIZE,
            "invalid size %" LOG_PUBLIC "u", size)
        if (size == 0) {
            break; // success with no output: valid
        }
        const uint8_t *ptr = data.ReadUnpadBuffer(size);
        HKS_IF_NULL_LOGE_BREAK(ptr, "ReadBuffer %" LOG_PUBLIC "u size ptr is nullptr", size)
        auto receivedPtr = std::make_unique<uint8_t[]>(size);
        if (receivedPtr == nullptr) {
            HKS_LOG_E("new receivedPtr failed");
            err = ERR_NO_MEMORY;
            break;
        }
        if (memcpy_s(receivedPtr.get(), size, ptr, size) != EOK) {
            HKS_LOG_E("memcpy_s receivedPtr failed");
            err = ERR_INVALID_DATA;
            break;
        }
        receivedData = std::move(receivedPtr);
        receivedSize = size;
    } while (false);
    return err;
}

int HksExtStub::ProcessAsyncReply(MessageParcel &data, uint32_t msgCode)
{
    // errCode = the real result code (passed through faithfully, error codes are not masked)
    HKS_LOG_I("ukey client ProcessAsyncReply begin, msgCode=%u", msgCode);
    uint32_t errCode = 1;
    if (!data.ReadUint32(errCode)) {
        HKS_LOG_E("ipc client read errCode failed");
        HKS_LOG_E("ukey client ProcessAsyncReply read errCode failed, msgCode=%u", msgCode);
        std::unique_ptr<uint8_t[]> emptyData(nullptr);
        SendAsyncReply(HKS_ERROR_IPC_MSG_FAIL, emptyData, 0, msgCode, nullptr);
        return ERR_INVALID_DATA;
    }
    HKS_LOG_I("ukey client ProcessAsyncReply got errCode=%u, msgCode=%u", errCode, msgCode);
    std::unique_ptr<uint8_t[]> receivedData{};
    uint32_t receivedSize = 0;
    int err = ERR_OK;
    if (errCode == HKS_SUCCESS) {
        err = ReadAsyncReplyData(data, receivedData, receivedSize);
    } else {
        // error path: no size/data fields (the server writes errInfo directly on error)
        err = ERR_INVALID_DATA;
    }

    // error-detail parsing (errInfo is parsed on the error path as well)
    int32_t errVal = 0;
    HKS_IF_TRUE_EXCU(!data.ReadInt32(errVal), errVal = static_cast<int32_t>(errCode));
    uint32_t descLen = 0;
    bool hasErrorInfo = false;
    HKS_IF_TRUE_EXCU(!data.ReadUint32(descLen), descLen = 0);
    HKS_IF_TRUE_EXCU(!data.ReadBool(hasErrorInfo), hasErrorInfo = false);
    char *errorDesc = nullptr;
    if (descLen > 0 && descLen < MAX_ERROR_MESSAGE_LEN) {
        const char *descPtr = reinterpret_cast<const char *>(data.ReadBuffer(descLen));
        if (descPtr != nullptr) {
            errorDesc = reinterpret_cast<char *>(HksMalloc(descLen + 1));
            HKS_IF_TRUE_EXCU(errorDesc != nullptr && memcpy_s(errorDesc, descLen + 1, descPtr, descLen) == EOK,
                errorDesc[descLen] = '\0');
        }
    }
    struct HksExternalErrorInfo errInfo = {errVal, errorDesc, descLen, hasErrorInfo};
    // wire code = the original request code, stored and passed through (the client uses
    // receivedCode == the code it sent to guard against cross-talk)
    SendAsyncReply(errCode, receivedData, receivedSize, msgCode, &errInfo);
    HKS_IF_TRUE_EXCU(errorDesc != nullptr, HKS_FREE(errorDesc));
    return err;
}

auto HksExtStub::WaitForAsyncReply(int timeout)
    -> std::tuple<uint32_t, std::unique_ptr<uint8_t[]>, uint32_t, uint32_t, HksExternalErrorInfo*>
{
    std::unique_lock<std::mutex> lck(mMutex);
    if (received) {
        struct HksExternalErrorInfo *errInfo = mErrInfo;
        mErrInfo = nullptr;
        return {mErrCode, std::move(mAsyncReply), mSize, mMsgCode, errInfo};
    }
    mAsyncReply = nullptr;
    mSize = 0;
    mMsgCode = 0;
    mErrCode = HKS_SUCCESS;
    if (mErrInfo != nullptr) {
        HksFreeExternalErrorInfo(mErrInfo);
        mErrInfo = nullptr;
    }
    HKS_LOG_I("begin wait for async reply");
    if (mCv.wait_for(lck, std::chrono::seconds(timeout)) == std::cv_status::timeout) {
        HKS_LOG_E("WaitForAsyncReply timeout! %" LOG_PUBLIC "u seconds", timeout);
        return {HKS_ERROR_BAD_STATE, nullptr, 0, 0, nullptr};
    }
    struct HksExternalErrorInfo *errInfo = mErrInfo;
    mErrInfo = nullptr;
    return {mErrCode, std::move(mAsyncReply), mSize, mMsgCode, errInfo};
}

int HksExtStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    (void)reply;
    (void)option;
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        HKS_LOG_E("ukey client OnRemoteRequest token mismatch, code=%u -> drop reply", code);
        return ERR_INVALID_DATA;
    }
    // ukey async refactor: coverage set = 11 ukey-native extension codes + 7 reused standard
    // codes (wire code = the original request code, unified delivery protocol) + the legacy 42
    // (transition-period compatibility with old servers)
    switch (code) {
        case HKS_MSG_GEN_KEY:
        case HKS_MSG_EXPORT_PUBLIC_KEY:
        case HKS_MSG_IMPORT_WRAPPED_KEY:
        case HKS_MSG_INIT:
        case HKS_MSG_UPDATE:
        case HKS_MSG_FINISH:
        case HKS_MSG_ABORT:
        case HKS_MSG_EXT_AUTH_UKEY_PIN:
        case HKS_MSG_EXT_GET_UKEY_PIN_AUTH_STATE:
        case HKS_MSG_EXT_OPEN_REMOTE_HANDLE:
        case HKS_MSG_EXT_CLOSE_REMOTE_HANDLE:
        case HKS_MSG_EXT_CLEAR_PIN_AUTH_STATE:
        case HKS_MSG_EXT_EXPORT_PROVIDER_CERTIFICATES:
        case HKS_MSG_EXT_EXPORT_CERTIFICATE:
        case HKS_MSG_EXT_IMPORT_CERTIFICATE:
        case HKS_MSG_EXT_QUERY_ABILITY_INFO:
        case HKS_MSG_EXT_GET_RESOURCE_ID:
        case HKS_MSG_EXT_SET_OR_GET_REMOTE_PROPERTY_REPLY: // legacy compat: SET_OR_GET replies with code 42
            return ProcessAsyncReply(data, code);
        default:
            HKS_LOG_E("OnRemoteRequest unexpected code %" LOG_PUBLIC "u", code);
            return ERR_TRANSACTION_FAILED;
    }
}

BrokerDelegator<HksExtProxy> HksExtProxy::delegator_;
HksExtProxy::HksExtProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IHksExtService>(impl)
{
}

void HksExtProxy::WriteErrorInfoToParcel(MessageParcel &data, const struct HksExternalErrorInfo *errInfo)
{
    int32_t errVal = (errInfo != nullptr) ? errInfo->errVal : 0;
    uint32_t descLen = (errInfo != nullptr && errInfo->errorDesc != nullptr) ? errInfo->errorDescLen : 0;
    const char *errorDesc = (errInfo != nullptr && errInfo->errorDesc != nullptr) ? errInfo->errorDesc : "";
    bool hasErrorInfo = (errInfo != nullptr) ? errInfo->hasErrorInfo : false;

    bool writeResult = data.WriteInt32(errVal);
    HKS_IF_NOT_TRUE_LOGE(writeResult, "WriteInt32 errVal %" LOG_PUBLIC "d failed", errVal)
    writeResult = data.WriteUint32(descLen);
    HKS_IF_NOT_TRUE_LOGE(writeResult, "WriteUint32 descLen %" LOG_PUBLIC "u failed", descLen)
    writeResult = data.WriteBool(hasErrorInfo);
    HKS_IF_NOT_TRUE_LOGE(writeResult, "WriteBool hasErrorInfo failed")
    HKS_IF_TRUE_RETURN_VOID(descLen <= 0 || descLen >= MAX_ERROR_MESSAGE_LEN)
    writeResult = data.WriteBuffer(errorDesc, descLen);
    HKS_IF_NOT_TRUE_LOGE(writeResult, "WriteBuffer errorDesc failed")
}

void HksExtProxy::SendAsyncReply(uint32_t errCode, std::unique_ptr<uint8_t[]> &sendData, uint32_t sendSize,
    uint32_t msgCode, const struct HksExternalErrorInfo *errInfo)
{
    HKS_IF_NULL_LOGE_RETURN_VOID(Remote(), "Remote() is nullptr! Would not SendRequest!")
    HKS_LOG_I("ukey SendAsyncReply begin, msgCode=%{public}u errCode=%{public}u sendSize=%{public}u",
        msgCode, errCode, sendSize);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = MessageOption::TF_ASYNC;
    do {
        bool writeResult = data.WriteInterfaceToken(GetDescriptor());
        HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult,
            "WriteInterfaceToken errCode %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d", errCode, writeResult)
        writeResult = data.WriteUint32(errCode);
        HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult, "WriteUint32 errCode %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d",
            errCode, writeResult)

        HKS_IF_TRUE_LOGE_BREAK(errCode != HKS_SUCCESS, "ukey callback fail errCode %" LOG_PUBLIC "u", errCode)
        // unified protocol: the success path always writes the size field (0 is valid — a
        // no-output operation), and the data buffer is written only when size>0; the client's
        // ProcessAsyncReply success path unconditionally reads size, so both ends align
        writeResult = data.WriteUint32(sendSize);
        HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult, "WriteUint32 sendSize %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d",
            sendSize, writeResult)

        if (sendSize == 0 || sendData == nullptr) {
            break; // success with no output data: valid protocol terminal state (the error-info
                   // fields are still written)
        }
        writeResult = data.WriteBuffer(sendData.get(), sendSize);
        HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult, "WriteBuffer size %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d",
            sendSize, writeResult)
    } while (0);

    WriteErrorInfoToParcel(data, errInfo);
    int res = Remote()->SendRequest(msgCode, data, reply, option);
    HKS_IF_TRUE_LOGE(res != ERR_OK, "Remote()->SendRequest failed %" LOG_PUBLIC "d", res)
    HKS_LOG_I("ukey SendAsyncReply done, msgCode=%{public}u errCode=%{public}u res=%{public}d",
        msgCode, errCode, res);
}

} // namespace Hks
} // namespace Security
} // namespace OHOS
 