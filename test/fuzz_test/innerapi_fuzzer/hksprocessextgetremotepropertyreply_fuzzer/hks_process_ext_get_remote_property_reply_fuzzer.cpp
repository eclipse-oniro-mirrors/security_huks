/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hks_process_ext_get_remote_property_reply_fuzzer.h"

#include <algorithm>
#include <vector>

#include "hks_external_error_info.h"
#include "hks_fuzz_util.h"
#include "hks_sa_interface.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "huks_service_ipc_interface_code.h"

namespace OHOS {
namespace Security {
namespace Hks {

static const std::u16string HKS_EXT_SERVICE_DESCRIPTOR = u"ohos.security.hksext.service";

static int32_t SendExtGetRemotePropertyReply(const sptr<HksExtStub> &stub, uint32_t errCode, uint32_t dataSize,
    const std::vector<uint8_t> &dataBuf, int32_t errVal, uint32_t descLen, bool hasErrorInfo,
    const std::vector<uint8_t> &descBuf)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption optionAsync = MessageOption::TF_ASYNC;

    (void)dataParcel.WriteInterfaceToken(HKS_EXT_SERVICE_DESCRIPTOR);
    (void)dataParcel.WriteUint32(errCode);
    if (errCode == HKS_SUCCESS) {
        (void)dataParcel.WriteUint32(dataSize);
        if (!dataBuf.empty()) {
            (void)dataParcel.WriteBuffer(dataBuf.data(), dataBuf.size());
        }
    }
    (void)dataParcel.WriteInt32(errVal);
    (void)dataParcel.WriteUint32(descLen);
    (void)dataParcel.WriteBool(hasErrorInfo);
    if (!descBuf.empty()) {
        (void)dataParcel.WriteBuffer(descBuf.data(), descBuf.size());
    }
    return stub->OnRemoteRequest(HKS_MSG_EXT_SET_OR_GET_REMOTE_PROPERTY_REPLY, dataParcel, replyParcel, optionAsync);
}

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    sptr<HksExtStub> extStub = new (std::nothrow) HksExtStub();
    if (extStub == nullptr) {
        return HKS_ERROR_NULL_POINTER;
    }

    uint32_t errCode = HKS_SUCCESS;
    if (fdp.ConsumeIntegralInRange<uint32_t>(0, 7) == 0) {
        errCode = fdp.ConsumeIntegral<uint32_t>();
    }
    uint32_t dataSize = fdp.ConsumeIntegralInRange<uint32_t>(0, MAX_OUT_BLOB_SIZE + 1);
    int32_t errVal = fdp.ConsumeIntegral<int32_t>();
    uint32_t descLen = fdp.ConsumeIntegralInRange<uint32_t>(0, MAX_ERROR_MESSAGE_LEN + 1);
    bool hasErrorInfo = fdp.ConsumeBool();

    std::vector<uint8_t> rawBuf = fdp.ConsumeRemainingBytes<uint8_t>();
    uint32_t dataWritten = std::min(dataSize, static_cast<uint32_t>(rawBuf.size()));
    std::vector<uint8_t> dataBuf(rawBuf.begin(), rawBuf.begin() + dataWritten);
    std::vector<uint8_t> descBuf(rawBuf.begin() + dataWritten, rawBuf.end());

    int32_t ret = SendExtGetRemotePropertyReply(extStub, errCode, dataSize, dataBuf, errVal, descLen, hasErrorInfo,
        descBuf);

    const std::vector<uint8_t> fixedDesc = { 'f', 'u', 'z', 'z', '-', 'd', 'e', 's', 'c' };
    (void)SendExtGetRemotePropertyReply(extStub, HKS_SUCCESS, 0, {}, 0, static_cast<uint32_t>(fixedDesc.size()),
        true, fixedDesc);

    auto asyncReply = extStub->WaitForAsyncReply(0);
    HksFreeExternalErrorInfo(std::get<4>(asyncReply));
    return ret;
}
}}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);
    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}
