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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_async_stub.h"

#include <cstdint>
#include <errors.h>
#include <ipc_types.h>
#include <memory>
#include <new>
#include <securec.h>

#include "hks_client_ipc_serialization.h"
#include "hks_cfi.h"
#include "hks_dcm_callback_handler.h"
#include "hks_ipc_serialization.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type.h"
#include "huks_service_ipc_interface_code.h"

/* upper bound of the PEM headers ("-----BEGIN CERTIFICATE-----\n" + "\n-----END CERTIFICATE-----")
 * plus slack, used to size the in-place base64 encoding buffer */
constexpr uint32_t ASYNC_STUB_BASE64_MARGIN = 64;

namespace OHOS {
namespace Security {
namespace Hks {

HksAsyncStub::HksAsyncStub(HksAsyncAnonAttestCallback callback, void *userData, bool needBase64)
    : mCallback(callback), mUserData(userData), mNeedBase64(needBase64)
{
}

void HksAsyncStub::SendAsyncReply(uint32_t errCode, std::unique_ptr<uint8_t[]> &certChain, uint32_t sz)
{
    /* direct dispatch variant for in-process callers; the IPC entry is OnRemoteRequest */
    InvokeCallback(errCode, certChain.get(), sz);
}

int HksAsyncStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    HKS_IF_TRUE_LOGE_RETURN(data.ReadInterfaceToken() != GetDescriptor(), ERR_INVALID_DATA,
        "failed to check interface token! code %" LOG_PUBLIC "u", code)
    HKS_IF_TRUE_LOGE_RETURN(code != HKS_MSG_ATTEST_KEY_ASYNC_REPLY, ERR_TRANSACTION_FAILED,
        "unknown remote request code %" LOG_PUBLIC "u", code)
    return ProcessAttestKeyAsyncReply(data);
}

int HksAsyncStub::ProcessAttestKeyAsyncReply(MessageParcel &data)
{
    uint32_t errCode = static_cast<uint32_t>(HKS_ERROR_IPC_MSG_FAIL);
    if (!data.ReadUint32(errCode) || errCode != HKS_SUCCESS) {
        HKS_LOG_E("async stub read errCode %" LOG_PUBLIC "u", errCode);
        InvokeCallback(errCode, nullptr, 0);
        return ERR_INVALID_DATA;
    }

    /* the service never reports success without a cert chain; a malformed success reply is
     * surfaced to the callback as an IPC failure instead of a bogus success */
    uint32_t sz = 0;
    if (!data.ReadUint32(sz) || sz == 0 || sz > MAX_OUT_BLOB_SIZE) {
        HKS_LOG_E("async stub invalid sz %" LOG_PUBLIC "u", sz);
        InvokeCallback(HKS_ERROR_IPC_MSG_FAIL, nullptr, 0);
        return ERR_INVALID_DATA;
    }
    const uint8_t *ptr = data.ReadBuffer(sz);
    if (ptr == nullptr) {
        HKS_LOG_E("async stub ReadBuffer %" LOG_PUBLIC "u ptr is nullptr", sz);
        InvokeCallback(HKS_ERROR_IPC_MSG_FAIL, nullptr, 0);
        return ERR_INVALID_DATA;
    }

    InvokeCallback(errCode, ptr, sz);
    return ERR_OK;
}

/* the user callback lives in non-CFI-instrumented code (app or test), so the indirect call
 * below must skip the cfi check - same treatment as the dlsym'd DCM entry points */
ENABLE_CFI(void HksAsyncStub::InvokeCallback(uint32_t errCode, const uint8_t *packedCertChain, uint32_t sz))
{
    int32_t result = static_cast<int32_t>(errCode);
    /* RAII: whatever was built below is wiped and released on every exit path, so no
     * per-branch HksFreeAnonAttestCertChain is needed */
    auto freeCertChain = [](struct HksCertChain *chain) { HksFreeAnonAttestCertChain(&chain); };
    std::unique_ptr<struct HksCertChain, decltype(freeCertChain)> certChain(nullptr, freeCertChain);
    if (errCode == HKS_SUCCESS && (packedCertChain == nullptr || sz == 0)) {
        /* defensive: success without a payload is a malformed reply, never report it as ok */
        result = HKS_ERROR_IPC_MSG_FAIL;
    } else if (errCode == HKS_SUCCESS) {
        struct HksBlob packedBlob = { sz, const_cast<uint8_t *>(packedCertChain) };
        struct HksCertChain *unpacked = nullptr;
        result = HksUnpackAnonAttestCertChainToNew(&packedBlob, mNeedBase64, &unpacked);
        if (result != HKS_SUCCESS) {
            HKS_LOG_E("async stub unpack cert chain fail, ret = %" LOG_PUBLIC "d", result);
        } else {
            certChain.reset(unpacked);
        }
    }
    HKS_LOG_I("async anon attest callback dispatch, result = %" LOG_PUBLIC "d", result);
    if (mCallback != nullptr) {
        mCallback(mUserData, result, certChain.get());
    }
    /* the cert chain is only valid during the callback; wipe and release it right after */
    HKS_LOG_I("async anon attest callback done");
}

} // namespace Hks
} // namespace Security
} // namespace OHOS

#ifdef __cplusplus
extern "C" {
#endif

/* read one cert from the packed buffer at *offset and store it in cert: the raw bytes are
 * copied into a newly allocated buffer sized to also fit the optional in-place base64(PEM)
 * encoding, which is applied right after the copy */
static int32_t CopyAndEncodeOneCert(const struct HksBlob *srcData, uint32_t *offset, bool needEncode,
    struct HksBlob *cert)
{
    struct HksBlob tmp = { 0, nullptr };
    int32_t ret = GetBlobFromBuffer(&tmp, srcData, offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get cert fail, ret = %" LOG_PUBLIC "d", ret)
    if (tmp.data == nullptr || tmp.size == 0) {
        HKS_LOG_E("cert is empty");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    /* when encoding in place, reserve room for the base64 expansion plus PEM headers */
    uint32_t capacity = tmp.size;
    if (needEncode) {
        if (tmp.size > (UINT32_MAX - ASYNC_STUB_BASE64_MARGIN) / 4) { /* 4: base64 group ratio */
            HKS_LOG_E("cert size %" LOG_PUBLIC "u too large to encode", tmp.size);
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        capacity = (tmp.size / 3 + 1) * 4 + ASYNC_STUB_BASE64_MARGIN; /* 3 raw -> 4 base64 */
    }
    cert->size = capacity;
    cert->data = static_cast<uint8_t *>(HksMalloc(capacity));
    HKS_IF_NULL_LOGE_RETURN(cert->data, HKS_ERROR_MALLOC_FAIL, "malloc cert fail")
    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(cert->data, cert->size, tmp.data, tmp.size),
        HKS_ERROR_INSUFFICIENT_DATA, "copy cert fail")
    if (needEncode) {
        /* in-place encode: EncodeCertChain reads rawSize bytes and writes the encoded data
         * back into the same (larger) buffer, updating the blob size to the encoded length */
        struct HksBlob inBlob = { tmp.size, cert->data };
        ret = EncodeCertChain(&inBlob, cert);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "EncodeCertChain fail, ret = %" LOG_PUBLIC "d", ret)
    }
    return HKS_SUCCESS;
}

int32_t HksUnpackAnonAttestCertChainToNew(const struct HksBlob *srcData, bool needEncode,
    struct HksCertChain **certChain)
{
    if ((srcData == nullptr) || (srcData->data == nullptr) || (certChain == nullptr) || (*certChain != nullptr)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (srcData->size < sizeof(uint32_t)) {
        HKS_LOG_E("invalid packed certs buffer, size = %" LOG_PUBLIC "u", srcData->size);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    /* read the count via memcpy: never assume the packed buffer is aligned for a u32 access */
    uint32_t certsCount = 0;
    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(&certsCount, sizeof(certsCount), srcData->data, sizeof(certsCount)),
        HKS_ERROR_INVALID_ARGUMENT, "copy certs count fail")
    if (certsCount == 0 || certsCount > HKS_CERT_COUNT) {
        HKS_LOG_E("invalid certs count %" LOG_PUBLIC "u", certsCount);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    /* RAII: the partially built chain is wiped and released on every error exit below, so no
     * per-branch HksFreeAnonAttestCertChain is needed */
    auto freeCertChain = [](struct HksCertChain *chain) { HksFreeAnonAttestCertChain(&chain); };
    struct HksCertChain *out = static_cast<struct HksCertChain *>(HksMalloc(sizeof(struct HksCertChain)));
    HKS_IF_NULL_LOGE_RETURN(out, HKS_ERROR_MALLOC_FAIL, "malloc cert chain fail")
    std::unique_ptr<struct HksCertChain, decltype(freeCertChain)> guard(out, freeCertChain);

    /* HksMalloc zeroes the allocated memory, so no extra memset is needed here */
    out->certs = static_cast<struct HksBlob *>(HksMalloc(sizeof(struct HksBlob) * certsCount));
    HKS_IF_NULL_LOGE_RETURN(out->certs, HKS_ERROR_MALLOC_FAIL, "malloc certs fail")
    out->certsCount = certsCount;

    uint32_t offset = sizeof(certsCount);
    for (uint32_t i = 0; i < certsCount; ++i) {
        int32_t ret = CopyAndEncodeOneCert(srcData, &offset, needEncode, &out->certs[i]);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy certs %" LOG_PUBLIC "u fail, ret = %" LOG_PUBLIC "d",
            i, ret)
    }

    *certChain = out;
    guard.release(); /* ownership transferred to the caller */
    return HKS_SUCCESS;
}

void HksFreeAnonAttestCertChain(struct HksCertChain **certChain)
{
    if (certChain == nullptr || *certChain == nullptr) {
        return;
    }
    struct HksCertChain *chain = *certChain;
    if (chain->certs != nullptr) {
        for (uint32_t i = 0; i < chain->certsCount; ++i) {
            HKS_MEMSET_FREE_BLOB(chain->certs[i]);
        }
        HKS_FREE(chain->certs);
    }
    chain->certsCount = 0;
    HKS_FREE(chain);
    *certChain = nullptr;
}

#ifdef __cplusplus
}
#endif
