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

#ifndef HKS_ASYNC_STUB_H
#define HKS_ASYNC_STUB_H

#include <memory>

#include <message_option.h>
#include <message_parcel.h>

#include "hks_sa_interface.h"
#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Unpack the packed anonymous attestation cert chain (layout written by the service side
 * PackAttestChain: [certsCount:u32]{[size:u32][data][align4]}*) into a newly allocated
 * HksCertChain. Each cert is copied into its own HksMalloc-ed buffer; when needEncode is
 * true each cert is additionally base64(PEM) encoded, keeping the same presentation as the
 * sync anon attest path. Release the result with HksFreeAnonAttestCertChain.
 */
int32_t HksUnpackAnonAttestCertChainToNew(const struct HksBlob *srcData, bool needEncode,
    struct HksCertChain **certChain);

/*
 * Free a HksCertChain allocated by HksUnpackAnonAttestCertChainToNew. Cert buffers are wiped
 * before being released. Safe to call with *certChain == NULL.
 */
void HksFreeAnonAttestCertChain(struct HksCertChain **certChain);

#ifdef __cplusplus
}
#endif

namespace OHOS {
namespace Security {
namespace Hks {

/*
 * Client-side stub for the async anonymous attestation. Unlike HksStub (which caches the
 * reply and lets the caller block in WaitForAsyncReply), HksAsyncStub directly holds the
 * user callback and context pointer: when the service-side HksProxy::SendAsyncReply arrives,
 * the reply is parsed and the callback is invoked with (userData, result, certChain). No
 * condition variable, no waiting, no global registry - the object itself is the routing key
 * (one stub instance == one request == one (callback, userData) pair).
 *
 * Result delivery is identical on every service-side security level: the admission reply
 * only tells whether the request was admitted (it carries a zero placeholder, never the
 * chain), and the chain itself always arrives through this stub via the
 * HKS_MSG_ATTEST_KEY_ASYNC_REPLY one-way message - sent by the TEE service once the DCM
 * networking completes, or by the software service right while it handles the admission
 * (the software engine attests inline). In the software case the one-way reply can even
 * overtake the admission reply, so the callback may run before the request function
 * returns.
 *
 * Lifetime: created with a local sptr and passed to the service via WriteRemoteObject. The
 * IPC framework holds a strong reference from then on, so the object stays alive after the
 * sending function returns, and is destroyed automatically once the service releases its
 * proxy (after SendAsyncReply).
 */
class HksAsyncStub : public IRemoteStub<IHksService> {
public:
    HksAsyncStub(HksAsyncAnonAttestCallback callback, void *userData, bool needBase64);
    ~HksAsyncStub() override = default;

    /* IHksService interface. The async flow reaches OnRemoteRequest through IPC; a direct
     * call only happens for in-process users/tests and dispatches to the callback too. */
    void SendAsyncReply(uint32_t errCode, std::unique_ptr<uint8_t[]> &certChain, uint32_t sz) override;

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;

private:
    int ProcessAttestKeyAsyncReply(MessageParcel &data);
    void InvokeCallback(uint32_t errCode, const uint8_t *packedCertChain, uint32_t sz);

    HksAsyncAnonAttestCallback mCallback = nullptr;
    void *mUserData = nullptr;
    bool mNeedBase64 = false;
};

} // namespace Hks
} // namespace Security
} // namespace OHOS

#endif /* HKS_ASYNC_STUB_H */
