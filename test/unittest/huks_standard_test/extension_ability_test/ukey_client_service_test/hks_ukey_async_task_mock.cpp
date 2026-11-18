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

#include "hks_response.h"
#include "hks_util.h"
#include "hks_error_code.h"
#include "hks_ukey_provider_proxy_resolver.h"
#include "iremote_object.h"
#include <string>
#include <memory>

namespace OHOS {
namespace Security {
namespace Hks {

void RegisterHandleRouting(uint64_t handle, const std::string &providerName,
    const sptr<IRemoteObject> &clientStub)
{
    (void)handle;
    (void)providerName;
    (void)clientStub;
}

void UnregisterHandleRouting(uint64_t handle, const sptr<IRemoteObject> &clientStub)
{
    (void)handle;
    (void)clientStub;
}

} // namespace Hks
} // namespace Security
} // namespace OHOS

namespace OHOS {
namespace Security {
namespace Huks {

std::shared_ptr<IHksProviderProxyResolver> HksGetProviderProxyResolver()
{
    return nullptr;
}

} // namespace Huks
} // namespace Security
} // namespace OHOS

extern "C" {

void HksSetThreadIdentityOverride(const struct HksProcessInfo *processInfo)
{
    (void)processInfo;
}

void HksSetThreadFullTokenIdOverride(uint64_t fullTokenId)
{
    (void)fullTokenId;
}

void HksAsyncResultSlotSetEnabled(bool enabled)
{
    (void)enabled;
}

void HksAsyncResultSlotTake(int32_t *result, struct HksBlob *response)
{
    if (result != nullptr) {
        *result = HKS_SUCCESS;
    }
    if (response != nullptr) {
        response->size = 0;
        response->data = nullptr;
    }
}

int32_t HksElapsedRealTime(uint64_t *timestampMs)
{
    if (timestampMs != nullptr) {
        *timestampMs = 0;
    }
    return HKS_SUCCESS;
}

} // extern "C"
