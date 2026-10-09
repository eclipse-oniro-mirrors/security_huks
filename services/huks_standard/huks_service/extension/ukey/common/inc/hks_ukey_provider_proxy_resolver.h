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

#ifndef HKS_UKEY_PROVIDER_PROXY_RESOLVER_H
#define HKS_UKEY_PROVIDER_PROXY_RESOLVER_H

#include "hks_ukey_common.h" // ProviderInfo

#include "ihuks_access_ext_base.h"

#include <memory>

namespace OHOS {
namespace Security {
namespace Huks {

/*
 * Unified proxy resolution seam (ukey async refactor):
 * the only interface between the task object and the proxy acquisition chain:
 *   1. Dependency direction is closed: HksUkeyAsyncTask does not depend directly on
 *      HksRemoteHandleManager / the lifecycle-management Singleton (mockable, so the task
 *      chain can be unit-tested standalone)
 *   2. The implementation delegates to the existing chain: HksProviderProxyResolverImpl is
 *      internally "HksProviderLifeCycleManager::GetInstanceWrapper -> GetExtensionProxy -> null check"
 *   3. SO reference-protection hook: the implementation holds an AutoRefCount so the SO is not
 *      unloaded during task execution
 * Serves only "obtaining the existing proxy during task execution"; it does not participate
 * in register/unregister lifecycle management.
 */
class IHksProviderProxyResolver {
public:
    virtual ~IHksProviderProxyResolver() = default;

    virtual int32_t GetProxy(const ProviderInfo &providerInfo,
        OHOS::sptr<IHuksAccessExtBase> &proxy) = 0;
};

// Get the default implementation (lives with the SO lifecycle, stateless so it can be global)
std::shared_ptr<IHksProviderProxyResolver> HksGetProviderProxyResolver();

} // namespace Huks
} // namespace Security
} // namespace OHOS

#endif
