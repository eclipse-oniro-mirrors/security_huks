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

#include "hks_ukey_provider_proxy_resolver.h"

#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_plugin_def.h"
#include "hks_provider_life_cycle_manager.h"
#include "hks_template.h"

namespace OHOS {
namespace Security {
namespace Huks {

/*
 * Implementation delegating to the existing chain (behavior identical to the original
 * HksRemoteHandleManager::GetProviderProxy), wrapped in the interface; AutoRefCount is
 * hooked up here (SO reference protection during task execution).
 */
class HksProviderProxyResolverImpl : public IHksProviderProxyResolver {
public:
    HksProviderProxyResolverImpl() = default;
    ~HksProviderProxyResolverImpl() override = default;

    int32_t GetProxy(const ProviderInfo &providerInfo,
        OHOS::sptr<IHuksAccessExtBase> &proxy) override
    {
        auto mgr = HksProviderLifeCycleManager::GetInstanceWrapper();
        HKS_IF_TRUE_LOGE_RETURN(mgr == nullptr, HKS_ERROR_NULL_POINTER, "provider manager null");
        int32_t ret = mgr->GetExtensionProxy(providerInfo, proxy);
        HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS || proxy == nullptr, HKS_ERROR_NOT_EXIST,
            "get extension proxy failed, provider=%{public}s ret=%{public}d",
            providerInfo.m_providerName.c_str(), ret);
        return HKS_SUCCESS;
    }
};

// For use by SO-internal registration / task construction (singleton semantics: lives as
// long as the SO; stateless, so a global instance is safe).
std::shared_ptr<IHksProviderProxyResolver> HksGetProviderProxyResolver()
{
    static std::shared_ptr<IHksProviderProxyResolver> resolver = std::make_shared<HksProviderProxyResolverImpl>();
    return resolver;
}

} // namespace Huks
} // namespace Security
} // namespace OHOS
