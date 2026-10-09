/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef HKS_PLUGIN_LOADER_H
#define HKS_PLUGIN_LOADER_H

#include <string>
#include <unordered_map>
#include <map>
#include <dlfcn.h>
#include <memory>
#include <mutex>
#include <atomic>
#include <cstdint>
#include "hks_cpp_paramset.h"
#include "hks_template.h"
#include "singleton.h"
#include "hks_type.h"
#include "hks_plugin_def.h"
#include "hks_mem.h"
#include "safe_map.h"
#include "hks_function_types.h"

// forward declarations (avoid a header dependency cycle: the thread-pool header lives in
// common, only pointer types are needed here)
namespace OHOS { namespace Security { namespace Hks { class HksTaskExecutor; class HksAsyncTask; } } }

namespace OHOS {
namespace Security {
namespace Huks {

class HuksPluginLoader : private OHOS::DelayedSingleton<HuksPluginLoader> {
public:
    OHOS::SafeMap<PluginMethodEnum, std::string> m_pluginMethodNameMap;
    HuksPluginLoader();
    ~HuksPluginLoader();
    int32_t LoadPlugins(const struct HksProcessInfo &info, const std::string &providerName,
        const CppParamSet &paramSet, OHOS::SafeMap<PluginMethodEnum, void*> &pluginProviderMap);
    int32_t UnLoadPlugins(const struct HksProcessInfo &info, const std::string &providerName,
        const CppParamSet &paramSet, OHOS::SafeMap<PluginMethodEnum, void*> &pluginProviderMap);
    int32_t DlcloseInternal();
    bool IsHandleNull() const;
    // ukey async refactor: SO-internal thread-pool control (via dlsym extern "C" aliases).
    // SubmitTaskExecutor does Get+Submit inside the libMutex critical section (prevents a
    // dlclose race); the submission path holds the lock for a very short window (enqueue +
    // notify, microseconds), so the mutual exclusion with register/unload is acceptable.
    OHOS::Security::Hks::HksTaskExecutor *GetTaskExecutor();
    int32_t StartTaskExecutor();
    int32_t StopTaskExecutor();
    // locked submission (Get+Submit inside the libMutex critical section; returns an
    // HksTaskAccept enum value, -1 when the executor is unavailable)
    int32_t SubmitTaskExecutor(std::unique_ptr<OHOS::Security::Hks::HksAsyncTask> task);
    static std::shared_ptr<HuksPluginLoader> GetInstanceWrapper();
    static void ReleaseInstance();

private:
    // refills the function-pointer map when the SO is loaded (reuses the handle after
    // UnLoadPlugins clears it; split out to honor the 50-line-per-function constraint)
    int32_t RepopulatePluginMethods(OHOS::SafeMap<PluginMethodEnum, void*> &pluginProviderMap);
    void* m_pluginHandle = nullptr;
    std::mutex libMutex;
    std::string GetMethodByEnum(PluginMethodEnum methodEnum);
};
}
}
}
#endif