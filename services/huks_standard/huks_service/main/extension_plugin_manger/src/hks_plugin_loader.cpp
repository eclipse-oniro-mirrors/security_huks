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

#include "hks_function_types.h"
#include "hks_plugin_lifecycle_manager.h"
#include "hks_plugin_loader.h"

#include "hks_task_executor.h"
#include <vector>

namespace OHOS {
namespace Security {
namespace Huks {

std::string pluginSo = "libhuks_external_crypto_ext_core.z.so";

std::shared_ptr<HuksPluginLoader> HuksPluginLoader::GetInstanceWrapper()
{
    return HuksPluginLoader::GetInstance();
}

void HuksPluginLoader::ReleaseInstance()
{
    HuksPluginLoader::DestroyInstance();
}

int32_t HuksPluginLoader::RepopulatePluginMethods(
    OHOS::SafeMap<PluginMethodEnum, void*> &pluginProviderMap)
{
    for (auto i = 0; i < static_cast<int32_t>(PluginMethodEnum::COUNT); ++i) {
        std::string methodString = GetMethodByEnum(static_cast<PluginMethodEnum>(i));
        if (methodString.empty()) {
            continue;
        }
        dlerror();
        void *func = dlsym(m_pluginHandle, methodString.c_str());
        const char *dlsym_error = dlerror();
        if (dlsym_error != nullptr) {
            HKS_LOG_E("failed to Find entry %{public}s, error: %{public}s",
                methodString.c_str(), dlsym_error);
            continue;
        }
        pluginProviderMap.Insert(static_cast<PluginMethodEnum>(i), func);
    }
    return HKS_SUCCESS;
}

int32_t HuksPluginLoader::LoadPlugins(const struct HksProcessInfo &info, const std::string &providerName,
    const CppParamSet &paramSet, OHOS::SafeMap<PluginMethodEnum, void*> &pluginProviderMap)
{
    std::lock_guard<std::mutex> lock(libMutex);

    // SO already loaded: re-populate function pointer map (may have been cleared by UnLoadPlugins)
    if (m_pluginHandle != nullptr) {
        return RepopulatePluginMethods(pluginProviderMap);
    }

    m_pluginHandle = dlopen(pluginSo.c_str(), RTLD_NOW);
    HKS_IF_NULL_LOGE_RETURN(m_pluginHandle, HKS_ERROR_OPEN_LIB_FAIL,
        "dlopen %" LOG_PUBLIC "s failed! %" LOG_PUBLIC "s", pluginSo.c_str(), dlerror())

    for (auto i = 0; i < static_cast<int32_t>(PluginMethodEnum::COUNT); ++i) {
        std::string methodString = GetMethodByEnum(static_cast<PluginMethodEnum>(i));
        if (methodString.empty()) {
            HKS_LOG_E("the entry %{public}s is not include", pluginSo.c_str());

            int32_t ret = dlclose(m_pluginHandle);
            HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, HKS_ERROR_DLCLOSE_FAIL,
                "dlclose fail, error: %{public}s", dlerror())

            m_pluginHandle = nullptr;
            pluginProviderMap.Clear();
            return HKS_ERROR_FIND_FUNC_MAP_FAIL;
        }

        dlerror();
        void *func = dlsym(m_pluginHandle, methodString.c_str());
        const char *dlsym_error = dlerror();
        if (dlsym_error != nullptr) {
            HKS_LOG_E("failed to Find entry %{public}s in dynamic link library, error: %{public}s",
                methodString.c_str(), dlsym_error);

            dlsym_error = dlerror();
            int32_t ret = dlclose(m_pluginHandle);
            HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, HKS_ERROR_DLCLOSE_FAIL,
                "dlclose fail, error: %{public}s", dlsym_error)

            m_pluginHandle = nullptr;
            pluginProviderMap.Clear();
            return HKS_ERROR_GET_FUNC_POINTER_FAIL;
        }
        pluginProviderMap.Insert(static_cast<PluginMethodEnum>(i), func);
    }

    return HKS_SUCCESS;
}

int32_t HuksPluginLoader::UnLoadPlugins(const struct HksProcessInfo &info, const std::string &providerName,
    const CppParamSet &paramSet, OHOS::SafeMap<PluginMethodEnum, void*> &pluginProviderMap)
{
    std::lock_guard<std::mutex> lock(libMutex);
    HKS_IF_TRUE_RETURN(m_pluginHandle == nullptr, HKS_SUCCESS)

    // Only clear function pointers; actual dlclose is deferred to avoid
    // invalidating Stub vtable while the service binder release (BR_RELEASE) is in flight.
    pluginProviderMap.Clear();
    HKS_LOG_I("UnLoadPlugins: function pointers cleared, dlclose deferred");
    return HKS_SUCCESS;
}

int32_t HuksPluginLoader::DlcloseInternal()
{
    std::lock_guard<std::mutex> lock(libMutex);
    HKS_IF_TRUE_RETURN(m_pluginHandle == nullptr, HKS_SUCCESS)

    int32_t ret = dlclose(m_pluginHandle);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, HKS_ERROR_DLCLOSE_FAIL,
        "dlclose fail, error: %{public}s", dlerror())

    m_pluginHandle = nullptr;
    HKS_LOG_I("delayed dlclose success!");
    return HKS_SUCCESS;
}

bool HuksPluginLoader::IsHandleNull() const
{
    return m_pluginHandle == nullptr;
}

// ukey async refactor: calls the SO-exported thread-pool control functions via dlsym (symbols
// in libhuks_external_crypto_ext_core.map; silently succeeds when the SO is not loaded — the
// thread pool lives with the SO). Executor handle acquisition: unlike Start/Stop, the returned
// pointer's lifetime is decided by the SO, so the caller must do Get+Submit within the same
// libMutex critical section (prevents a dlclose race); therefore this method does not lock
// itself (Start/Stop lock for idempotency; this one is locked by the caller uniformly)
OHOS::Security::Hks::HksTaskExecutor *HuksPluginLoader::GetTaskExecutor()
{
    HKS_IF_TRUE_RETURN(m_pluginHandle == nullptr, nullptr)
    using GetFunc = OHOS::Security::Hks::HksTaskExecutor *(*)();
    dlerror();
    auto func = reinterpret_cast<GetFunc>(dlsym(m_pluginHandle, "HksExtPluginGetTaskExecutorC"));
    const char *err = dlerror();
    if (func == nullptr || err != nullptr) {
        HKS_LOG_E("dlsym HksExtPluginGetTaskExecutorC fail: %{public}s", err != nullptr ? err : "null");
        return nullptr;
    }
    return func();
}


int32_t HuksPluginLoader::SubmitTaskExecutor(const std::string &providerName,
    std::unique_ptr<OHOS::Security::Hks::HksAsyncTask> task)
{
    // Empty providerName (extraction failed or legacy code path) falls back to the SO-internal
    // global executor via dlsym — preserves the original behavior when providerName is unavailable.
    if (providerName.empty()) {
        std::lock_guard<std::mutex> lock(libMutex);
        HKS_IF_TRUE_RETURN(m_pluginHandle == nullptr, -1)
        auto *executor = GetTaskExecutor();
        HKS_IF_TRUE_RETURN(executor == nullptr, -1)
        return static_cast<int32_t>(executor->Submit(std::move(task)));
    }
    // Per-provider executor: created on first use (1 worker + 16 pending), isolating slow
    // operations from other providers. executorMutex_ protects the map and is held across
    // Submit to prevent a UAF window: without holding the lock, a concurrent
    // StopExecutorForProvider could remove and destroy the executor between the lookup
    // and the Submit call. Submit is O(1) (push_back + notify, no blocking), so the lock
    // hold time is negligible. StopExecutorForProvider's Stop()+join runs outside the lock.
    std::lock_guard<std::mutex> lock(executorMutex_);
    auto it = executors_.find(providerName);
    if (it != executors_.end()) {
        it->second->Start();
        int32_t ret = static_cast<int32_t>(it->second->Submit(std::move(task)));
        if (ret == static_cast<int32_t>(OHOS::Security::Hks::HksTaskAccept::STOPPED)) {
            HKS_LOG_E("per-provider executor still stopped after restart, evicting, provider=%{public}s",
                providerName.c_str());
            executors_.erase(it);
        }
        return ret;
    }
    auto newExecutor = std::make_unique<Hks::HksTaskExecutor>(Hks::HksTaskExecutor::Config{});
    newExecutor->Start();
    int32_t acceptRaw = static_cast<int32_t>(newExecutor->Submit(std::move(task)));
    if (acceptRaw == static_cast<int32_t>(OHOS::Security::Hks::HksTaskAccept::STOPPED)) {
        // Start failed (pthread_create); do not cache the dead executor — the next
        // Submit will create a fresh one and retry.
        HKS_LOG_E("per-provider executor start failed, not cached, provider=%{public}s",
            providerName.c_str());
    } else {
        HKS_LOG_I("per-provider executor created, provider=%{public}s", providerName.c_str());
        executors_[providerName] = std::move(newExecutor);
    }
    return acceptRaw;
}

int32_t HuksPluginLoader::StopExecutorForProvider(const std::string &providerName)
{
    std::unique_ptr<OHOS::Security::Hks::HksTaskExecutor> executorToStop;
    {
        std::lock_guard<std::mutex> lock(executorMutex_);
        auto it = executors_.find(providerName);
        if (it == executors_.end()) {
            return HKS_SUCCESS; // not found: already stopped or never created
        }
        executorToStop = std::move(it->second);
        executors_.erase(it);
    }
    HKS_LOG_I("per-provider executor stopping, provider=%{public}s", providerName.c_str());
    executorToStop->Stop(); // join in-flight tasks (<=60s) + drain queued
    executorToStop.reset();
    HKS_LOG_I("per-provider executor stopped, provider=%{public}s", providerName.c_str());
    return HKS_SUCCESS;
}

int32_t HuksPluginLoader::StartTaskExecutor()
{
    std::lock_guard<std::mutex> lock(libMutex);
    HKS_IF_TRUE_RETURN(m_pluginHandle == nullptr, HKS_SUCCESS)
    using StartFunc = int32_t (*)();
    dlerror();
    auto func = reinterpret_cast<StartFunc>(dlsym(m_pluginHandle, "HksExtPluginStartTaskExecutorC"));
    const char *err = dlerror();
    if (func == nullptr || err != nullptr) {
        HKS_LOG_E("dlsym HksExtPluginStartTaskExecutorC fail: %{public}s", err != nullptr ? err : "null");
        return HKS_ERROR_FIND_FUNC_MAP_FAIL;
    }
    return func();
}

int32_t HuksPluginLoader::StopTaskExecutor()
{
    std::lock_guard<std::mutex> lock(libMutex);
    HKS_IF_TRUE_RETURN(m_pluginHandle == nullptr, HKS_SUCCESS)
    using StopFunc = int32_t (*)();
    dlerror();
    auto func = reinterpret_cast<StopFunc>(dlsym(m_pluginHandle, "HksExtPluginStopTaskExecutorC"));
    const char *err = dlerror();
    if (func == nullptr || err != nullptr) {
        HKS_LOG_E("dlsym HksExtPluginStopTaskExecutorC fail: %{public}s", err != nullptr ? err : "null");
        return HKS_ERROR_FIND_FUNC_MAP_FAIL;
    }
    return func(); // inner Stop(): joins in-flight tasks (<=60s) and runs OnDone for each queued
                   // task one by one — the caller is the delayed-dlclose thread
}

std::string HuksPluginLoader::GetMethodByEnum(PluginMethodEnum methodEnum)
{
    std::string methodString = "";
    bool isFind = m_pluginMethodNameMap.Find(methodEnum, methodString);
    HKS_IF_TRUE_RETURN(isFind, methodString)
    HKS_LOG_E("enum = %{public}d can not Find string", methodEnum);
    return "";
}

static void RegisterAuthMethodMaps(OHOS::SafeMap<PluginMethodEnum, std::string> &map)
{
    map.Insert(PluginMethodEnum::FUNC_ON_AUTH_UKEY_PIN,
        "_ZN4OHOS8Security4Huks25HksExtPluginOnAuthUkeyPinERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetR21HksExtAuthPinOutParamPP20HksExternalErrorInfo");
    map.Insert(PluginMethodEnum::FUNC_ON_GET_VERIFY_PIN_STATUS,
        "_ZN4OHOS8Security4Huks33HksExtPluginOnGetUkeyPinAuthStateERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRiPP20HksExternalErrorInfo");
    map.Insert(PluginMethodEnum::FUNC_ON_CLEAR_PIN_STATUS,
        "_ZN4OHOS8Security4Huks35HksExtPluginOnClearUkeyPinAuthStateERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetPP20HksExternalErrorInfo");
}

static void RegisterCertificateMethodMaps(OHOS::SafeMap<PluginMethodEnum, std::string> &map)
{
    map.Insert(PluginMethodEnum::FUNC_ON_LIST_INDEX_CERTIFICATE,
        "_ZN4OHOS8Security4Huks31HksExtPluginOnExportCertificateERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_PP20HksExternalErrorInfo");
    map.Insert(PluginMethodEnum::FUNC_ON_LIST_PROVIDER_ALL_CERTIFICATE,
        "_ZN4OHOS8Security4Huks40HksExtPluginOnExportProviderCertificatesERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_PP20HksExternalErrorInfo");
    map.Insert(PluginMethodEnum::FUNC_ON_IMPORT_CERTIFICATE,
        "_ZN4OHOS8Security4Huks31HksExtPluginOnImportCertificateERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK14HksExtCertInfoRK11CppParamSetPP20HksExternalErrorInfo");
}

static void RegisterRemoteHandleMethodMaps(OHOS::SafeMap<PluginMethodEnum, std::string> &map)
{
    map.Insert(PluginMethodEnum::FUNC_ON_CREATE_REMOTE_KEY_HANDLE,
        "_ZN4OHOS8Security4Huks30HksExtPluginOnOpenRemoteHandleERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetPP20HksExternalErrorInfo");
    map.Insert(PluginMethodEnum::FUNC_ON_CLOSE_REMOTE_KEY_HANDLE,
        "_ZN4OHOS8Security4Huks31HksExtPluginOnCloseRemoteHandleERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetPP20HksExternalErrorInfo");
    map.Insert(PluginMethodEnum::FUNC_ON_SET_OR_GET_REMOTE_PROPERTY,
        "_ZN4OHOS8Security4Huks36HksExtPluginOnSetOrGetRemoteProperty"
        "ER23HksProcessWithErrorInfo23HksExtPropertyOperationRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEESD_R11CppParamSet");
}

static void RegisterSessionMethodMaps(OHOS::SafeMap<PluginMethodEnum, std::string> &map)
{
    map.Insert(PluginMethodEnum::FUNC_ON_INIT_SESSION,
        "_ZN4OHOS8Security4Huks25HksExtPluginOnInitSessionER23HksProcessWithErrorInfoRKNSt3__h12basic_string"
        "IcNS4_11char_traitsIcEENS4_9allocatorIcEEEERK11CppParamSetRj");
    map.Insert(PluginMethodEnum::FUNC_ON_UPDATE_SESSION,
        "_ZN4OHOS8Security4Huks27HksExtPluginOnUpdateSessionER23HksProcessWithErrorInfoRKjRK11CppParamSet"
        "RKNSt3__h6vectorIhNS9_9allocatorIhEEEERSD_");
    map.Insert(PluginMethodEnum::FUNC_ON_FINISH_SESSION,
        "_ZN4OHOS8Security4Huks27HksExtPluginOnFinishSessionER23HksProcessWithErrorInfoRKjRK11CppParamSet"
        "RKNSt3__h6vectorIhNS9_9allocatorIhEEEERSD_");
    map.Insert(PluginMethodEnum::FUNC_ON_ABORT_SESSION,
        "_ZN4OHOS8Security4Huks26HksExtPluginOnAbortSessionER23HksProcessWithErrorInfoRKjRK11CppParamSet");
}

static void RegisterOtherMethodMaps(OHOS::SafeMap<PluginMethodEnum, std::string> &map)
{
    map.Insert(PluginMethodEnum::FUNC_ON_REGISTER_PROVIDER,
        "_ZN4OHOS8Security4Huks30HksExtPluginOnRegisterProviderERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetNS5_8functionIFvS2_EEE");
    map.Insert(PluginMethodEnum::FUNC_ON_UN_REGISTER_PROVIDER,
        "_ZN4OHOS8Security4Huks32HksExtPluginOnUnRegisterProviderERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetbRi");
    map.Insert(PluginMethodEnum::FUNC_ON_GENERATE_KEY,
        "_ZN4OHOS8Security4Huks25HksExtPluginOnGenerateKeyER23HksProcessWithErrorInfoRKNSt3__h12basic_string"
        "IcNS4_11char_traitsIcEENS4_9allocatorIcEEEERK11CppParamSet");
    map.Insert(PluginMethodEnum::FUNC_ON_UNREGISTER_ALL_OBSERVERS,
        "_ZN4OHOS8Security4Huks36HksExtPluginOnUnregisterAllObserversEv");
    map.Insert(PluginMethodEnum::FUNC_ON_EXPORT_PUBLIC_KEY,
        "_ZN4OHOS8Security4Huks29HksExtPluginOnExportPublicKeyER23HksProcessWithErrorInfoRKNSt3__h12basic_string"
        "IcNS4_11char_traitsIcEENS4_9allocatorIcEEEERK11CppParamSetRNS4_6vectorIhNS8_IhEEEE");
    map.Insert(PluginMethodEnum::FUNC_ON_IMPORT_WRAPPED_KEY,
        "_ZN4OHOS8Security4Huks30HksExtPluginOnImportWrappedKeyER23HksProcessWithErrorInfoRKNSt3__h12basic_string"
        "IcNS4_11char_traitsIcEENS4_9allocatorIcEEEESC_RK11CppParamSetRKNS4_6vectorIhNS8_IhEEEE");
    map.Insert(PluginMethodEnum::FUNC_ON_QUERY_ABILITY,
        "_ZN4OHOS8Security4Huks30HksExtPluginOnQueryAbilityInfoERK14HksProcessInfoRNSt3__h12basic_stringIcNS5_11"
        "char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetR14CppAbilityInfo");
    map.Insert(PluginMethodEnum::FUNC_ON_GET_RESOURCE_ID,
        "_ZN4OHOS8Security4Huks27HksExtPluginOnGetResourceIdERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_PP20HksExternalErrorInfo");
}

HuksPluginLoader::HuksPluginLoader()
{
    RegisterOtherMethodMaps(m_pluginMethodNameMap);
    RegisterAuthMethodMaps(m_pluginMethodNameMap);
    RegisterCertificateMethodMaps(m_pluginMethodNameMap);
    RegisterRemoteHandleMethodMaps(m_pluginMethodNameMap);
    RegisterSessionMethodMaps(m_pluginMethodNameMap);
}

HuksPluginLoader::~HuksPluginLoader()
{
}

}
}
}
