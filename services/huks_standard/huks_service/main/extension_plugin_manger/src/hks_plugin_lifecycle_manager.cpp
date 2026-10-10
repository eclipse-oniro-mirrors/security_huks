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

#include "hks_plugin_lifecycle_manager.h"
#include "hks_plugin_loader.h"
#include "hks_cfi.h"
#include "hks_ukey_common.h"
#include <thread>

#define NO_EXTENSION 0
#define ONE_EXTENSION 1
namespace OHOS {
namespace Security {
namespace Huks {

std::shared_ptr<HuksPluginLifeCycleMgr> HuksPluginLifeCycleMgr::GetInstanceWrapper()
{
    return HuksPluginLifeCycleMgr::GetInstance();
}

void HuksPluginLifeCycleMgr::ReleaseInstance()
{
    HuksPluginLifeCycleMgr::DestroyInstance();
}

constexpr int WAIT_CALLBACK = 20;

static std::function<void(HksProcessInfo)> MakeDeathCallback(
    std::shared_ptr<HuksPluginLifeCycleMgr> plugin,
    const std::string &providerName, const CppParamSet &paramSet)
{
    return [plugin, providerName, paramSet](const HksProcessInfo &processInfo) mutable {
        std::thread([plugin, pdrName = providerName, paramSet_ = paramSet, processInfo]() mutable {
            if (plugin == nullptr) {
                HKS_LOG_E("MakeDeathCallback: plugin instance is null, skip UnRegisterProvider");
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<long long>(WAIT_CALLBACK)));
            HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
            plugin->UnRegisterProvider(processInfo, pdrName, paramSet_, true);
        }).detach();
    };
}

int32_t HuksPluginLifeCycleMgr::RegisterProvider(const struct HksProcessInfo &info,
    const std::string &providerName, const CppParamSet &paramSet)
{
    int32_t ret;
    std::unique_lock<std::mutex> lock(soMutex);
    auto pluginLoader = HuksPluginLoader::GetInstanceWrapper();
    if (m_refCount.load() == NO_EXTENSION) {
        HKS_IF_TRUE_LOGE_RETURN(pluginLoader == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get pluginLoader instance.")
        // Always cancel pending dlclose when refCount is 0, regardless of
        // whether the SO handle is still valid. The delayed dlclose thread
        // only checks generation, not refCount, so we must bump generation
        // to prevent it from closing the SO after a new Register arrives.
        m_dlcloseGeneration.fetch_add(1, std::memory_order_acq_rel);
        ret = pluginLoader->LoadPlugins(info, providerName, paramSet, m_pluginProviderMap);
        HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "regist provider failed!")
    }

    auto deathCallback = MakeDeathCallback(GetInstanceWrapper(), providerName, paramSet);
    ret = OnRegistProvider(info, providerName, paramSet, deathCallback);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "regist provider method in plugin loader is fail")

    // ukey async refactor: start the SO-internal thread pool at the end of the successful
    // registration path (idempotent; if worker creation fails, Submit always returns STOPPED
    // and reports the error via the callback, and the registration itself is not rolled back)
    if (pluginLoader != nullptr) {
        (void)pluginLoader->StartTaskExecutor();
    }

    m_refCount.fetch_add(1, std::memory_order_acq_rel);
    return ret;
}

// Body of the delayed-dlclose thread: waits for the Ability Manager Service Phase 2 and its
// binder release (BR_RELEASE) to finish, then unloads safely. ukey async refactor timing rule:
// stop the SO-internal thread pool before dlclose (Stop+join before dlclose; this runs on the
// detached delayed thread, satisfying the rule). Lock-order rule: the unload check (generation
// + refCount) and Stop/join are in two separate critical sections — calling StopTaskExecutor
// (->Stop->join) while holding soMutex would deadlock against the AutoRefCount on the worker
// dispatch path (construction/destruction need the same soMutex), so the lock must be released
// before join.
void HuksPluginLifeCycleMgr::DelayedDlclose(uint32_t gen)
{
    std::this_thread::sleep_for(std::chrono::seconds(1));
    auto loader = HuksPluginLoader::GetInstanceWrapper();
    if (loader == nullptr) {
        return;
    }
    bool proceed = false;
    {
        std::unique_lock<std::mutex> lock(soMutex);
        if (m_dlcloseGeneration.load(std::memory_order_acquire) != gen) {
            HKS_LOG_I("deferred dlclose cancelled, generation changed");
            return;
        }
        if (m_refCount.load(std::memory_order_acquire) != NO_EXTENSION) {
            HKS_LOG_I("deferred dlclose cancelled, refCount not zero");
            return;
        }
        proceed = true;
    }
    if (!proceed) {
        return;
    }
    (void)loader->StopTaskExecutor();
    // second confirmation: if a new RegisterProvider arrived during the lock-released window
    // (generation changed) or an in-flight dispatch raised refCount, skip dlclose and restart
    // the thread pool to restore service (Start supports the Stopped->Running restart);
    // otherwise unload safely
    {
        std::unique_lock<std::mutex> lock(soMutex);
        if (m_dlcloseGeneration.load(std::memory_order_acquire) != gen ||
            m_refCount.load(std::memory_order_acquire) != NO_EXTENSION) {
            lock.unlock();
            HKS_LOG_I("provider re-registered during deferred stop, restarting executor");
            (void)loader->StartTaskExecutor();
            return;
        }
    }
    loader->DlcloseInternal();
}

int32_t HuksPluginLifeCycleMgr::UnRegisterProvider(const struct HksProcessInfo &info, const std::string &providerName,
    const CppParamSet &paramSet, bool isdeath)
{
    std::unique_lock<std::mutex> lock(soMutex);
    if (m_refCount.load() == NO_EXTENSION) {
        HKS_LOG_I("lib has closed!");
        return HKS_ERROR_LIB_REPEAT_CLOSE;
    }

    int32_t ret = HKS_SUCCESS;
    int32_t deleteCount = 1;
    do {
        ret = OnUnRegistProvider(info, providerName, paramSet, isdeath, deleteCount);
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS, "unregist provider failed! ret = %{public}d", ret)

        HKS_IF_TRUE_LOGE_BREAK(m_refCount.load() != ONE_EXTENSION,
            "don't need close lib, refCount = %{public}d", m_refCount.load())

        auto pluginLoader = HuksPluginLoader::GetInstanceWrapper();
        if (pluginLoader == nullptr) {
            ret = HKS_ERROR_NULL_POINTER;
            HKS_LOG_E("Failed to get pluginLoader instance.");
            break;
        }

        auto pluginLifeCycleMgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
        if (pluginLifeCycleMgr == nullptr) {
            ret = HKS_ERROR_NULL_POINTER;
            HKS_LOG_E("Failed to get pluginLifeCycleMgr instance.");
            break;
        }

        ret = pluginLifeCycleMgr->OnUnregisterAllObservers();
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS, "Failed to unregister all observers, ret = %{public}d", ret)

        // Only clear function pointers; actual dlclose is deferred to keep
        // Stub vtable valid while the service binder release (BR_RELEASE) is in flight.
        ret = pluginLoader->UnLoadPlugins(info, providerName, paramSet, m_pluginProviderMap);
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS, "unload plugins failed!, ret = %{public}d", ret)

        // Launch delayed dlclose thread: wait 1s for the Ability Manager Service Phase 2 and
        // its binder release (BR_RELEASE) to complete, then dlclose if no new RegisterProvider arrived.
        uint32_t gen = m_dlcloseGeneration.load(std::memory_order_acquire);
        std::thread(&HuksPluginLifeCycleMgr::DelayedDlclose, GetInstanceWrapper(), gen).detach();
    } while (0);

    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "unregist provider fail");

    int32_t currentRefCount = m_refCount.load(std::memory_order_acquire);
    if (deleteCount > currentRefCount) {
        HKS_LOG_E("UnRegisterProvider: deleteCount %{public}d > refCount %{public}d, clamping",
            deleteCount, currentRefCount);
        deleteCount = currentRefCount;
    }
    m_refCount.fetch_sub(deleteCount, std::memory_order_acq_rel);

    return ret;
}

struct AutoRefCount {
    std::atomic<int32_t> &m_refCount;
    std::mutex &soMutex;
    explicit AutoRefCount(std::atomic<int32_t> &refCount, std::mutex &mutexIn) : m_refCount(refCount), soMutex(mutexIn)
    {
        std::unique_lock<std::mutex> lock(soMutex);
        m_refCount.fetch_add(1, std::memory_order_acq_rel);
    }
    ~AutoRefCount()
    {
        std::unique_lock<std::mutex> lock(soMutex);
        m_refCount.fetch_sub(1, std::memory_order_acq_rel);
    }
};

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnQueryAbility(const HksProcessInfo &processInfo, std::string &resourceId,
    CppAbilityInfo &abilityInfo))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_QUERY_ABILITY, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "OnQueryAbility method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnQueryAbilityFunc>(funcPtr))(processInfo, resourceId, abilityInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "OnQueryAbility fail, ret = %{public}d", ret)
    HKS_LOG_I("query ability success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnRegistProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::function<void(HksProcessInfo)> callback))
{
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_REGISTER_PROVIDER, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "OnRegistProvider method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnRegisterProviderFunc>(funcPtr))(processInfo, providerName, paramSet, callback);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "OnRegistProvider fail, ret = %{public}d", ret)
    HKS_LOG_I("regist provider success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnUnRegistProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, bool isdeath, int32_t &deleteCount))
{
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_UN_REGISTER_PROVIDER, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "UnRegistProvider method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnUnRegisterProviderFunc>(funcPtr))
        (processInfo, providerName, paramSet, isdeath, deleteCount);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "UnRegistProvider fail, ret = %{public}d", ret)
    HKS_LOG_I("unregist provider success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnCreateRemoteKeyHandle(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, struct HksExternalErrorInfo **errInfo))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_CREATE_REMOTE_KEY_HANDLE, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "CreateRemoteKeyHandle method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnCreateRemoteKeyHandleFunc>(funcPtr))(processInfo, index, paramSet, errInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "CreateRemoteKeyHandle fail, ret = %{public}d", ret)
    HKS_LOG_I("create remote key handle success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnCloseRemoteKeyHandle(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, struct HksExternalErrorInfo **errInfo))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_CLOSE_REMOTE_KEY_HANDLE, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "CloseRemoteKeyHandle method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnCloseRemoteKeyHandleFunc>(funcPtr))(processInfo, index, paramSet, errInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "CloseRemoteKeyHandle fail, ret = %{public}d", ret)
    HKS_LOG_I("close remote key handle success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnAuthUkeyPin(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, struct HksExtAuthPinOutParam &authOutParam, struct HksExternalErrorInfo **errInfo))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_AUTH_UKEY_PIN, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "AuthUkeyPin method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnAuthUkeyPinFunc>(funcPtr))(processInfo, index, paramSet, authOutParam, errInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "AuthUkeyPin fail, ret = %{public}d", ret)
    HKS_LOG_I("auth ukey pin success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnGetVerifyPinStatus(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &state, struct HksExternalErrorInfo **errInfo))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_GET_VERIFY_PIN_STATUS, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "GetVerifyPinStatus method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnGetVerifyPinStatusFunc>(funcPtr))(processInfo, index, paramSet, state, errInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "GetVerifyPinStatus fail, ret = %{public}d", ret)
    HKS_LOG_I("get verify pin status success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnClearUkeyPinAuthStatus(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, struct HksExternalErrorInfo **errInfo))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_CLEAR_PIN_STATUS, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "ClearPinStatus method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnClearUkeyPinAuthStatusFunc>(funcPtr))(processInfo, index, paramSet, errInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "ClearPinStatus fail, ret = %{public}d", ret)
    HKS_LOG_I("clear pin status success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnSetOrGetRemoteProperty(struct HksProcessWithErrorInfo &processAndError,
    enum HksExtPropertyOperation operation, const std::string &index, const std::string &propertyId,
    CppParamSet &paramSet))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_SET_OR_GET_REMOTE_PROPERTY, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "SetOrGetRemoteProperty method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnSetOrGetRemotePropertyFunc>(funcPtr))(processAndError, operation,
        index, propertyId, paramSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "SetOrGetRemoteProperty fail, ret = %{public}d", ret)
    HKS_LOG_I("set or get remote property success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnExportCertificate(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, std::string &certsJson,
    struct HksExternalErrorInfo **errInfo))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_LIST_INDEX_CERTIFICATE, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "FindProviderCertificate method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnListIndexCertificateFunc>(funcPtr))(processInfo, index, paramSet, certsJson,
        errInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "FindProviderCertificate fail, ret = %{public}d", ret)
    HKS_LOG_I("list provider certificate success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnExportProviderAllCertificates(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::string &certsJsonArr,
    struct HksExternalErrorInfo **errInfo))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_LIST_PROVIDER_ALL_CERTIFICATE, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "ListProviderAllCertificate method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnListProviderAllCertificateFunc>(funcPtr))
        (processInfo, providerName, paramSet, certsJsonArr, errInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "ListProviderAllCertificate fail, ret = %{public}d", ret)
    HKS_LOG_I("list provider all certificate success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnImportCertificate(const HksProcessInfo &processInfo,
    const std::string &index, const struct HksExtCertInfo &certInfo, const CppParamSet &paramSet,
    struct HksExternalErrorInfo **errInfo))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_IMPORT_CERTIFICATE, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "ImportCertificate method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnImportCertificateFunc>(funcPtr))
        (processInfo, index, certInfo, paramSet, errInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "ImportCertificate fail, ret = %{public}d", ret)
    HKS_LOG_I("import certificate success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnInitSession(struct HksProcessWithErrorInfo &processAndError,
    const std::string &index, const CppParamSet &paramSet, uint32_t &handle))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_INIT_SESSION, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "InitSession method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnInitSessionFunc>(funcPtr))(processAndError, index, paramSet, handle);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "InitSession fail, ret = %{public}d", ret)
    HKS_LOG_I("init session success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnUpdateSession(struct HksProcessWithErrorInfo &processAndError,
    const uint32_t &handle, const CppParamSet &paramSet, const std::vector<uint8_t> &inData,
    std::vector<uint8_t> &outData))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_UPDATE_SESSION, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "UpdateSession method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnUpdateSessionFunc>(funcPtr))(processAndError, handle, paramSet, inData, outData);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "UpdateSession fail, ret = %{public}d", ret)
    HKS_LOG_I("update session success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnFinishSession(struct HksProcessWithErrorInfo &processAndError,
    const uint32_t &handle, const CppParamSet &paramSet, const std::vector<uint8_t> &inData,
    std::vector<uint8_t> &outData))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_FINISH_SESSION, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "FinishSession method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnFinishSessionFunc>(funcPtr))(processAndError, handle, paramSet, inData, outData);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "FinishSession fail, ret = %{public}d", ret)
    HKS_LOG_I("finish session success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnGenerateKey(struct HksProcessWithErrorInfo &processAndError,
    const std::string &resourceId, const CppParamSet &paramSet))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_GENERATE_KEY, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "GenerateKey method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnGenerateKeyFunc>(funcPtr))(processAndError, resourceId, paramSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "GenerateKey fail, ret = %{public}d", ret)
    HKS_LOG_I("generate key success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnAbortSession(struct HksProcessWithErrorInfo &processAndError,
    const uint32_t &handle, const CppParamSet &paramSet))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_ABORT_SESSION, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "AbortSession method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnAbortSessionFunc>(funcPtr))(processAndError, handle, paramSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "AbortSession fail, ret = %" LOG_PUBLIC "d", ret)
    HKS_LOG_I("abort session success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnUnregisterAllObservers())
{
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_UNREGISTER_ALL_OBSERVERS, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "UnregisterAllObservers method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnUnregisterAllObserversFunc>(funcPtr))();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "UnregisterAllObservers fail, ret = %{public}d", ret)
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnImportWrappedKey(struct HksProcessWithErrorInfo &processAndError,
    const std::string &index, const std::string &wrappingKeyIndex, const CppParamSet &paramSet,
    const std::vector<uint8_t> &wrappedData))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_IMPORT_WRAPPED_KEY, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "ImportWrappedKey method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnImportWrappedKeyFunc>(funcPtr))
        (processAndError, index, wrappingKeyIndex, paramSet, wrappedData);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "ImportWrappedKey fail, ret = %" LOG_PUBLIC "d", ret)
    HKS_LOG_I("import wrapped key success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnExportPublicKey(struct HksProcessWithErrorInfo &processAndError,
    const std::string &index, const CppParamSet &paramSet, std::vector<uint8_t> &outData))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_EXPORT_PUBLIC_KEY, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "ExportPublicKey method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnExportPublicKeyFunc>(funcPtr))(processAndError, index, paramSet, outData);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "ExportPublicKey fail, ret = %" LOG_PUBLIC "d", ret)
    HKS_LOG_I("export public key success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnGetResourceId(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::string &resourceId,
    struct HksExternalErrorInfo **errInfo))
{
    AutoRefCount refCnt(m_refCount, soMutex);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_GET_RESOURCE_ID, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "GetResourceId method enum not found in plugin provider map.")

    int32_t ret = (*reinterpret_cast<OnGetResourceIdFunc>(funcPtr))(processInfo, providerName, paramSet, resourceId,
        errInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "GetResourceId fail, ret = %" LOG_PUBLIC "d", ret)
    HKS_LOG_I("get resource id success");
    return HKS_SUCCESS;
}

}
}
}