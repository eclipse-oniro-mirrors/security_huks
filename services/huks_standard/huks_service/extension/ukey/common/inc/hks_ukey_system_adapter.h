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

#ifndef HKS_UKEY_SYSTEM_ADAPTER_H
#define HKS_UKEY_SYSTEM_ADAPTER_H

#include "hks_plugin_def.h"
#include "hks_cpp_paramset.h"
#include <string>

namespace OHOS {
namespace Security {
namespace Huks {

    int32_t HksGetFrontUserId(int32_t &outId);
    int32_t VerifyCallerAndAdjustUidParam(const HksProcessInfo &processInfo, const CppParamSet &paramSet,
        CppParamSet &newParamSet);

    // Caller system-app check (worker-thread safe). When the ukey plugin runs on the
    // huks_service worker thread (the ukey async refactor thread pool), there is no IPC
    // context: IPCSkeleton::GetCallingFullTokenID() falls back to the service's own token
    // (native, not a HAP), so IsSystemAppByFullTokenID would wrongly reject system apps.
    // processInfo.accessTokenId is the caller's real tokenID captured by the IPC thread on
    // admission (correct on both sync and async paths); here its system-app flag is queried
    // via AccessTokenKit::GetHapTokenInfo, consistent with the pre-refactor semantics of
    // IsSystemAppByFullTokenID(caller's full token).
    bool HksIsCallerSystemApp(const HksProcessInfo *processInfo);

}
}
}

#endif
