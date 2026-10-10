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

#include "hks_ukey_system_adapter.h"
#include "hks_log.h"
#include "hks_template.h"
#include "os_account_manager.h"
#include "accesstoken_kit.h"
#include <cinttypes>

namespace OHOS::Security::Huks {

int32_t HksGetFrontUserId(int32_t &outId)
{
    std::vector<int> ids{};
    int ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    HKS_IF_TRUE_LOGE_RETURN(ret != OHOS::ERR_OK || ids.empty(), HKS_FAILURE,
        "QueryActiveOsAccountIds Failed!! ret = %" LOG_PUBLIC "d", ret)
    HKS_LOG_I("QueryActiveOsAccountIds success: FrontUserId= %" LOG_PUBLIC "d", ids[0]);
    outId = ids[0];
    return HKS_SUCCESS;
}

bool HksIsCallerSystemApp(const HksProcessInfo *processInfo)
{
    HKS_IF_NULL_LOGE_RETURN(processInfo, false, "HksIsCallerSystemApp: processInfo null")
    if (processInfo->accessTokenId == 0) {
        HKS_LOG_E("HksIsCallerSystemApp: caller accessTokenId is zero");
        return false;
    }
    // tokenAttr matches the high 32 bits of the full tokenIDEx (accesstoken_info_manager.cpp
    // sets tokenIdEx.tokenIdExStruct.tokenAttr |= SYSTEM_APP_FLAG when creating the token),
    // SYSTEM_APP_FLAG = 0x1. Hence (hapInfo.tokenAttr & 0x1) is bit-equivalent to the
    // pre-refactor IsSystemAppByFullTokenID(caller's full token).
    constexpr unsigned int SYSTEM_APP_FLAG = 0x0001;
    OHOS::Security::AccessToken::HapTokenInfo hapInfo;
    int ret = OHOS::Security::AccessToken::AccessTokenKit::GetHapTokenInfo(
        static_cast<OHOS::Security::AccessToken::AccessTokenID>(processInfo->accessTokenId), hapInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != OHOS::ERR_OK || (hapInfo.tokenAttr & SYSTEM_APP_FLAG) == 0, false,
        "HksIsCallerSystemApp: not system hap, ret=%" LOG_PUBLIC "d accessTokenId=%" LOG_PUBLIC PRIu64,
        ret, processInfo->accessTokenId)
    return true;
}

int32_t VerifyCallerAndAdjustUidParam(const HksProcessInfo &processInfo, const CppParamSet &paramSet,
    CppParamSet &newParamSet)
{
    auto uidParam = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_UID>();
    if (uidParam.first != HKS_SUCCESS) {
        std::vector<HksParam> params = {
            { .tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)}
        };
        newParamSet = CppParamSet(paramSet, params);
        HKS_IF_NULL_LOGE_RETURN(newParamSet.GetParamSet(), HKS_ERROR_NULL_POINTER, "new paramset fail.")
        return HKS_SUCCESS;
    }
    HKS_IF_NOT_TRUE_LOGE_RETURN(HksIsCallerSystemApp(&processInfo), HKS_ERROR_UKEY_NOT_SYSTEM_APP,
        "VerifyCallerAndAdjustUidParam: not system hap, check permission failed.")
    newParamSet = CppParamSet(paramSet);
    return HKS_SUCCESS;
}

}
