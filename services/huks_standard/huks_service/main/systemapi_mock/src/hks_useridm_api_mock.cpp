/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hks_useridm_api_wrap.h"
#include "user_idm_client.h"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"

#define USER_IAM OHOS::UserIam::UserAuth

static constexpr const uint32_t g_paramSidMax = 2;

static const struct SecInfoWrap SecInfoParams[g_paramSidMax] = {
    {
        .secureUid = 1,
        .enrolledInfoLen = 3
    }, {
        .secureUid = 2,
        .enrolledInfoLen = 1
    }
};

void *HksLockUserIdm(void)
{
    auto *cntr = new (std::nothrow) OHOS::Security::Hks::HksIpcCounter();
    HKS_IF_NULL_LOGE_RETURN(cntr, nullptr, "useridm mock new HksIpcCounter failed")
    int32_t ret = cntr->Wait();
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("useridm mock HksIpcCounter wait failed %" LOG_PUBLIC "d", ret);
        delete cntr;
        return nullptr;
    }
    return cntr;
}

void HksUnlockUserIdm(void *ptr)
{
    HKS_IF_NULL_LOGE_RETURN_VOID(ptr, "useridm mock HksUnlockUserIdm nullptr")
    delete static_cast<OHOS::Security::Hks::HksIpcCounter *>(ptr);
}

static int32_t ConvertToHksAuthType(enum USER_IAM::AuthType authType, enum HksUserAuthType *hksAuthType)
{
    switch (authType) {
        case USER_IAM::AuthType::FACE:
            *hksAuthType = HKS_USER_AUTH_TYPE_FACE;
            break;
        case USER_IAM::AuthType::FINGERPRINT:
            *hksAuthType =  HKS_USER_AUTH_TYPE_FINGERPRINT;
            break;
        case USER_IAM::AuthType::PIN:
            *hksAuthType =  HKS_USER_AUTH_TYPE_PIN;
            break;
        default:
            HKS_LOG_E("Invalid authType!");
            return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

static struct EnrolledInfoWrap EnrolledInfoParams[g_paramSidMax][3] = {
    {
        {
            .authType = HKS_USER_AUTH_TYPE_PIN,
            .enrolledId = 1
        }, {
            .authType = HKS_USER_AUTH_TYPE_FINGERPRINT,
            .enrolledId = 2
        }, {
            .authType = HKS_USER_AUTH_TYPE_FACE,
            .enrolledId = 3
        }
    }, {
        {
            .authType = HKS_USER_AUTH_TYPE_PIN,
            .enrolledId = 0
        }
    }
};

static int32_t g_ParamsId = 0;

int32_t HksUserIdmGetSecInfo(int32_t userId, struct SecInfoWrap **outSecInfo)
{
    (void)userId;
    if (outSecInfo == nullptr)
        return HKS_ERROR_INVALID_ARGUMENT;
    *outSecInfo = static_cast<struct SecInfoWrap *>(HksMalloc(sizeof(struct SecInfoWrap)));
    HKS_IF_NULL_RETURN(*outSecInfo, HKS_ERROR_MALLOC_FAIL)
    (*outSecInfo)->enrolledInfo = static_cast<struct EnrolledInfoWrap *>(
        HksMalloc(sizeof(struct EnrolledInfoWrap) * SecInfoParams[g_ParamsId].enrolledInfoLen));
    if ((*outSecInfo)->enrolledInfo == NULL) {
        HKS_FREE(*outSecInfo);
        return HKS_ERROR_MALLOC_FAIL;
    }
    (*outSecInfo)->secureUid = SecInfoParams[g_ParamsId].secureUid;
    (*outSecInfo)->enrolledInfoLen = SecInfoParams[g_ParamsId].enrolledInfoLen;
    for (uint32_t i = 0; i < SecInfoParams[g_ParamsId].enrolledInfoLen; i++) {
        (*outSecInfo)->enrolledInfo[i] = EnrolledInfoParams[g_ParamsId][i];
    }
    return HKS_SUCCESS;
}

int32_t HksUserIdmGetAuthInfoNum(int32_t userId, enum HksUserAuthType hksAuthType, uint32_t *numOfAuthInfo)
{
    *numOfAuthInfo = 1;
    return HKS_SUCCESS;
}

int32_t HksConvertUserIamTypeToHksType(enum HksUserIamType userIamType, uint32_t userIamValue, uint32_t *hksValue)
{
    HKS_IF_NULL_RETURN(hksValue, HKS_ERROR_NULL_POINTER)
    HKS_IF_TRUE_RETURN(userIamType != HKS_AUTH_TYPE, HKS_ERROR_NOT_SUPPORTED)
    return ConvertToHksAuthType((enum USER_IAM::AuthType)userIamValue, (enum HksUserAuthType *)hksValue);
}
