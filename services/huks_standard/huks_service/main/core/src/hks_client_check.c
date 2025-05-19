/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "hks_client_check.h"

#include <stddef.h>

#include "hks_base_check.h"
#include "hks_common_check.h"
#include "hks_log.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_mem.h"
#include "hks_storage_manager.h"

#include "securec.h"

#ifdef L2_STANDARD
static const uint32_t CHANGE_STORAGE_LEVEL_CFG_LIST[] = HUKS_CHANGE_STORAGE_LEVEL_CONFIG;
#endif

#ifndef _CUT_AUTHENTICATE_
static int32_t CheckProcessNameAndKeyAliasSize(uint32_t processNameSize, uint32_t keyAliasSize)
{
    HKS_IF_TRUE_LOGE_RETURN(processNameSize > HKS_MAX_PROCESS_NAME_LEN, HKS_ERROR_INVALID_ARGUMENT,
        "processName size too long, size %" LOG_PUBLIC "u", processNameSize)

    HKS_IF_TRUE_LOGE_RETURN(keyAliasSize > HKS_MAX_KEY_ALIAS_LEN, HKS_ERROR_INVALID_ARGUMENT,
        "keyAlias size too long, size %" LOG_PUBLIC "u", keyAliasSize)

    return HKS_SUCCESS;
}

int32_t HksCheckProcessNameAndKeyAlias(const struct HksBlob *processName, const struct HksBlob *keyAlias)
{
    HKS_IF_NOT_SUCC_RETURN(HksCheckBlob2(processName, keyAlias), HKS_ERROR_INVALID_ARGUMENT)

    return CheckProcessNameAndKeyAliasSize(processName->size, keyAlias->size);
}

int32_t HksCheckGenAndImportKeyParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, const struct HksBlob *key)
{
    int32_t ret = HksCheckBlob3AndParamSet(processName, keyAlias, key, paramSetIn);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    return CheckProcessNameAndKeyAliasSize(processName->size, keyAlias->size);
}

int32_t HksCheckImportWrappedKeyParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksBlob *wrappingKeyAlias, const struct HksParamSet *paramSetIn, const struct HksBlob *wrappedKeyData)
{
    int32_t ret = HksCheckBlob4AndParamSet(processName, keyAlias, wrappingKeyAlias, wrappedKeyData, paramSetIn);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = CheckProcessNameAndKeyAliasSize(processName->size, keyAlias->size);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    return CheckProcessNameAndKeyAliasSize(processName->size, wrappingKeyAlias->size);
}

int32_t HksCheckAllParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *data1, const struct HksBlob *data2)
{
    int32_t ret = HksCheckBlob4AndParamSet(processName, keyAlias, data1, data2, paramSet);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    return CheckProcessNameAndKeyAliasSize(processName->size, keyAlias->size);
}

int32_t HksCheckServiceInitParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet)
{
    int32_t ret = HksCheckBlob2AndParamSet(processName, keyAlias, paramSet);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    return CheckProcessNameAndKeyAliasSize(processName->size, keyAlias->size);
}

int32_t HksCheckGetKeyParamSetParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet)
{
    HKS_IF_NOT_SUCC_RETURN(HksCheckProcessNameAndKeyAlias(processName, keyAlias), HKS_ERROR_INVALID_ARGUMENT)

    HKS_IF_TRUE_LOGE_RETURN(paramSet == NULL || paramSet->paramSetSize == 0, HKS_ERROR_INVALID_ARGUMENT,
        "invalid paramSet")

    return HKS_SUCCESS;
}

int32_t HksCheckExportPublicKeyParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksBlob *key)
{
    HKS_IF_NOT_SUCC_RETURN(HksCheckBlob3(processName, keyAlias, key), HKS_ERROR_INVALID_ARGUMENT)

    return CheckProcessNameAndKeyAliasSize(processName->size, keyAlias->size);
}

int32_t HksCheckDeriveKeyParams(const struct HksBlob *processName, const struct HksParamSet *paramSet,
    const struct HksBlob *mainKey, const struct HksBlob *derivedKey)
{
    return HksCheckGenAndImportKeyParams(processName, mainKey, paramSet, derivedKey);
}

int32_t HksCheckGetKeyInfoListParams(const struct HksBlob *processName, const struct HksKeyInfo *keyInfoList,
    const uint32_t *listCount)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(processName), HKS_ERROR_INVALID_ARGUMENT, "invalid processName")

    HKS_IF_TRUE_LOGE_RETURN(processName->size > HKS_MAX_PROCESS_NAME_LEN, HKS_ERROR_INVALID_ARGUMENT,
        "processName size too long, size %" LOG_PUBLIC "u", processName->size)

    HKS_IF_TRUE_LOGE_RETURN(keyInfoList == NULL || listCount == NULL, HKS_ERROR_INVALID_ARGUMENT,
        "keyInfoList or listCount null.")

    for (uint32_t i = 0; i < *listCount; ++i) {
        HKS_IF_TRUE_RETURN(CheckBlob(&(keyInfoList[i].alias)) != HKS_SUCCESS || keyInfoList[i].paramSet == NULL ||
            keyInfoList[i].paramSet->paramSetSize == 0, HKS_ERROR_INVALID_ARGUMENT)
    }

    return HKS_SUCCESS;
}
#endif /* _CUT_AUTHENTICATE_ */

int32_t HksCheckGenerateRandomParams(const struct HksBlob *processName, const struct HksBlob *random)
{
    HKS_IF_NOT_SUCC_RETURN(HksCheckBlob2(processName, random), HKS_ERROR_INVALID_ARGUMENT)

    if (processName->size > HKS_MAX_PROCESS_NAME_LEN) {
        HKS_LOG_E("processName size too long, size %" LOG_PUBLIC "u.", processName->size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (random->size > HKS_MAX_RANDOM_LEN) {
        HKS_LOG_E("random size too long, size %" LOG_PUBLIC "u.", random->size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

#ifdef HKS_SUPPORT_API_ATTEST_KEY
int32_t HksCheckAttestKeyParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *certChain)
{
    return HksCheckGenAndImportKeyParams(processName, keyAlias, paramSet, certChain);
}
#endif

#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
static int32_t CheckAuthAccessLevel(const struct HksParamSet *paramSet)
{
    struct HksParam *authAccess = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_KEY_AUTH_ACCESS_TYPE, &authAccess);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_ACCESS_TYPE_FAILED, "get auth access type fail")

    HKS_IF_TRUE_LOGE_RETURN(authAccess->uint32Param < HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD,
        HKS_ERROR_INVALID_ARGUMENT, "auth access level is too low")
    return HKS_SUCCESS;
}

static int32_t CheckUserAuthParamsValidity(const struct HksParamSet *paramSet, uint32_t userAuthType,
    uint32_t authAccessType, uint32_t challengeType)
{
    int32_t ret = HksCheckUserAuthParams(userAuthType, authAccessType, challengeType);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check user auth params failed")

    if (challengeType == HKS_CHALLENGE_TYPE_NONE) {
        struct HksParam *authTimeout = NULL;
        ret = HksGetParam(paramSet, HKS_TAG_AUTH_TIMEOUT, &authTimeout);
        if (ret == HKS_SUCCESS) {
            HKS_IF_TRUE_LOGE_RETURN(authTimeout->uint32Param > MAX_AUTH_TIMEOUT_SECOND ||
                authTimeout->uint32Param == 0, HKS_ERROR_INVALID_TIME_OUT, "invalid auth timeout param")
        }
    }

    struct HksParam *secureSignType = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_KEY_SECURE_SIGN_TYPE, &secureSignType);
    if (ret == HKS_SUCCESS) {
        ret = HksCheckSecureSignParams(secureSignType->uint32Param);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_SECURE_SIGN_TYPE, "secure sign type is invalid")

        /* secure sign ability only support sign-purpose algorithm */
        struct HksParam *purposeParam = NULL;
        ret = HksGetParam(paramSet, HKS_TAG_PURPOSE, &purposeParam);
        HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS || (purposeParam->uint32Param & HKS_KEY_PURPOSE_SIGN) == 0,
            HKS_ERROR_INVALID_ARGUMENT, "secure sign tag only support sign-purpose alg")
        ret = CheckAuthAccessLevel(paramSet);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT, "check auth access level fail")
    }

    return HKS_SUCCESS;
}
#endif

int32_t HksCheckAndGetUserAuthInfo(const struct HksParamSet *paramSet, uint32_t *userAuthType,
    uint32_t *authAccessType)
{
#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
    HKS_IF_NULL_LOGE_RETURN(paramSet, HKS_ERROR_NOT_SUPPORTED, "null init paramSet: not support user auth!")

    struct HksParam *noRequireAuth = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_NO_AUTH_REQUIRED, &noRequireAuth);
    if (ret == HKS_SUCCESS && noRequireAuth->boolParam == true) {
        HKS_LOG_I("no require auth=true");
        return HKS_ERROR_NOT_SUPPORTED;
    }

    struct HksParam *userAuthTypeParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_USER_AUTH_TYPE, &userAuthTypeParam);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, HKS_ERROR_NOT_SUPPORTED, "no user auth type param: not support user auth!")

    struct HksParam *accessTypeParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_KEY_AUTH_ACCESS_TYPE, &accessTypeParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_ACCESS_TYPE_FAILED, "get auth access type param failed")

    struct HksParam *challengeTypeParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_CHALLENGE_TYPE, &challengeTypeParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_CHALLENGE_TYPE_FAILED, "get challenge type param failed")

    ret = CheckUserAuthParamsValidity(paramSet, userAuthTypeParam->uint32Param, accessTypeParam->uint32Param,
        challengeTypeParam->uint32Param);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check user auth params validity failed")

    *userAuthType = userAuthTypeParam->uint32Param;
    *authAccessType = accessTypeParam->uint32Param;
    return HKS_SUCCESS;
#else
    (void)paramSet;
    (void)userAuthType;
    (void)authAccessType;
    return HKS_SUCCESS;
#endif
}

bool HksCheckIsAllowedWrap(const struct HksParamSet *paramSet)
{
    struct HksParam *isAllowedWrap = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_ALLOWED_WRAP, &isAllowedWrap);
    HKS_IF_NOT_SUCC_RETURN(ret, false)
    return isAllowedWrap->boolParam;
}

int32_t HksCheckUserAuthKeyPurposeValidity(const struct HksParamSet *paramSet)
{
#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
    HKS_IF_NULL_LOGE_RETURN(paramSet, HKS_ERROR_NULL_POINTER, "paramSet is null!")

    // step 1. Judge whether the user auth key purpose is set.
    struct HksParam *userAuthKeyPurposeParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_KEY_AUTH_PURPOSE, &userAuthKeyPurposeParam);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, HKS_SUCCESS, "not set key auth purpose: default need user auth access control!")

    // step 2. Judge whether the user auth key purpose is within the range of alogrithm key purpose.
    struct HksParam *keyPurposeParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_PURPOSE, &keyPurposeParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get key purpose param failed!")

    uint32_t keyPurpose = keyPurposeParam->uint32Param;
    if ((userAuthKeyPurposeParam->uint32Param == 0) ||
        (userAuthKeyPurposeParam->uint32Param | keyPurpose) != keyPurpose) {
        HKS_LOG_E("key auth purpose is invalid!");
        return HKS_ERROR_INVALID_PURPOSE;
    }

    // step 3. Judge the validify of symmetric and asymmetric algorithm settings for purpose.
    ret = HksCheckUserAuthKeyInfoValidity(paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckUserAuthKeyInfoValidity failed!")

    return HKS_SUCCESS;
#else
    (void)paramSet;
    return HKS_SUCCESS;
#endif
}

int32_t HksCheckListAliasesParam(const struct HksBlob *processName)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(processName), HKS_ERROR_INVALID_ARGUMENT, "invalid processName");

    HKS_IF_TRUE_LOGE_RETURN(processName->size > HKS_MAX_PROCESS_NAME_LEN, HKS_ERROR_INVALID_ARGUMENT,
        "processName size too long, size %" LOG_PUBLIC "u", processName->size)
    return HKS_SUCCESS;
}

int32_t HKsCheckOldKeyAliasDiffNewKeyAlias(const struct HksBlob *oldKeyAlias,
    const struct HksBlob *newKeyAlias)
{
    HKS_IF_TRUE_LOGE_RETURN(oldKeyAlias == NULL || newKeyAlias == NULL, HKS_ERROR_INVALID_ARGUMENT,
        "oldKeyAlias or newKeyAlias is null!")
    HKS_IF_TRUE_LOGE_RETURN(oldKeyAlias->size == newKeyAlias->size &&
        HksMemCmp(oldKeyAlias->data, newKeyAlias->data, oldKeyAlias->size) == 0, HKS_ERROR_ALREADY_EXISTS,
        "oldKeyAlias same as newKeyAlias!")
    return HKS_SUCCESS;
}

int32_t HksCheckOldKeyExist(const struct HksProcessInfo *processInfo, const struct HksBlob *oldKeyAlias,
    const struct HksParamSet *paramSet)
{
    int32_t ret = HksCheckProcessNameAndKeyAlias(&processInfo->processName, oldKeyAlias);
    HKS_IF_NOT_SUCC_RETURN(ret, ret);

    ret = HksManageStoreIsKeyBlobExist(processInfo, paramSet, oldKeyAlias, HKS_STORAGE_TYPE_KEY);
    HKS_IF_TRUE_LOGE(ret == HKS_ERROR_NOT_EXIST, "the oldKey not exist!")
    return ret;
}

int32_t HksCheckNewKeyNotExist(const struct HksProcessInfo *processInfo, const struct HksBlob *newKeyAlias,
    const struct HksParamSet *paramSet)
{
    int32_t ret = HksCheckProcessNameAndKeyAlias(&processInfo->processName, newKeyAlias);
    HKS_IF_NOT_SUCC_RETURN(ret, ret);

    ret = HksManageStoreIsKeyBlobExist(processInfo, paramSet, newKeyAlias, HKS_STORAGE_TYPE_KEY);
    HKS_IF_TRUE_LOGE_RETURN(ret == HKS_SUCCESS, HKS_ERROR_ALREADY_EXISTS, "the newKey is already exist!")
    HKS_IF_TRUE_LOGI_RETURN(ret == HKS_ERROR_NOT_EXIST, HKS_SUCCESS, "the newKey is  not exist!")
    return ret;
}

#ifdef L2_STANDARD
int32_t HksCheckProcessInConfigList(const struct HksBlob *processName)
{
    uint32_t uid = 0;
    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(&uid, sizeof(uid), processName->data, processName->size),
        HKS_ERROR_NO_PERMISSION, "illegal uid, please check your process name")

    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(CHANGE_STORAGE_LEVEL_CFG_LIST); ++i) {
        HKS_IF_TRUE_LOGI_RETURN(uid == CHANGE_STORAGE_LEVEL_CFG_LIST[i], HKS_SUCCESS,
            "%" LOG_PUBLIC "u could change storage level", uid)
    }
    HKS_LOG_E("%" LOG_PUBLIC "u don't have permission to change storage level", uid);
    return HKS_ERROR_NO_PERMISSION;
}

int32_t HksCheckChangeStorageLevelParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksParamSet *srcParamSet, const struct HksParamSet *destParamSet)
{
    // step 1. common check
    int32_t ret = HksCheckBlob2AndParamSet2(processName, keyAlias, srcParamSet, destParamSet);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = CheckProcessNameAndKeyAliasSize(processName->size, keyAlias->size);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    // step 2. Judge whether storage level is expected, currently only support d->c
    struct HksParam *srcStorageLevelParam = NULL;
    ret = HksGetParam(srcParamSet, HKS_TAG_AUTH_STORAGE_LEVEL, &srcStorageLevelParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "srcParamSet not set storage level!")

    HKS_IF_TRUE_LOGE_RETURN(srcStorageLevelParam->uint32Param != HKS_AUTH_STORAGE_LEVEL_DE, HKS_ERROR_NOT_SUPPORTED,
        "storage level in srcParamSet must be DE")

    struct HksParam *destStorageLevelParam = NULL;
    ret = HksGetParam(destParamSet, HKS_TAG_AUTH_STORAGE_LEVEL, &destStorageLevelParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "destParamSet not set storage level!")

    HKS_IF_TRUE_LOGE_RETURN(destStorageLevelParam->uint32Param != HKS_AUTH_STORAGE_LEVEL_CE, HKS_ERROR_NOT_SUPPORTED,
        "storage level in destParamSet must be CE")
    return HKS_SUCCESS;
}
#endif