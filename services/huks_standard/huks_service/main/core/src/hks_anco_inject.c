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

#include "hks_anco_inject.h"

#include <securec.h>
#include <stdbool.h>

#include "hks_common_check.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"

#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
#include "hks_bms_api_wrap.h"
#include "parameter.h"
#endif

bool HksIsAncoBrokerCall(const struct HksParamSet *paramSet)
{
    if (paramSet == NULL) {
        return false;
    }
    struct HksParam *dummyParam = NULL;
    return (HksGetParam(paramSet, HKS_TAG_ANCO_APP_UID, &dummyParam) == HKS_SUCCESS);
}

int32_t HksInjectCertTypeForAncoBroker(struct HksParamSet *newParamSet, uint32_t uidInt)
{
    if (newParamSet == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (!HksIsAncoBrokerCall(newParamSet)) {
        return HKS_SUCCESS; /* non-ANCO broker call, skip injection */
    }
    struct HksParam certTypeParam = {
        .tag = HKS_TAG_ATTESTATION_CERT_TYPE,
        .uint32Param = HKS_ATTESTATION_CERT_TYPE_RSA
    };
    int32_t ret = HksAddParams(newParamSet, &certTypeParam, 1);
    if (ret == HKS_SUCCESS) {
        HKS_LOG_I("anco broker (uid=%{public}u, has ANCO_APP_UID), inject CERT_TYPE=RSA for compat attest", uidInt);
    }
    return ret;
}

#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
// read mandatory ANCO_APP_UID (uint32 blob) from paramSet; fails if missing or invalid
static int32_t ReadAncoApkUid(const struct HksParamSet *paramSet, uint32_t *outApkUid)
{
    struct HksParam *ancoUidParam = NULL;
    if (HksGetParam(paramSet, HKS_TAG_ANCO_APP_UID, &ancoUidParam) != HKS_SUCCESS) {
        HKS_LOG_E("InjectAncoAttestApplicationId: no ANCO_APP_UID");
        return HKS_ERROR_NOT_SUPPORTED;
    }
    if (ancoUidParam->blob.size != sizeof(uint32_t) || ancoUidParam->blob.data == NULL) {
        HKS_LOG_E("ANCO_APP_UID blob invalid size=%u", ancoUidParam->blob.size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    uint32_t apkUid = 0;
    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(&apkUid, sizeof(uint32_t), ancoUidParam->blob.data, ancoUidParam->blob.size),
        HKS_ERROR_INVALID_ARGUMENT, "memcpy ANCO_APP_UID failed")
    HKS_LOG_I("InjectAncoAttestApplicationId read ANCO_APP_UID apkUid=%{public}u", apkUid);
    *outApkUid = apkUid;
    return HKS_SUCCESS;
}

// read optional ANCO attest params (userId, versionCode, signature) from paramSet;
static void ReadAncoOptionalParams(const struct HksParamSet *paramSet,
    int32_t *outUserId, uint64_t *outVersionCode, const struct HksBlob **outSignature)
{
    struct HksParam *ancoUserIdParam = NULL;
    int32_t userId = 0;
    if (HksGetParam(paramSet, HKS_TAG_ANCO_USER_ID, &ancoUserIdParam) == HKS_SUCCESS) {
        userId = (int32_t)ancoUserIdParam->uint32Param;
    }
    HKS_LOG_I("InjectAncoAttestApplicationId read ANCO_USER_ID userId=%{public}d", userId);
    *outUserId = userId;

    struct HksParam *verCodeParam = NULL;
    uint64_t versionCode = 0;
    if (HksGetParam(paramSet, HKS_TAG_ANCO_APP_VERSION_CODE, &verCodeParam) == HKS_SUCCESS) {
        versionCode = verCodeParam->uint64Param;
    }
    *outVersionCode = versionCode;

    struct HksParam *sigParam = NULL;
    const struct HksBlob *signature = NULL;
    if (HksGetParam(paramSet, HKS_TAG_ANCO_APP_SIGNATURE, &sigParam) == HKS_SUCCESS) {
        signature = &sigParam->blob;
    }
    *outSignature = signature;
}

// read ANCO attest parameters (uid, userId, versionCode, signature) from paramSet
static int32_t ReadAncoAttestParams(const struct HksParamSet *paramSet,
    uint32_t *outApkUid, int32_t *outUserId, uint64_t *outVersionCode,
    const struct HksBlob **outSignature)
{
    int32_t ret = ReadAncoApkUid(paramSet, outApkUid);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ReadAncoOptionalParams(paramSet, outUserId, outVersionCode, outSignature);
    return HKS_SUCCESS;
}

int32_t HksInjectAncoAttestApplicationId(struct HksParamSet *paramSet, struct HksBlob *outAppIdBuf)
{
    if (paramSet == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    uint32_t apkUid = 0;
    int32_t userId = 0;
    uint64_t versionCode = 0;
    const struct HksBlob *signature = NULL;
    int32_t ret = ReadAncoAttestParams(paramSet, &apkUid, &userId, &versionCode, &signature);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    struct HksBlob appId = { 0, NULL };
    ret = HksGetAncoAttestApplicationId(apkUid, userId, versionCode, signature, &appId);
    HKS_LOG_I("HksGetAncoAttestApplicationId ret=%{public}d appId.size=%{public}u", ret, appId.size);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksGetAncoAttestApplicationId failed uid=%u", apkUid)

    struct HksParam params[] = {
        { .tag = HKS_TAG_ATTESTATION_APPLICATION_ID, .blob = appId },
        { .tag = HKS_TAG_ATTESTATION_APPLICATION_ID_TYPE, .uint32Param = HKS_HAP_TYPE },
        { .tag = HKS_TAG_APPLICATION_ID, .blob = appId }
    };
    ret = HksAddParams(paramSet, params, HKS_ARRAY_SIZE(params));
    if (outAppIdBuf != NULL) {
        *outAppIdBuf = appId;
    } else {
        HKS_FREE_BLOB(appId);
    }
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "add AncoAttestApplicationId failed")
    HKS_LOG_I("InjectAncoAttestApplicationId success uid=%u userId=%d", apkUid, userId);
    return HKS_SUCCESS;
}
#endif /* HKS_SUPPORT_GET_BUNDLE_INFO */

#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
// Mirrors AddAppInfoToParamSet: get appInfo by caller type, inject APPLICATION_ID + APPLICATION_ID_TYPE.
// Returns HKS_SUCCESS and skips injection (non-fatal) if appInfo is unavailable.
static int32_t GenKeyAddAppInfo(const struct HksProcessInfo *processInfo, struct HksParamSet *paramSet)
{
    struct HksBlob appInfo = { 0, NULL };
    enum HksCallerType appidType = HksGetCallerType();
    int32_t ret = HKS_SUCCESS;
    if (appidType == HKS_HAP_TYPE) {
        ret = HksGetHapInfo(processInfo, &appInfo);
        HKS_IF_NOT_SUCC_LOGE(ret, "HksGetHapInfo failed")
    } else if (appidType == HKS_SA_TYPE) {
        ret = HksGetSaInfo(&appInfo);
        HKS_IF_NOT_SUCC_LOGE(ret, "HksGetSaInfo failed")
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_W("gen key: get appInfo failed callerType=%{public}d ret=%{public}d, skip inject appId",
            appidType, ret);
        return HKS_SUCCESS;
    }
    ret = CheckBlob(&appInfo);
    if (ret != HKS_SUCCESS) {
        HKS_FREE_BLOB(appInfo);
        HKS_LOG_W("gen key: appInfo blob invalid, skip inject appId");
        return HKS_SUCCESS;
    }
    struct HksParam appParams[] = {
        { .tag = HKS_TAG_ATTESTATION_APPLICATION_ID, .blob = appInfo },
        { .tag = HKS_TAG_ATTESTATION_APPLICATION_ID_TYPE, .uint32Param = appidType }
    };
    ret = HksAddParams(paramSet, appParams, HKS_ARRAY_SIZE(appParams));
    HKS_FREE_BLOB(appInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "gen key: add appInfo params failed ret=%{public}d", ret)
    return HKS_SUCCESS;
}

// Mirrors AddModelToParamSet: inject HKS_TAG_ATTESTATION_ID_MODEL from GetProductModel.
static int32_t GenKeyAddModel(struct HksParamSet *paramSet)
{
    const char *modelPtr = GetProductModel();
    if (modelPtr == NULL) {
        return HKS_SUCCESS; /* non-fatal: skip if product model unavailable */
    }
    struct HksParam modelParam = {
        .tag = HKS_TAG_ATTESTATION_ID_MODEL,
        .blob = { .size = strlen(modelPtr), .data = (uint8_t *)modelPtr }
    };
    int32_t ret = HksAddParams(paramSet, &modelParam, 1);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "gen key: add model failed ret=%{public}d", ret)
    return HKS_SUCCESS;
}

// inject APPLICATION_ID + APPLICATION_ID_TYPE + MODEL into keyBlob for non-ANCO-broker callers,
int32_t HksInjectAppInfoForNonAncoGenKey(const struct HksProcessInfo *processInfo, struct HksParamSet **inOutParamSet)
{
    if (inOutParamSet == NULL || *inOutParamSet == NULL || processInfo == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParamSet *newParamSet = NULL;
    int32_t ret = AppendToNewParamSet(*inOutParamSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "gen key: AppendToNewParamSet failed ret=%{public}d", ret)

    ret = GenKeyAddAppInfo(processInfo, newParamSet);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    ret = GenKeyAddModel(newParamSet);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&newParamSet);
        return ret;
    }

    ret = HksBuildParamSet(&newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("gen key: HksBuildParamSet failed ret=%{public}d", ret);
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    HksFreeParamSet(inOutParamSet);
    *inOutParamSet = newParamSet;
    HKS_LOG_I("gen key: inject APPLICATION_ID+TYPE+MODEL into keyblob for non-anco caller");
    return HKS_SUCCESS;
}

int32_t HksInjectAncoAppInfoForGenKey(const struct HksProcessInfo *processInfo, struct HksParamSet **inOutParamSet)
{
    if (inOutParamSet == NULL || *inOutParamSet == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (!HksIsAncoBrokerCall(*inOutParamSet)) {
        /* non-ANCO broker: inject appId for anonymous attest (reads appId from keyBlob) */
        return HksInjectAppInfoForNonAncoGenKey(processInfo, inOutParamSet);
    }

    struct HksParamSet *newParamSet = NULL;
    int32_t ret = AppendToNewParamSet(*inOutParamSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "AppendToNewParamSet failed ret=%{public}d", ret)

    struct HksBlob appId = { 0, NULL };
    ret = HksInjectAncoAttestApplicationId(newParamSet, &appId);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InjectAncoAttestApplicationId failed ret=%{public}d", ret);
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    ret = HksInjectCertTypeForAncoBroker(newParamSet, processInfo->uidInt);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InjectCertTypeForAncoBroker failed ret=%{public}d", ret);
        HKS_FREE_BLOB(appId);
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    ret = HksBuildParamSet(&newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("gen key: HksBuildParamSet failed ret=%{public}d", ret);
        HKS_FREE_BLOB(appId);
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    HKS_FREE_BLOB(appId);
    HksFreeParamSet(inOutParamSet);
    *inOutParamSet = newParamSet;
    HKS_LOG_I("gen key: inject APPLICATION_ID+CERT_TYPE into keyblob ok");
    return HKS_SUCCESS;
}
#endif /* HKS_SUPPORT_GET_BUNDLE_INFO */