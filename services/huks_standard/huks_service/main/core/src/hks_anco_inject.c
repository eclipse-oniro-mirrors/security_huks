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
#endif

bool HksIsAncoBrokerCall(const struct HksParamSet *paramSet)
{
    if (paramSet == NULL) {
        return false;
    }
    struct HksParam *ancoUidParam = NULL;
    return (HksGetParam(paramSet, HKS_TAG_ANCO_APP_UID, &ancoUidParam) == HKS_SUCCESS);
}

int32_t HksInjectCertTypeForAncoBroker(struct HksParamSet *newParamSet, const struct HksParamSet *origParamSet)
{
    if (newParamSet == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (!HksIsAncoBrokerCall(origParamSet)) {
        return HKS_SUCCESS; /* non-ANCO broker call, skip injection */
    }
    struct HksParam *existCertType = NULL;
    if (HksGetParam(newParamSet, HKS_TAG_ATTESTATION_CERT_TYPE, &existCertType) == HKS_SUCCESS) {
        HKS_LOG_I("anco broker: CERT_TYPE already injected, skip");
        return HKS_SUCCESS;
    }
    struct HksParam certTypeParam = {
        .tag = HKS_TAG_ATTESTATION_CERT_TYPE,
        .uint32Param = HKS_ATTESTATION_CERT_TYPE_RSA
    };
    int32_t ret = HksAddParams(newParamSet, &certTypeParam, 1);
    if (ret == HKS_SUCCESS) {
        HKS_LOG_I("anco broker (has ANCO_APP_UID), inject CERT_TYPE=RSA for compat attest");
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

    // ATTESTATION_APPLICATION_ID: blob=appId (bundleName|versionCode|signature), DCM reads it to write cert claim.
    // ATTESTATION_APPLICATION_ID_TYPE: HKS_HAP_TYPE, DCM reads it to select OID (hksApplicationIdRawOid).
    struct HksParam params[] = {
        { .tag = HKS_TAG_ATTESTATION_APPLICATION_ID, .blob = appId },
        { .tag = HKS_TAG_ATTESTATION_APPLICATION_ID_TYPE, .uint32Param = HKS_HAP_TYPE }
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
int32_t HksInjectAncoAppInfoForGenKey(const struct HksProcessInfo *processInfo, struct HksParamSet **inOutParamSet)
{
    (void)processInfo;
    if (inOutParamSet == NULL || *inOutParamSet == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    // non-ANCO broker: keep original behavior — do NOT inject APPLICATION_ID into keyBlob.
    // attest path reads appInfo at attest time via AddAppInfoAndModelToParamSet (original behavior).
    if (!HksIsAncoBrokerCall(*inOutParamSet)) {
        return HKS_SUCCESS;
    }

    struct HksParamSet *newParamSet = NULL;
    int32_t ret = AppendToNewParamSet(*inOutParamSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "AppendToNewParamSet failed ret=%{public}d", ret)

    struct HksBlob appId = { 0, NULL };
    ret = HksInjectAncoAttestApplicationId(newParamSet, &appId);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InjectAncoAttestApplicationId failed ret=%{public}d", ret);
        HKS_FREE_BLOB(appId);
        HksFreeParamSet(&newParamSet);
        return ret;
    }
    ret = HksInjectCertTypeForAncoBroker(newParamSet, *inOutParamSet);
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