/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef HKS_BASE_CHECK_H
#define HKS_BASE_CHECK_H

#include "hks_param.h"
#include "hks_type_inner.h"

enum CheckKeyType {
    HKS_CHECK_TYPE_GEN_KEY,
    HKS_CHECK_TYPE_USE_KEY,
    HKS_CHECK_TYPE_GEN_MAC_KEY,
    HKS_CHECK_TYPE_GEN_DERIVE_KEY,
};

struct Params {
    bool needCheck;
    uint32_t value;
    bool isAbsent;
};

struct ParamsValues {
    struct Params keyLen;
    struct Params padding;
    struct Params purpose;
    struct Params digest;
    struct Params mode;
};

struct ParamsValuesChecker {
    enum CheckKeyType checkType;
    struct ParamsValues paramValues;
};

struct ExpectParams {
    bool needCheck;
    const uint32_t *values;
    uint32_t valueCnt;
};

struct ExpectParamsValues {
    const struct ExpectParams keyLen;
    const struct ExpectParams padding;
    const struct ExpectParams purpose;
    const struct ExpectParams digest;
    const struct ExpectParams mode;
};
#define EXPECT_PARAMS_VALUES_INIT {{0}, {0}, {0}, {0}, {0}}

struct ExpectParamsValuesChecker {
    enum CheckKeyType checkType;
    const struct ExpectParamsValues paramValues;
};

struct HksAlgParamSetHandler {
    enum HksKeyAlg alg;
    const struct ParamsValuesChecker *algParamSet;
    uint32_t algParamSetCnt;
    const struct ExpectParamsValuesChecker *expectParams;
    uint32_t expectParamsCnt;
};

struct AuthAccessTypeChecker {
    enum HksUserAuthType userAuthType;
    const struct ExpectParams allowAuthAccessTypes;
};

struct KeyInfoParams {
    bool needCheck;
    enum HksTag tag;
    const uint32_t *values;
    uint32_t valueCnt;
};

struct AuthAcceessKeyInfoChecker {
    enum HksKeyAlg keyAlg;
    const struct KeyInfoParams *params;
    uint32_t paramsCnt;
};

#define HKS_ROOT_USER_UPPERBOUND 100

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksCheckValue(uint32_t inputValue, const uint32_t *expectValues, uint32_t valuesCount);

int32_t HksGetKeySize(uint32_t alg, const struct HksBlob *key, uint32_t *keySize);

int32_t HksCheckGenKeyPurpose(uint32_t alg, uint32_t inputPurpose, uint32_t keyFlag);

#ifdef HKS_SUPPORT_RSA_C
#ifdef HKS_SUPPORT_RSA_C_FLEX_KEYSIZE
int32_t CheckRsaKeySize(uint32_t keyLen);
#endif
#endif

int32_t HksCheckGenKeyMutableParams(uint32_t alg, const struct ParamsValues *inputParams);

int32_t CheckImportMutableParams(uint32_t alg, const struct ParamsValues *params);

int32_t HksCheckSignature(uint32_t cmdId, uint32_t alg, uint32_t keySize, const struct HksBlob *signature);

int32_t HksCheckSignVerifyMutableParams(uint32_t cmdId, uint32_t alg, const struct ParamsValues *inputParams);

int32_t HksCheckCipherMutableParams(uint32_t cmdId, uint32_t alg, const struct ParamsValues *inputParams);

int32_t HksCheckCipherData(uint32_t cmdId, uint32_t alg, const struct ParamsValues *inputParams,
    const struct HksBlob *inData, const struct HksBlob *outData);

int32_t HksCheckCipherMaterialParams(uint32_t alg, const struct ParamsValues *inputParams,
    const struct HksParamSet *paramSet);

int32_t HksCheckUserAuthParams(uint32_t userAuthType, uint32_t authAccessType, uint32_t challengeType);

int32_t HksCheckSecureSignParams(uint32_t secureSignType);

int32_t GetInputParams(const struct HksParamSet *paramSet, struct ParamsValues *inputParams);

int32_t HksCheckNeedCache(uint32_t alg, uint32_t digest);

int32_t HksCheckUserAuthKeyInfoValidity(const struct HksParamSet *paramSet);

int32_t InitInputParamsByAlg(uint32_t alg, enum CheckKeyType checkType, struct ParamsValues *inputParams);

int32_t GetExpectParams(uint32_t alg, enum CheckKeyType checkType, struct ExpectParamsValues *expectValues);

static inline bool HksAttestIsAnonymous(const struct HksParamSet *paramSet)
{
    struct HksParam *attestParam = NULL;
    if (HksGetParam(paramSet, HKS_TAG_ATTESTATION_MODE, &attestParam) == HKS_SUCCESS) {
        return attestParam->uint32Param == HKS_ATTESTATION_MODE_ANONYMOUS;
    }
    return false;
}

#ifdef __cplusplus
}
#endif

#endif /* HKS_BASE_CHECK_H */

