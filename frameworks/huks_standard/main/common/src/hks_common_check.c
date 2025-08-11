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
#define HUKS_DISABLE_LOG_AT_FILE_TO_REDUCE_ROM_SIZE

#include "hks_common_check.h"

#include <stddef.h>

#include "hks_log.h"
#include "hks_param.h"
#include "hks_template.h"
#include "securec.h"

int32_t HksCheckBlob4(const struct HksBlob *data1, const struct HksBlob *data2,
    const struct HksBlob *data3, const struct HksBlob *data4)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(data1), HKS_ERROR_INVALID_ARGUMENT, "invalid data1.")

    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(data2), HKS_ERROR_INVALID_ARGUMENT, "invalid data2.")

    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(data3), HKS_ERROR_INVALID_ARGUMENT, "invalid data3.")

    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(data4), HKS_ERROR_INVALID_ARGUMENT, "invalid data4.")

    return HKS_SUCCESS;
}

int32_t HksCheckBlob3(const struct HksBlob *data1, const struct HksBlob *data2, const struct HksBlob *data3)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(data1), HKS_ERROR_INVALID_ARGUMENT, "invalid data1.")

    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(data2), HKS_ERROR_INVALID_ARGUMENT, "invalid data2.")

    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(data3), HKS_ERROR_INVALID_ARGUMENT, "invalid data3.")

    return HKS_SUCCESS;
}

int32_t HksCheckBlob2(const struct HksBlob *data1, const struct HksBlob *data2)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(data1), HKS_ERROR_INVALID_ARGUMENT, "invalid data1.")

    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(data2), HKS_ERROR_INVALID_ARGUMENT, "invalid data2.")

    return HKS_SUCCESS;
}

int32_t HksCheckParamSetValidity(const struct HksParamSet *paramSet)
{
    HKS_IF_NULL_LOGE_RETURN(paramSet, HKS_ERROR_NULL_POINTER, "paramSet NULL!")
    HKS_IF_NOT_SUCC_LOGE_RETURN(HksCheckParamSet(paramSet, paramSet->paramSetSize),
        HKS_ERROR_INVALID_ARGUMENT, "paramSet invalid!")

    return HksCheckParamSetTag(paramSet);
}

int32_t HksCheckBlob4AndParamSet(const struct HksBlob *data1, const struct HksBlob *data2,
    const struct HksBlob *data3, const struct HksBlob *data4, const struct HksParamSet *paramSet)
{
    int32_t ret = HksCheckBlob4(data1, data2, data3, data4);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    return HksCheckParamSetValidity(paramSet);
}

int32_t HksCheckBlob3AndParamSet(const struct HksBlob *data1, const struct HksBlob *data2,
    const struct HksBlob *data3, const struct HksParamSet *paramSet)
{
    int32_t ret = HksCheckBlob3(data1, data2, data3);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    return HksCheckParamSetValidity(paramSet);
}

int32_t HksCheckBlob2AndParamSet(const struct HksBlob *data1, const struct HksBlob *data2,
    const struct HksParamSet *paramSet)
{
    int32_t ret = HksCheckBlob2(data1, data2);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    return HksCheckParamSetValidity(paramSet);
}

int32_t HksCheckBlobAndParamSet(const struct HksBlob *data, const struct HksParamSet *paramSet)
{
    HKS_IF_NOT_SUCC_RETURN(CheckBlob(data), HKS_ERROR_INVALID_ARGUMENT)

    return HksCheckParamSetValidity(paramSet);
}

int32_t HksCheckBlobAndParamSet2(const struct HksBlob *data, const struct HksParamSet *paramSet1,
    const struct HksParamSet *paramSet2)
{
    int32_t ret = CheckBlob(data);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = HksCheckParamSetValidity(paramSet1);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = HksCheckParamSetValidity(paramSet2);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    return HKS_SUCCESS;
}

int32_t HksCheckBlob2AndParamSet2(const struct HksBlob *data1, const struct HksBlob *data2,
    const struct HksParamSet *paramSet1, const struct HksParamSet *paramSet2)
{
    int32_t ret = CheckBlob(data1);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = CheckBlob(data2);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = HksCheckParamSetValidity(paramSet1);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = HksCheckParamSetValidity(paramSet2);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    return HKS_SUCCESS;
}

int32_t HksGetDigestLen(uint32_t digest, uint32_t *digestLen)
{
    switch (digest) {
        case HKS_DIGEST_MD5:
            *digestLen = HKS_DIGEST_MD5_LEN;
            break;
        case HKS_DIGEST_SHA1:
            *digestLen = HKS_DIGEST_SHA1_LEN;
            break;
        case HKS_DIGEST_SHA224:
            *digestLen = HKS_DIGEST_SHA224_LEN;
            break;
        case HKS_DIGEST_SHA256:
            *digestLen = HKS_DIGEST_SHA256_LEN;
            break;
        case HKS_DIGEST_SHA384:
            *digestLen = HKS_DIGEST_SHA384_LEN;
            break;
        case HKS_DIGEST_SHA512:
            *digestLen = HKS_DIGEST_SHA512_LEN;
            break;
        case HKS_DIGEST_SM3:
            *digestLen = HKS_DIGEST_SM3_LEN;
            break;
        default:
            return HKS_ERROR_INVALID_DIGEST;
    }
    return HKS_SUCCESS;
}

int32_t HksCheckAesAeMode(const struct HksParamSet *paramSet, bool *isAes, bool *isAeMode)
{
    struct HksParam *algParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ALGORITHM, &algParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_ALG_FAIL, "append cipher get alg param failed!")
    *isAes = (algParam->uint32Param == HKS_ALG_AES);
    if (!(*isAes)) {
        return HKS_SUCCESS;
    }

    struct HksParam *modeParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_BLOCK_MODE, &modeParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_MODE_FAIL, "append cipher get mode param failed!")

    *isAeMode = (modeParam->uint32Param == HKS_MODE_CCM) || (modeParam->uint32Param == HKS_MODE_GCM);
    return HKS_SUCCESS;
}

int32_t HksCheckWrappedDataFormatValidity(const struct HksBlob *wrappedData, uint32_t validTotalBlobs,
    const uint32_t *validBlobLengths)
{
    if ((CheckBlob(wrappedData) != HKS_SUCCESS) || (wrappedData->size > HKS_WRAPPED_FORMAT_MAX_SIZE) ||
        (validTotalBlobs == 0)) {
        HKS_LOG_E("wrapped data format:invalid argument!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    const uint8_t *data = wrappedData->data;
    uint32_t dataSize = wrappedData->size;

    uint32_t offset = 0;
    uint32_t partDataLength = 0;
    uint32_t blobIndex = 0;

    for (blobIndex = 0; blobIndex < validTotalBlobs && offset < dataSize; blobIndex++) {
        if (((dataSize - offset) < sizeof(uint32_t))) {
            HKS_LOG_E("the residual data length is to small.");
            return HKS_ERROR_INVALID_WRAPPED_FORMAT;
        }
        partDataLength = 0;
        (void)memcpy_s((uint8_t *)&partDataLength, sizeof(uint32_t), data + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        if ((partDataLength == 0) || (partDataLength > dataSize - offset)) {
            HKS_LOG_E(" the blob part:%" LOG_PUBLIC "u length is out of range!", blobIndex);
            return HKS_ERROR_INVALID_WRAPPED_FORMAT;
        }
        offset += partDataLength;

        HKS_IF_TRUE_LOGE_RETURN((validBlobLengths != NULL) && (*(validBlobLengths + blobIndex) != partDataLength),
            HKS_ERROR_INVALID_WRAPPED_FORMAT,
            "the blob part:%" LOG_PUBLIC "u length is invalid, should be %" LOG_PUBLIC "u!",
            blobIndex, *(validBlobLengths + blobIndex));
    }

    if (offset != dataSize) {
        HKS_LOG_E("data is redundant!");
        return HKS_ERROR_INVALID_WRAPPED_FORMAT;
    }
    return HKS_SUCCESS;
}

int32_t HksGetBlobFromWrappedData(const struct HksBlob *wrappedData, uint32_t blobIndex, uint32_t totalBlobs,
    struct HksBlob *blob)
{
    if ((CheckBlob(wrappedData) != HKS_SUCCESS) || (blobIndex >= totalBlobs) || (blob == NULL)) {
        HKS_LOG_E("invalid argument!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    const uint8_t *data = wrappedData->data;
    uint32_t dataSize = wrappedData->size;
    uint32_t partDataLength = 0;

    for (uint32_t index = 0, offset = 0; index < totalBlobs && offset < dataSize; index++) {
        partDataLength = 0;
        (void)memcpy_s((uint8_t *)&partDataLength, sizeof(uint32_t), data + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        if ((partDataLength == 0) || (partDataLength > HKS_WRAPPED_FORMAT_MAX_SIZE) ||
            (partDataLength > dataSize - offset)) {
            return HKS_ERROR_INVALID_WRAPPED_FORMAT;
        }

        if (blobIndex == index) {
            blob->size = partDataLength;
            blob->data = (uint8_t *)(data + offset);
            return HKS_SUCCESS;
        }
        offset += partDataLength;
    }
    return HKS_ERROR_INVALID_WRAPPED_FORMAT;
}

int32_t HksCheckKeyNeedStored(const struct HksParamSet *paramSet, bool *isNeedStorage)
{
    struct HksParam *storageFlag = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_KEY_STORAGE_FLAG, &storageFlag);
    if ((ret == HKS_SUCCESS) && (storageFlag->uint32Param == HKS_STORAGE_PERSISTENT)) {
        *isNeedStorage = true;
        return ret;
    }
    ret = HksGetParam(paramSet, HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG, &storageFlag);
    if ((ret == HKS_SUCCESS) && (storageFlag->uint32Param == HKS_STORAGE_ONLY_USED_IN_HUKS)) {
        *isNeedStorage = true;
        return ret;
    }
    return ret;
}

int32_t HksCheckKeyBlobParamSetEqualRuntimeParamSet(const struct HksParamSet *keyBlobParamSet,
    const struct HksParamSet *runtimeParamSet, uint32_t tag)
{
    if (keyBlobParamSet == NULL || runtimeParamSet == NULL) {
        HKS_LOG_E("invalid params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    bool isExistInParamsetOne = true;
    struct HksParam *paramInParamsetOne = NULL;
    int32_t ret = HksGetParam(keyBlobParamSet, tag, &paramInParamsetOne);
    if (ret != HKS_SUCCESS) {
        isExistInParamsetOne = false;
    }
    bool isExistInParamsetTwo = true;
    struct HksParam *paramInParamsetTwo = NULL;
    ret = HksGetParam(runtimeParamSet, tag, &paramInParamsetTwo);
    if (ret != HKS_SUCCESS) {
        isExistInParamsetTwo = false;
    }

    HKS_IF_TRUE_LOGE_RETURN(isExistInParamsetOne && (!isExistInParamsetTwo),
        HKS_ERROR_BAD_STATE, "please set param in paramsetTwo");
    HKS_IF_TRUE_LOGE_RETURN(isExistInParamsetOne && isExistInParamsetTwo &&
        (paramInParamsetOne->uint32Param != paramInParamsetTwo->uint32Param),
        HKS_ERROR_BAD_STATE, "values does not match");

    return HKS_SUCCESS;
}

void SetRsaPssSaltLenType(const struct HksParamSet *paramSet, struct HksUsageSpec *usageSpec)
{
    struct HksParam *saltLenTypeParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_RSA_PSS_SALT_LEN_TYPE, &saltLenTypeParam);
    if (ret == HKS_SUCCESS) {
        usageSpec->pssSaltLenType = saltLenTypeParam->uint32Param;
    } else {
        usageSpec->pssSaltLenType = HKS_RSA_PSS_SALTLEN_MAX;
    }
}