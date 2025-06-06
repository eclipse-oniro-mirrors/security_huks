/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hks_test_adapt_for_de.h"
#include "hks_three_stage_test_common.h"

int32_t InitParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramcount)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksInitParamSet failed");
        return ret;
    }

    ret = HksAddParams(*paramSet, params, paramcount);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(paramSet);
        return ret;
    }

    ret = HksBuildParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(paramSet);
        return ret;
    }

    return ret;
}

static int32_t TestLessThanMaxSeg(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    uint32_t purpose, const struct HksBlob *inData, struct HksBlob *outData)
{
    struct HksBlob tmpOutData = {
        .size = MAX_OUTDATA_SIZE,
        .data = NULL
    };
    if (MallocAndCheckBlobData(&tmpOutData, tmpOutData.size) != HKS_SUCCESS) {
        return HKS_FAILURE;
    }
    int32_t ret = HksUpdateForDe(handle, paramSet, inData, &tmpOutData);
    HKS_FREE(tmpOutData.data);
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }
    struct HksBlob tmpInData = {
        .size = 0,
        .data = NULL
    };
    if (MallocAndCheckBlobData(&tmpInData, MAX_UPDATE_SIZE) != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    if (purpose == HKS_KEY_PURPOSE_VERIFY) {
        ret = HksFinishForDe(handle, paramSet, outData, &tmpInData);
    } else {
        ret = HksFinishForDe(handle, paramSet, &tmpInData, outData);
    }
    HKS_FREE(tmpInData.data);
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

int32_t HksTestUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData)
{
    struct HksBlob inDataSeg = *inData;
    inDataSeg.size = MAX_UPDATE_SIZE;

    uint8_t *lastPtr = inData->data + inData->size - 1;
    struct HksBlob outDataSeg = {
        .size = MAX_OUTDATA_SIZE,
        .data = NULL
    };

    bool isFinished = false;

    while (inDataSeg.data <= lastPtr) {
        if (inDataSeg.data + MAX_UPDATE_SIZE <= lastPtr) {
            outDataSeg.size = MAX_OUTDATA_SIZE;
        } else {
            isFinished = true;
            inDataSeg.size = lastPtr - inDataSeg.data + 1;
            outDataSeg.size = inDataSeg.size + MAX_UPDATE_SIZE;
        }
        if (MallocAndCheckBlobData(&outDataSeg, outDataSeg.size) != HKS_SUCCESS) {
            return HKS_FAILURE;
        }
        if (HksUpdateForDe(handle, paramSet, &inDataSeg, &outDataSeg) != HKS_SUCCESS) {
            HKS_LOG_E("HksUpdate Failed.");
            HKS_FREE(outDataSeg.data);
            return HKS_FAILURE;
        }
        HKS_FREE(outDataSeg.data);
        if ((isFinished == false) && (inDataSeg.data + MAX_UPDATE_SIZE > lastPtr)) {
            return HKS_SUCCESS;
        }
        inDataSeg.data += MAX_UPDATE_SIZE;
    }
    return HKS_SUCCESS;
}

int32_t TestBatchUpdateLoopFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    struct HksBlob inDataSeg = *inData;
    uint8_t *lastPtr = inData->data + inData->size - 1;
    struct HksBlob outDataSeg = { MAX_OUTDATA_SIZE, NULL };
    uint8_t *cur = outData->data;
    uint32_t curSize = outData->size;
    outData->size = 0;

    inDataSeg.size = MAX_UPDATE_SIZE;

    bool isFinished = false;

    isFinished = true;
    inDataSeg.size = lastPtr - inDataSeg.data + 1;

    if (MallocAndCheckBlobData(&outDataSeg, outDataSeg.size) != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    int32_t ret = HksUpdateForDe(handle, paramSet, &inDataSeg, &outDataSeg);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksUpdate Failed.");
        HKS_FREE(outDataSeg.data);
        return ret;
    }
    (void)memcpy_s(cur, outDataSeg.size, outDataSeg.data, outDataSeg.size);
    cur += outDataSeg.size;
    outData->size += outDataSeg.size;
    HKS_FREE(outDataSeg.data);
    if ((isFinished == false) && (inDataSeg.data + MAX_UPDATE_SIZE > lastPtr)) {
        return HKS_FAILURE;
    }
    inDataSeg.data += MAX_UPDATE_SIZE;

    struct HksBlob outDataFinish = { inDataSeg.size * TIMES, NULL };
    if (MallocAndCheckBlobData(&outDataFinish, outDataFinish.size) != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    if (HksFinishForDe(handle, paramSet, &inDataSeg, &outDataFinish) != HKS_SUCCESS) {
        HKS_FREE(outDataFinish.data);
        return HKS_FAILURE;
    }

    if (memcpy_s(cur, curSize, outDataFinish.data, outDataFinish.size) != EOK) {
        HKS_FREE(outDataFinish.data);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    outData->size += outDataFinish.size;
    HKS_FREE(outDataFinish.data);

    return HKS_SUCCESS;
}

int32_t TestUpdateLoopFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    struct HksBlob inDataSeg = *inData;
    uint8_t *lastPtr = inData->data + inData->size - 1;
    struct HksBlob outDataSeg = { MAX_OUTDATA_SIZE, NULL };
    uint8_t *cur = outData->data;
    uint32_t curSize = outData->size;
    outData->size = 0;

    inDataSeg.size = MAX_UPDATE_SIZE;

    bool isFinished = false;

    while (inDataSeg.data <= lastPtr) {
        if (inDataSeg.data + MAX_UPDATE_SIZE <= lastPtr) {
            outDataSeg.size = MAX_OUTDATA_SIZE;
        } else {
            isFinished = true;
            inDataSeg.size = lastPtr - inDataSeg.data + 1;
            break;
        }
        if (MallocAndCheckBlobData(&outDataSeg, outDataSeg.size) != HKS_SUCCESS) {
            return HKS_FAILURE;
        }
        if (HksUpdateForDe(handle, paramSet, &inDataSeg, &outDataSeg) != HKS_SUCCESS) {
            HKS_LOG_E("HksUpdate Failed.");
            HKS_FREE(outDataSeg.data);
            return HKS_FAILURE;
        }
        (void)memcpy_s(cur, outDataSeg.size, outDataSeg.data, outDataSeg.size);
        cur += outDataSeg.size;
        outData->size += outDataSeg.size;
        HKS_FREE(outDataSeg.data);
        if ((isFinished == false) && (inDataSeg.data + MAX_UPDATE_SIZE > lastPtr)) {
            return HKS_FAILURE;
        }
        inDataSeg.data += MAX_UPDATE_SIZE;
    }

    struct HksBlob outDataFinish = { inDataSeg.size * TIMES, NULL };
    if (MallocAndCheckBlobData(&outDataFinish, outDataFinish.size) != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    if (HksFinishForDe(handle, paramSet, &inDataSeg, &outDataFinish) != HKS_SUCCESS) {
        HKS_FREE(outDataFinish.data);
        return HKS_FAILURE;
    }

    if (memcpy_s(cur, curSize, outDataFinish.data, outDataFinish.size) != EOK) {
        HKS_FREE(outDataFinish.data);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    outData->size += outDataFinish.size;
    HKS_FREE(outDataFinish.data);

    return HKS_SUCCESS;
}

int32_t TestUpdateFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    uint32_t purpose, const struct HksBlob *inData, struct HksBlob *outData)
{
    struct HksBlob inDataSeg = *inData;
    inDataSeg.size = MAX_UPDATE_SIZE;

    uint8_t *lastPtr = inData->data + inData->size - 1;
    struct HksBlob outDataSeg = { MAX_OUTDATA_SIZE, NULL };

    bool isFinished = false;

    if (inData->size <= MAX_UPDATE_SIZE) {
        return TestLessThanMaxSeg(handle, paramSet, purpose, inData, outData);
    }

    while (inDataSeg.data <= lastPtr) {
        if (inDataSeg.data + MAX_UPDATE_SIZE <= lastPtr) {
            outDataSeg.size = MAX_OUTDATA_SIZE;
            if (MallocAndCheckBlobData(&outDataSeg, outDataSeg.size) != HKS_SUCCESS) {
                return HKS_FAILURE;
            }
        } else {
            isFinished = true;
            inDataSeg.size = lastPtr - inDataSeg.data + 1;
            break;
        }
        if (HksUpdateForDe(handle, paramSet, &inDataSeg, &outDataSeg) != HKS_SUCCESS) {
            HKS_LOG_E("HksUpdate Failed.");
            HKS_FREE(outDataSeg.data);
            return HKS_FAILURE;
        }
        HKS_FREE(outDataSeg.data);
        if ((isFinished == false) && (inDataSeg.data + MAX_UPDATE_SIZE > lastPtr)) {
            return HKS_FAILURE;
        }
        inDataSeg.data += MAX_UPDATE_SIZE;
    }

    if (purpose != HKS_KEY_PURPOSE_VERIFY) {
        if (HksFinishForDe(handle, paramSet, &inDataSeg, outData) != HKS_SUCCESS) {
            HKS_LOG_E("HksFinish Failed.");
            return HKS_FAILURE;
        }
    } else {
        uint8_t tmp[] = "temp";
        struct HksBlob tempBlob = { sizeof(tmp), tmp };
        if (HksUpdateForDe(handle, paramSet, &inDataSeg, &tempBlob) != HKS_SUCCESS) {
            HKS_LOG_E("HksUpdate Failed.");
            return HKS_FAILURE;
        }
        if (HksFinishForDe(handle, paramSet, outData, &tempBlob) != HKS_SUCCESS) {
            HKS_LOG_E("HksFinish Failed.");
            return HKS_FAILURE;
        }
    }
    return HKS_SUCCESS;
}

int32_t MallocAndCheckBlobData(struct HksBlob *blob, const uint32_t blobSize)
{
    blob->data = (uint8_t *)HksMalloc(blobSize);
    if (blob->data == NULL) {
        HKS_LOG_E("could not alloc memory");
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

int32_t TestCmpKeyAliasHash(const struct HksBlob *srcData1, const struct HksBlob *srcData2)
{
    struct HksParam hashParam = {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    };
    struct HksParamSet *hashParamSet = NULL;
    int32_t ret = InitParamSet(&hashParamSet, &hashParam, sizeof(hashParam) / sizeof(struct HksParam));
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    struct HksBlob hash1 = { MAX_OUTDATA_SIZE, NULL };
    if (MallocAndCheckBlobData(&hash1, hash1.size) != HKS_SUCCESS) {
        HksFreeParamSet(&hashParamSet);
        return HKS_FAILURE;
    }
    ret = HksHash(hashParamSet, srcData1, &hash1);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&hashParamSet);
        HKS_FREE(hash1.data);
        return HKS_FAILURE;
    }

    struct HksBlob hash2 = { MAX_OUTDATA_SIZE, NULL };
    if (MallocAndCheckBlobData(&hash2, hash2.size) != HKS_SUCCESS) {
        HKS_FREE(hash1.data);
        HksFreeParamSet(&hashParamSet);
        return HKS_FAILURE;
    }
    ret = HksHash(hashParamSet, srcData2, &hash2);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&hashParamSet);
        HKS_FREE(hash1.data);
        HKS_FREE(hash2.data);
        return HKS_FAILURE;
    }

    ret = HksMemCmp(hash1.data, hash2.data, hash2.size);
    HksFreeParamSet(&hashParamSet);
    HKS_FREE(hash1.data);
    HKS_FREE(hash2.data);

    return ret;
}
