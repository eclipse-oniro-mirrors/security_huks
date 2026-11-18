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

#include "hks_common_check_test.h"

#include <gtest/gtest.h>

#include "hks_common_check.h"

#include "file_ex.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

#include <cstring>

using namespace testing::ext;
namespace Unittest::HksFrameworkCommonCheckTest {
class HksCommonCheckTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksCommonCheckTest::SetUpTestCase(void)
{
}

void HksCommonCheckTest::TearDownTestCase(void)
{
}

void HksCommonCheckTest::SetUp()
{
}

void HksCommonCheckTest::TearDown()
{
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest001
 * @tc.desc: tdd HksGetBlobFromWrappedData, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest001");
    int32_t ret = HksGetBlobFromWrappedData(nullptr, 0, 0, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest002
 * @tc.desc: tdd HksCheckWrappedDataFormatValidity, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest002");
    int32_t ret = HksCheckWrappedDataFormatValidity(nullptr, 0, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest003
 * @tc.desc: tdd HksCheckAesAeMode, expecting HKS_ERROR_CHECK_GET_ALG_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest003");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCheckAesAeMode(paramSet, nullptr, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_CHECK_GET_ALG_FAIL);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest004
 * @tc.desc: tdd HksCheckAesAeMode, expecting HKS_ERROR_CHECK_GET_MODE_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest004");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    struct HksParam param = { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES};
    ret = HksAddParams(paramSet, &param, 1);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    bool isAes = true;
    ret = HksCheckAesAeMode(paramSet, &isAes, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_CHECK_GET_MODE_FAIL);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest005
 * @tc.desc: tdd HksCheckParamSetValidity, expecting HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest005");
    int32_t ret = HksCheckParamSetValidity(nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest006
 * @tc.desc: tdd HksCheckParamSetValidity, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest006");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    paramSet->paramSetSize = 0;
    ret = HksCheckParamSetValidity(paramSet);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest007
 * @tc.desc: tdd HksCheckBlob2, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest007");
    int32_t ret = HksCheckBlob2(nullptr, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest008
 * @tc.desc: tdd HksCheckBlob2, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest008");
    const char *blobData = "test";
    struct HksBlob blob1 = { .size = strlen(blobData), .data = (uint8_t *)blobData };
    int32_t ret = HksCheckBlob2(&blob1, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest009
 * @tc.desc: tdd HksCheckBlob3, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest009");
    int32_t ret = HksCheckBlob3(nullptr, nullptr, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest010
 * @tc.desc: tdd HksCheckBlob3, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest010");
    const char *blobData = "test";
    struct HksBlob blob1 = { .size = strlen(blobData), .data = (uint8_t *)blobData };
    struct HksBlob blob2 = { .size = strlen(blobData), .data = (uint8_t *)blobData };
    int32_t ret = HksCheckBlob3(&blob1, &blob2, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest011
 * @tc.desc: tdd HksCheckBlob4, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest011");
    int32_t ret = HksCheckBlob4(nullptr, nullptr, nullptr, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest012
 * @tc.desc: tdd HksCheckBlob4, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest012");
    const char *blobData = "test";
    struct HksBlob blob1 = { .size = strlen(blobData), .data = (uint8_t *)blobData };
    int32_t ret = HksCheckBlob4(&blob1, nullptr, nullptr, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest013
 * @tc.desc: tdd HksCheckBlob4, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest013");
    const char *blobData = "test";
    struct HksBlob blob1 = { .size = strlen(blobData), .data = (uint8_t *)blobData };
    struct HksBlob blob2 = { .size = strlen(blobData), .data = (uint8_t *)blobData };
    struct HksBlob blob3 = { .size = strlen(blobData), .data = (uint8_t *)blobData };
    int32_t ret = HksCheckBlob4(&blob1, &blob2, &blob3, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest014
 * @tc.desc: tdd HksGetDigestLen, expecting HKS_ERROR_INVALID_DIGEST
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest014");
    uint32_t digestLen = 0;
    int32_t ret = HksGetDigestLen(0xFFFFFFFF, &digestLen);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_DIGEST);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest015
 * @tc.desc: tdd HksCheckWrappedDataFormatValidity, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest015");
    const char *wrappedData = "test";
    struct HksBlob wrappedBlob = { .size = strlen(wrappedData), .data = (uint8_t *)wrappedData };
    int32_t ret = HksCheckWrappedDataFormatValidity(&wrappedBlob, 0, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest016
 * @tc.desc: tdd HksCheckWrappedDataFormatValidity, expecting HKS_ERROR_INVALID_WRAPPED_FORMAT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest016, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest016");
    uint8_t data[2] = { 0x01, 0x02 };
    struct HksBlob wrappedBlob = { .size = sizeof(data), .data = data };
    int32_t ret = HksCheckWrappedDataFormatValidity(&wrappedBlob, 1, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_WRAPPED_FORMAT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest017
 * @tc.desc: tdd HksCheckWrappedDataFormatValidity, expecting HKS_ERROR_INVALID_WRAPPED_FORMAT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest017, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest017");
    uint8_t data[4] = { 0x00, 0x00, 0x00, 0x00 };
    struct HksBlob wrappedBlob = { .size = sizeof(data), .data = data };
    int32_t ret = HksCheckWrappedDataFormatValidity(&wrappedBlob, 1, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_WRAPPED_FORMAT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest018
 * @tc.desc: tdd HksCheckWrappedDataFormatValidity, expecting HKS_ERROR_INVALID_WRAPPED_FORMAT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest018, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest018");
    uint8_t data[6] = { 0x01, 0x00, 0x00, 0x00, 0xAA, 0xBB };
    struct HksBlob wrappedBlob = { .size = sizeof(data), .data = data };
    uint32_t validLen = 1;
    int32_t ret = HksCheckWrappedDataFormatValidity(&wrappedBlob, 1, &validLen);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_WRAPPED_FORMAT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest019
 * @tc.desc: tdd HksGetBlobFromWrappedData, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest019, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest019");
    const char *wrappedData = "test";
    struct HksBlob wrappedBlob = { .size = strlen(wrappedData), .data = (uint8_t *)wrappedData };
    int32_t ret = HksGetBlobFromWrappedData(&wrappedBlob, 0, 1, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest020
 * @tc.desc: tdd HksGetBlobFromWrappedData, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest020, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest020");
    const char *wrappedData = "test";
    struct HksBlob wrappedBlob = { .size = strlen(wrappedData), .data = (uint8_t *)wrappedData };
    struct HksBlob outBlob = { 0 };
    int32_t ret = HksGetBlobFromWrappedData(&wrappedBlob, 1, 1, &outBlob);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest021
 * @tc.desc: tdd HksGetBlobFromWrappedData, expecting HKS_ERROR_INVALID_WRAPPED_FORMAT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest021, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest021");
    uint8_t data[5] = { 0x00, 0x00, 0x00, 0x00, 0xAA };
    struct HksBlob wrappedBlob = { .size = sizeof(data), .data = data };
    struct HksBlob outBlob = { 0 };
    int32_t ret = HksGetBlobFromWrappedData(&wrappedBlob, 0, 1, &outBlob);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_WRAPPED_FORMAT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest022
 * @tc.desc: tdd HksCheckKeyBlobParamSetEqualRuntimeParamSet, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest022, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest022");
    int32_t ret = HksCheckKeyBlobParamSetEqualRuntimeParamSet(nullptr, nullptr, 0);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCommonCheckTest.HksCommonCheckTest023
 * @tc.desc: tdd HksCheckKeyBlobParamSetEqualRuntimeParamSet, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCommonCheckTest, HksCommonCheckTest023, TestSize.Level0)
{
    HKS_LOG_I("enter HksCommonCheckTest023");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCheckKeyBlobParamSetEqualRuntimeParamSet(paramSet, nullptr, HKS_TAG_ALGORITHM);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
}
}
