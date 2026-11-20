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

#include "hks_keynode_test.h"

#include <gtest/gtest.h>
#include <string>

#include "base/security/huks/services/huks_standard/huks_engine/main/core/src/hks_keynode.c"
#include "file_ex.h"
#include "hks_keynode.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type_inner.h"

using namespace testing::ext;
namespace Unittest::HksKeyNodeTest {
class HksKeyNodeTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksKeyNodeTest::SetUpTestCase(void)
{
}

void HksKeyNodeTest::TearDownTestCase(void)
{
}

void HksKeyNodeTest::SetUp()
{
}

void HksKeyNodeTest::TearDown()
{
}

static const struct HksParam g_params[] = {
    {
        .tag = HKS_TAG_CRYPTO_CTX,
        .uint64Param = 0
    },
};

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest001
 * @tc.desc: tdd HksCreateKeyNode, expect keyNode == NULL
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest001");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyNodeTest001 HksInitParamSet failed";
    ret = HksAddParams(paramSet, g_params, sizeof(g_params) / sizeof(g_params[0]));
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyNodeTest001 HksAddParams failed";
    ret = HksBuildParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyNodeTest001 HksBuildParamSet failed";
    struct HuksKeyNode *keyNode = HksCreateKeyNode(nullptr, paramSet);
    EXPECT_EQ(keyNode == nullptr, true) << "HksKeyNodeTest001 HksCreateKeyNode not failed";
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest002
 * @tc.desc: tdd HksKeyNodeTest002, function is FreeKeyBlobParamSet
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest002");
    struct HksParamSet **param = nullptr;
    FreeKeyBlobParamSet(param);
    EXPECT_EQ(param == nullptr, true);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest003
 * @tc.desc: tdd HksKeyNodeTest003, function is FreeParamsForBuildKeyNode
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest003");
    struct HksBlob blob = {
        .size = sizeof(HksBlob),
        .data = reinterpret_cast<uint8_t *>(HksMalloc(sizeof(HksBlob))),
    };

    FreeParamsForBuildKeyNode(&blob, nullptr, nullptr, nullptr);

    struct HksParamSet *runtimeParamSet = reinterpret_cast<HksParamSet *>(HksMalloc(sizeof(HksParamSet)));
    ASSERT_EQ(runtimeParamSet == nullptr, false) << "runtimeParamSet malloc failed.";
    FreeParamsForBuildKeyNode(&blob, &runtimeParamSet, nullptr, nullptr);

    struct HksParamSet *keyBlobParamSet = reinterpret_cast<HksParamSet *>(HksMalloc(sizeof(HksParamSet)));
    ASSERT_EQ(keyBlobParamSet == nullptr, false) << "keyBlobParamSet malloc failed.";
    FreeParamsForBuildKeyNode(&blob, &runtimeParamSet, &keyBlobParamSet, nullptr);

    struct HuksKeyNode *keyNode = reinterpret_cast<HuksKeyNode *>(HksMalloc(sizeof(HuksKeyNode)));
    ASSERT_EQ(keyNode == nullptr, false) << "keyNode malloc failed.";
    FreeParamsForBuildKeyNode(&blob, &runtimeParamSet, &keyBlobParamSet, keyNode);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest004
 * @tc.desc: tdd HksKeyNodeTest004, function is FreeCachedData
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest004");
    void *ctx = nullptr;
    FreeCachedData(&ctx);

    struct HksBlob *blob = reinterpret_cast<HksBlob *>(HksMalloc(sizeof(HksBlob)));
    ASSERT_EQ(blob == nullptr, false) << "blob malloc failed.";
    blob->size = sizeof(HksBlob);
    blob->data = reinterpret_cast<uint8_t *>(HksMalloc(sizeof(HksBlob)));
    FreeCachedData(reinterpret_cast<void **>(&blob));
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest005
 * @tc.desc: tdd HksKeyNodeTest005, function is KeyNodeFreeCtx
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest005");
    void *ctx = nullptr;
    KeyNodeFreeCtx(HKS_KEY_PURPOSE_AGREE, HKS_ALG_RSA, false, &ctx);

    KeyNodeFreeCtx(HKS_KEY_PURPOSE_DERIVE, HKS_ALG_RSA, false, &ctx);

    KeyNodeFreeCtx(HKS_KEY_PURPOSE_ENCRYPT, HKS_ALG_ECC, false, &ctx);

    KeyNodeFreeCtx(HKS_KEY_PURPOSE_DECRYPT, HKS_ALG_ECC, false, &ctx);

    KeyNodeFreeCtx(HKS_KEY_PURPOSE_MAC, HKS_ALG_ECC, false, &ctx);
    EXPECT_EQ(ctx == nullptr, true);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest006
 * @tc.desc: tdd HksKeyNodeTest006, function is FreeRuntimeParamSet
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest006");
    struct HksParamSet **paramSet = nullptr;
    FreeRuntimeParamSet(paramSet);
    struct HksParamSet *paramSetTwo = reinterpret_cast<HksParamSet *>(HksMalloc(sizeof(HksParamSet)));
    ASSERT_EQ(paramSetTwo == nullptr, false) << "paramSetTwo malloc failed.";
    FreeRuntimeParamSet(&paramSetTwo);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest007
 * @tc.desc: tdd HksKeyNodeTest007, function is FreeKeyBlobParamSet, expect *paramSet == NULL
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest007");
    struct HksParamSet *paramSet = nullptr;
    FreeKeyBlobParamSet(&paramSet);
    EXPECT_EQ(paramSet == nullptr, true);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest008
 * @tc.desc: tdd HksKeyNodeTest008, function is SetAesCcmModeTag, expect HKS_SUCCESS with invalid purpose
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest008");
    bool tag = true;
    int32_t ret = SetAesCcmModeTag(nullptr, HKS_ALG_AES, HKS_KEY_PURPOSE_SIGN, &tag);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(tag, false);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest009
 * @tc.desc: tdd HksKeyNodeTest009, function is SetAesCcmModeTag, expect HKS_ERROR_UNKNOWN_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest009");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyNodeTest009 HksInitParamSet failed";
    ret = HksBuildParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyNodeTest009 HksBuildParamSet failed";
    bool tag = false;
    ret = SetAesCcmModeTag(paramSet, HKS_ALG_AES, HKS_KEY_PURPOSE_ENCRYPT, &tag);
    EXPECT_EQ(ret, HKS_ERROR_UNKNOWN_ERROR);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest010
 * @tc.desc: tdd HksKeyNodeTest010, function is KeyNodeFreeCtx, expect not crash
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest010");
    void *ctx = nullptr;
    KeyNodeFreeCtx(HKS_KEY_PURPOSE_WRAP, HKS_ALG_ECC, false, &ctx);
    KeyNodeFreeCtx(HKS_KEY_PURPOSE_SIGN, HKS_ALG_ECC, false, &ctx);
    KeyNodeFreeCtx(HKS_KEY_PURPOSE_VERIFY, HKS_ALG_ECC, false, &ctx);
    KeyNodeFreeCtx(HKS_KEY_PURPOSE_ENCRYPT, HKS_ALG_RSA, false, &ctx);
    KeyNodeFreeCtx(HKS_KEY_PURPOSE_DECRYPT, HKS_ALG_RSA, false, &ctx);
    EXPECT_EQ(ctx == nullptr, true);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest011
 * @tc.desc: tdd HksKeyNodeTest011, function is FreeRuntimeParamSet, expect missing purpose/algorithm
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest011");
    struct HksParam cryptoCtxParam = { .tag = HKS_TAG_CRYPTO_CTX, .uint64Param = 1 };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyNodeTest011 HksInitParamSet failed";
    ret = HksAddParams(paramSet, &cryptoCtxParam, 1);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyNodeTest011 HksAddParams failed";
    ret = HksBuildParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyNodeTest011 HksBuildParamSet failed";
    FreeRuntimeParamSet(&paramSet);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest012
 * @tc.desc: tdd HksKeyNodeTest012, function is FreeRuntimeParamSet, expect SetAesCcmModeTag failed
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest012");
    struct HksParam params[] = {
        { .tag = HKS_TAG_CRYPTO_CTX, .uint64Param = 1 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyNodeTest012 HksInitParamSet failed";
    ret = HksAddParams(paramSet, params, sizeof(params) / sizeof(params[0]));
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyNodeTest012 HksAddParams failed";
    ret = HksBuildParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyNodeTest012 HksBuildParamSet failed";
    FreeRuntimeParamSet(&paramSet);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest013
 * @tc.desc: tdd HksKeyNodeTest013, function is DeleteKeyNodeFree, expect in-use key node not deleted
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest013");
    struct HuksKeyNode *keyNode = reinterpret_cast<HuksKeyNode *>(HksMalloc(sizeof(HuksKeyNode)));
    ASSERT_EQ(keyNode == nullptr, false) << "HksKeyNodeTest013 keyNode malloc failed.";
    keyNode->isInUse = true;
    keyNode->handle = 0;
    DeleteKeyNodeFree(keyNode);
    HKS_FREE(keyNode);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest014
 * @tc.desc: tdd HksKeyNodeTest014, function is DeleteFirstTimeOutBatchKeyNode and GetTokenIdFromParamSet
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest014");
    DeleteFirstTimeOutBatchKeyNode();
    uint32_t tokenId = GetTokenIdFromParamSet(nullptr);
    EXPECT_EQ(tokenId, INVALID_TOKEN_ID);
}

}