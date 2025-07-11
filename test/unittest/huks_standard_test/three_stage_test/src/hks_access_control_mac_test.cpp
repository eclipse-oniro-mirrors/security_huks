/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "hks_access_control_mac_test.h"
#include "hks_access_control_test_common.h"
#include "hks_api.h"
#include "hks_test_adapt_for_de.h"

#include <gtest/gtest.h>
#include <vector>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::HksAccessControlPartTest {
class HksAccessControlMacTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAccessControlMacTest::SetUpTestCase(void)
{
}

void HksAccessControlMacTest::TearDownTestCase(void)
{
}

void HksAccessControlMacTest::SetUp()
{
    ASSERT_EQ(HksInitialize(), 0);
}

void HksAccessControlMacTest::TearDown()
{
    std::system("find /data/service/el1/public/huks_service -user root -delete");
}

/* 001: gen hmac for mac; init for mac */
const TestAccessCaseParams HKS_ACCESS_TEST_001_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FACE },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256  },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FACE },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
        },
    .initResult = HKS_SUCCESS
};

#ifdef _USE_OPENSSL_
/* mbedtls engine don't support SM3 alg */
/* 002: gen sm3 for mac; init for mac */
const TestAccessCaseParams HKS_ACCESS_TEST_002_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM3 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_CUSTOM },
            { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = 0 },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM3 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3  },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_CUSTOM },
            { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = 0 },
        },
    .initResult = HKS_SUCCESS
};
#endif

/**
 * @tc.name: HksAccessControlMacTest.HksAccessMacPartTest001
 * @tc.desc: alg-HMAC gen-pur-HMC.
 * @tc.type: FUNC
 * @tc.auth_type: FACE
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlMacTest, HksAccessMacPartTest001, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessMacPartTest003");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 3,
        .time = 0,
        .authType = 2
    };
    ASSERT_EQ(CheckAccessHmacTest(HKS_ACCESS_TEST_001_PARAMS, testIDMParams), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlMacTest.HksAccessMacPartTest002
 * @tc.desc: alg-SM3 gen-pur-HMC.
 * @tc.type: FUNC
 * @tc.auth_type: PIN
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlMacTest, HksAccessMacPartTest002, TestSize.Level0)
{
#ifdef _USE_OPENSSL_
    /* mbedtls engine don't support SM3 alg */
    HKS_LOG_I("Enter HksAccessMacPartTest002");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    ASSERT_EQ(CheckAccessHmacTest(HKS_ACCESS_TEST_002_PARAMS, testIDMParams), HKS_SUCCESS);
#endif
}

/**
 * @tc.name: HksAccessControlMacTest.HksAccessMacPartTest003
 * @tc.desc: supports fine-grained access control, alg-HMAC gen-pur-HMC.
 * @tc.type: FUNC
 * @tc.auth_type: FACE
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlMacTest, HksAccessMacPartTest003, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessMacPartTest003");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 3,
        .time = 0,
        .authType = 2
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_001_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC }
    );
    ASSERT_EQ(CheckAccessHmacTest(testAccessCaseParams, testIDMParams), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlMacTest.HksAccessMacPartTest004
 * @tc.desc: supports fine-grained access control, alg-SM3 gen-pur-HMC.
 * @tc.type: FUNC
 * @tc.auth_type: PIN
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlMacTest, HksAccessMacPartTest004, TestSize.Level0)
{
#ifdef _USE_OPENSSL_
    /* mbedtls engine don't support SM3 alg */
    HKS_LOG_I("Enter HksAccessMacPartTest004");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_002_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC }
    );
    ASSERT_EQ(CheckAccessHmacTest(testAccessCaseParams, testIDMParams), HKS_SUCCESS);
#endif
}

/**
 * @tc.name: HksAccessControlMacTest.HksAccessMacPartTest005
 * @tc.desc: one stage api:HksMac do not support operate user-auth-key
 * @tc.type: FUNC
 * @tc.auth_type: PIN
 * @tc.result:HKS_ERROR_NOT_SUPPORTED
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlMacTest, HksAccessMacPartTest005, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessMacPartTest005");
    uint8_t alias[] = "testCheckAuthMac";
    struct HksBlob keyAlias = { sizeof(alias), alias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, HKS_ACCESS_TEST_001_PARAMS.genParams.data(),
        HKS_ACCESS_TEST_001_PARAMS.genParams.size());
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    (void)HksFreeParamSet(&genParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    // test mac
    struct HksParam macParams[] =
    {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256  },
    };
    struct HksParamSet *macParamSet = nullptr;
    ret = InitParamSet(&macParamSet, macParams, sizeof(macParams) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t out[256] = {0};
    struct HksBlob outBlob = { sizeof(out), out };
    ret = HksMacForDe(&keyAlias, macParamSet, &outBlob, &outBlob);
    (void)HksFreeParamSet(&macParamSet);
    (void)HksDeleteKeyForDe(&keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);
}
}