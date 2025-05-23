/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <iostream>

#include "file_ex.h"
#include "hks_ability.h"
#include "hks_config.h"
#include "hks_crypto_hal.h"
#include "hks_crypto_hal_common.h"
#include "hks_mem.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace Huks {
namespace UnitTest {
namespace {
struct TestCaseParams {
    HksKeySpec spec = {0};

    HksErrorCode generateKeyResult = HksErrorCode::HKS_SUCCESS;
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HKS_CRYPTO_HAL_RSA_KEY_001_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    },
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_GENERATE_KEY)
    .generateKeyResult = HKS_SUCCESS,
#else
    .generateKeyResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_KEY_002_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    },
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_GENERATE_KEY)
    .generateKeyResult = HKS_SUCCESS,
#else
    .generateKeyResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_KEY_003_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    },
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_GENERATE_KEY)
    .generateKeyResult = HKS_SUCCESS,
#else
    .generateKeyResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_RSA_KEY_004_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    },
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_GENERATE_KEY)
    .generateKeyResult = HKS_SUCCESS,
#else
    .generateKeyResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_KEY_005_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    },
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_GENERATE_KEY)
    .generateKeyResult = HKS_SUCCESS,
#else
    .generateKeyResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_KEY_006_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    },
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_GENERATE_KEY)
    .generateKeyResult = HKS_SUCCESS,
#else
    .generateKeyResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};
}  // namespace

class HksCryptoHalRsaKey : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
protected:
    void RunTestCase(const TestCaseParams &testCaseParams) const
    {
        HksBlob key = { .size = 0, .data = nullptr };
        ASSERT_EQ(HksCryptoHalGenerateKey(&testCaseParams.spec, &key), testCaseParams.generateKeyResult);
        if (testCaseParams.generateKeyResult == HKS_SUCCESS) {
            ASSERT_NE((uint32_t)0, key.size);
            ASSERT_NE(nullptr, key.data);
            HKS_FREE(key.data);
        }
    }
};

void HksCryptoHalRsaKey::SetUpTestCase(void)
{
}

void HksCryptoHalRsaKey::TearDownTestCase(void)
{
}

void HksCryptoHalRsaKey::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalRsaKey::TearDown()
{
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksCryptoHalRsaKey_001
 * @tc.name      : HksCryptoHalRsaKey_001
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate RSA-512bit key.
 */
HWTEST_F(HksCryptoHalRsaKey, HksCryptoHalRsaKey_001, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_KEY_001_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaKey_002
 * @tc.name      : HksCryptoHalRsaKey_002
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate RSA-768bit key.
 */
HWTEST_F(HksCryptoHalRsaKey, HksCryptoHalRsaKey_002, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_KEY_002_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaKey_003
 * @tc.name      : HksCryptoHalRsaKey_003
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate RSA-1024bit key.
 */
HWTEST_F(HksCryptoHalRsaKey, HksCryptoHalRsaKey_003, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_KEY_003_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaKey_004
 * @tc.name      : HksCryptoHalRsaKey_004
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate RSA-2048bit key.
 */
HWTEST_F(HksCryptoHalRsaKey, HksCryptoHalRsaKey_004, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_KEY_004_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaKey_005
 * @tc.name      : HksCryptoHalRsaKey_005
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate RSA-3072bit key.
 */
HWTEST_F(HksCryptoHalRsaKey, HksCryptoHalRsaKey_005, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_KEY_005_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaKey_006
 * @tc.name      : HksCryptoHalRsaKey_006
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate RSA-4096bit key.
 */
HWTEST_F(HksCryptoHalRsaKey, HksCryptoHalRsaKey_006, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_KEY_006_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaKey_007
 * @tc.name      : HksCryptoHalRsaKey_007
 * @tc.desc      : Generate key and export public key with RSA.
 */
HWTEST_F(HksCryptoHalRsaKey, HksCryptoHalRsaKey_007, Function | SmallTest | Level1)
{
    int32_t ret;

    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
    };

    HksBlob key = { .size = 0, .data = NULL };

    ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(ret, HKS_SUCCESS);

    KeyMaterialRsa *keyMaterial = (KeyMaterialRsa *)key.data;
    ASSERT_NE(keyMaterial, nullptr);

    uint32_t keyOutLen = sizeof(KeyMaterialRsa) + keyMaterial->nSize + keyMaterial->eSize;
    HksBlob keyOut = { .size = keyOutLen, .data = (uint8_t *)HksMalloc(keyOutLen) };
    ASSERT_NE(keyOut.data, nullptr);

    ret = HksCryptoHalGetPubKey(&key, &keyOut);
    ASSERT_EQ(ret, HKS_SUCCESS);
    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(keyOut);
}
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS