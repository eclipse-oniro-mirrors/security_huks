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

#include <gtest/gtest.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <securec.h>

#include "file_ex.h"
#include "hks_ability.h"
#include "hks_common_check.h"
#include "hks_config.h"
#include "hks_crypto_hal.h"
#include "hks_crypto_hal_common.h"
#include "hks_mem.h"
#include "hks_ml_dsa_kat.h"
#include "hks_template.h"
#include "securec.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace Huks {
namespace UnitTest {
class HksCryptoHalMlDsa : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksCryptoHalMlDsa::SetUpTestCase(void)
{
}

void HksCryptoHalMlDsa::TearDownTestCase(void)
{
}

void HksCryptoHalMlDsa::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalMlDsa::TearDown()
{
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_001, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_44,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_NE((uint32_t)0, key.size);
    ASSERT_NE(nullptr, key.data);

    HksKeyMaterialMlDsa *keyMaterial = (HksKeyMaterialMlDsa *)key.data;
    ASSERT_EQ(keyMaterial->keyAlg, (uint32_t)HKS_ALG_ML_DSA);
    ASSERT_EQ(keyMaterial->keyParamSet, (uint32_t)HKS_ML_DSA_KEY_PARAM_SET_44);
    ASSERT_EQ(keyMaterial->pubKeySize, (uint32_t)HKS_ML_DSA_PUB_KEY_SIZE_1312);
    ASSERT_EQ(keyMaterial->priKeySize, (uint32_t)HKS_ML_DSA_PRI_KEY_SIZE_2560);
    ASSERT_EQ(key.size, sizeof(HksKeyMaterialMlDsa) + HKS_ML_DSA_PUB_KEY_SIZE_1312 + HKS_ML_DSA_PRI_KEY_SIZE_2560);

    HKS_FREE(key.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_002, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_65,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_NE((uint32_t)0, key.size);
    ASSERT_NE(nullptr, key.data);

    HksKeyMaterialMlDsa *keyMaterial = (HksKeyMaterialMlDsa *)key.data;
    ASSERT_EQ(keyMaterial->keyAlg, (uint32_t)HKS_ALG_ML_DSA);
    ASSERT_EQ(keyMaterial->keyParamSet, (uint32_t)HKS_ML_DSA_KEY_PARAM_SET_65);
    ASSERT_EQ(keyMaterial->pubKeySize, (uint32_t)HKS_ML_DSA_PUB_KEY_SIZE_1952);
    ASSERT_EQ(keyMaterial->priKeySize, (uint32_t)HKS_ML_DSA_PRI_KEY_SIZE_4032);

    HKS_FREE(key.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_003, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_87,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_NE((uint32_t)0, key.size);
    ASSERT_NE(nullptr, key.data);

    HksKeyMaterialMlDsa *keyMaterial = (HksKeyMaterialMlDsa *)key.data;
    ASSERT_EQ(keyMaterial->keyAlg, (uint32_t)HKS_ALG_ML_DSA);
    ASSERT_EQ(keyMaterial->keyParamSet, (uint32_t)HKS_ML_DSA_KEY_PARAM_SET_87);
    ASSERT_EQ(keyMaterial->pubKeySize, (uint32_t)HKS_ML_DSA_PUB_KEY_SIZE_2592);
    ASSERT_EQ(keyMaterial->priKeySize, (uint32_t)HKS_ML_DSA_PRI_KEY_SIZE_4896);

    HKS_FREE(key.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_004, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = 999,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_SIZE);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_005, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_44,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    uint32_t keyOutLen = key.size;
    HksBlob keyOut = { .size = keyOutLen, .data = (uint8_t *)HksMalloc(keyOutLen) };
    ASSERT_NE(keyOut.data, nullptr);

    ret = HksCryptoHalGetPubKey(&key, &keyOut);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksKeyMaterialMlDsa *pubKeyMaterial = (HksKeyMaterialMlDsa *)keyOut.data;
    ASSERT_EQ(pubKeyMaterial->keyAlg, (uint32_t)HKS_ALG_ML_DSA);
    ASSERT_EQ(pubKeyMaterial->keyParamSet, (uint32_t)HKS_ML_DSA_KEY_PARAM_SET_44);
    ASSERT_NE(pubKeyMaterial->pubKeySize, (uint32_t)0);
    ASSERT_EQ(pubKeyMaterial->priKeySize, (uint32_t)0);
    ASSERT_EQ(pubKeyMaterial->reserved, (uint32_t)0);
    ASSERT_EQ(keyOut.size, sizeof(HksKeyMaterialMlDsa) + HKS_ML_DSA_PUB_KEY_SIZE_1312);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(keyOut);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_006, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_65,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    uint32_t keyOutLen = key.size;
    HksBlob keyOut = { .size = keyOutLen, .data = (uint8_t *)HksMalloc(keyOutLen) };
    ASSERT_NE(keyOut.data, nullptr);

    ret = HksCryptoHalGetPubKey(&key, &keyOut);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksKeyMaterialMlDsa *pubKeyMaterial = (HksKeyMaterialMlDsa *)keyOut.data;
    ASSERT_EQ(pubKeyMaterial->keyAlg, (uint32_t)HKS_ALG_ML_DSA);
    ASSERT_EQ(pubKeyMaterial->keyParamSet, (uint32_t)HKS_ML_DSA_KEY_PARAM_SET_65);
    ASSERT_NE(pubKeyMaterial->pubKeySize, (uint32_t)0);
    ASSERT_EQ(pubKeyMaterial->priKeySize, (uint32_t)0);
    ASSERT_EQ(pubKeyMaterial->reserved, (uint32_t)0);
    ASSERT_EQ(keyOut.size, sizeof(HksKeyMaterialMlDsa) + HKS_ML_DSA_PUB_KEY_SIZE_1952);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(keyOut);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_007, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(_USE_OPENSSL_)
    uint8_t smallBuf[1] = {0};
    HksBlob smallKeyIn = { .size = 1, .data = smallBuf };
    HksBlob keyOut = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGetPubKey(&smallKeyIn, &keyOut);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_008, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(_USE_OPENSSL_)
    uint8_t fakeData[sizeof(HksKeyMaterialMlDsa)] = {0};
    HksKeyMaterialMlDsa *fakeMaterial = (HksKeyMaterialMlDsa *)fakeData;
    fakeMaterial->keyAlg = HKS_ALG_ML_DSA;
    fakeMaterial->keyParamSet = HKS_ML_DSA_KEY_PARAM_SET_44;
    fakeMaterial->pubKeySize = 0;
    fakeMaterial->priKeySize = 0;
    fakeMaterial->reserved = 0;
    HksBlob fakeKeyIn = { .size = sizeof(HksKeyMaterialMlDsa), .data = fakeData };
    uint8_t outBuf[4096] = {0};
    HksBlob keyOut = { .size = 4096, .data = outBuf };
    int32_t ret = HksCryptoHalGetPubKey(&fakeKeyIn, &keyOut);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_009, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(_USE_OPENSSL_)
    uint8_t fakeData[sizeof(HksKeyMaterialMlDsa)] = {0};
    HksKeyMaterialMlDsa *fakeMaterial = (HksKeyMaterialMlDsa *)fakeData;
    fakeMaterial->keyAlg = HKS_ALG_ML_DSA;
    fakeMaterial->keyParamSet = HKS_ML_DSA_KEY_PARAM_SET_44;
    fakeMaterial->pubKeySize = HKS_ML_DSA_PUB_KEY_SIZE_1312;
    fakeMaterial->priKeySize = 0;
    fakeMaterial->reserved = 0;
    HksBlob fakeKeyIn = { .size = sizeof(HksKeyMaterialMlDsa), .data = fakeData };
    uint8_t outBuf[sizeof(HksKeyMaterialMlDsa)] = {0};
    HksBlob keyOut = { .size = sizeof(HksKeyMaterialMlDsa), .data = outBuf };
    int32_t ret = HksCryptoHalGetPubKey(&fakeKeyIn, &keyOut);
    /* keyIn material does not contain the declared pubKeySize, input check fails first */
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_010, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_44,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    uint32_t smallOutLen = sizeof(HksKeyMaterialMlDsa) + 10;
    uint8_t *smallOutBuf = (uint8_t *)HksMalloc(smallOutLen);
    ASSERT_NE(smallOutBuf, nullptr);
    HksBlob keyOut = { .size = smallOutLen, .data = smallOutBuf };

    ret = HksCryptoHalGetPubKey(&key, &keyOut);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE(smallOutBuf);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_011, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_44,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr);

    ret = HksCryptoHalSign(&key, &usageSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(signature.size, (uint32_t)0);

    HKS_FREE(key.data);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_012, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && \
    defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_44,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    HksBlob pubKey = { .size = 0, .data = nullptr };
    uint32_t pubKeyOutLen = key.size;
    pubKey.data = (uint8_t *)HksMalloc(pubKeyOutLen);
    pubKey.size = pubKeyOutLen;
    ASSERT_NE(pubKey.data, nullptr);
    ret = HksCryptoHalGetPubKey(&key, &pubKey);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };

    HksUsageSpec signSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr);

    ret = HksCryptoHalSign(&key, &signSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(signature.size, (uint32_t)0);

    HksUsageSpec verifySpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_VERIFY,
        .algParam = &contextBlob,
    };

    ret = HksCryptoHalVerify(&pubKey, &verifySpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(pubKey);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_013, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_65,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr);

    ret = HksCryptoHalSign(&key, &usageSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HKS_FREE(key.data);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_014, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_87,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr);

    ret = HksCryptoHalSign(&key, &usageSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HKS_FREE(key.data);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_015, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && \
    defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_44,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    HksBlob pubKey = { .size = 0, .data = nullptr };
    uint32_t pubKeyOutLen = key.size;
    pubKey.data = (uint8_t *)HksMalloc(pubKeyOutLen);
    pubKey.size = pubKeyOutLen;
    ASSERT_NE(pubKey.data, nullptr);
    ret = HksCryptoHalGetPubKey(&key, &pubKey);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };

    HksUsageSpec signSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr);

    ret = HksCryptoHalSign(&key, &signSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t tamperedMsgData[dataLen];
    (void)memcpy_s(tamperedMsgData, dataLen, message.data, dataLen);
    tamperedMsgData[0] ^= 0xFF;
    HksBlob tamperedMessage = { .size = dataLen, .data = tamperedMsgData };

    HksUsageSpec verifySpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_VERIFY,
        .algParam = &contextBlob,
    };

    ret = HksCryptoHalVerify(&pubKey, &verifySpec, &tamperedMessage, &signature);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(pubKey);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_016, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    uint8_t smallData[1] = {0};
    HksBlob smallKey = { .size = 1, .data = smallData };
    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };
    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }
    struct HksBlob signature = { .size = ML_DSA_MAX_KEY_SIZE, .data = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(signature.data, nullptr);

    int32_t ret = HksCryptoHalSign(&smallKey, &usageSpec, &message, &signature);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_017, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    uint32_t fakeTotalLen = sizeof(HksKeyMaterialMlDsa) + HKS_ML_DSA_PUB_KEY_SIZE_1312 + HKS_ML_DSA_PRI_KEY_SIZE_2560;
    uint8_t *fakeBuf = (uint8_t *)HksMalloc(fakeTotalLen);
    ASSERT_NE(fakeBuf, nullptr);
    (void)memset_s(fakeBuf, fakeTotalLen, 0xAA, fakeTotalLen);
    HksKeyMaterialMlDsa *fakeMaterial = (HksKeyMaterialMlDsa *)fakeBuf;
    fakeMaterial->keyAlg = HKS_ALG_ML_DSA;
    fakeMaterial->keyParamSet = 999;
    fakeMaterial->pubKeySize = HKS_ML_DSA_PUB_KEY_SIZE_1312;
    fakeMaterial->priKeySize = HKS_ML_DSA_PRI_KEY_SIZE_2560;
    fakeMaterial->reserved = 0;
    HksBlob fakeKey = { .size = fakeTotalLen, .data = fakeBuf };

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }
    struct HksBlob signature = { .size = ML_DSA_MAX_KEY_SIZE, .data = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(signature.data, nullptr);

    int32_t ret = HksCryptoHalSign(&fakeKey, &usageSpec, &message, &signature);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE(fakeBuf);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_018, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    uint8_t smallData[1] = {0};
    HksBlob smallKey = { .size = 1, .data = smallData };
    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_VERIFY,
        .algParam = &contextBlob,
    };

    uint8_t sigData[64] = {0};
    struct HksBlob signature = { .size = 64, .data = sigData };
    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    int32_t ret = HksCryptoHalVerify(&smallKey, &usageSpec, &message, &signature);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE(message.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_019, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && \
    defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_65,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    HksBlob pubKey = { .size = 0, .data = nullptr };
    uint32_t pubKeyOutLen = key.size;
    pubKey.data = (uint8_t *)HksMalloc(pubKeyOutLen);
    pubKey.size = pubKeyOutLen;
    ASSERT_NE(pubKey.data, nullptr);
    ret = HksCryptoHalGetPubKey(&key, &pubKey);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };

    HksUsageSpec signSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr);

    ret = HksCryptoHalSign(&key, &signSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksUsageSpec verifySpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_VERIFY,
        .algParam = &contextBlob,
    };

    ret = HksCryptoHalVerify(&pubKey, &verifySpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(pubKey);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_020, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && \
    defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_87,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    HksBlob pubKey = { .size = 0, .data = nullptr };
    uint32_t pubKeyOutLen = key.size;
    pubKey.data = (uint8_t *)HksMalloc(pubKeyOutLen);
    pubKey.size = pubKeyOutLen;
    ASSERT_NE(pubKey.data, nullptr);
    ret = HksCryptoHalGetPubKey(&key, &pubKey);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };

    HksUsageSpec signSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr);

    ret = HksCryptoHalSign(&key, &signSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksUsageSpec verifySpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_VERIFY,
        .algParam = &contextBlob,
    };

    ret = HksCryptoHalVerify(&pubKey, &verifySpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(pubKey);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_021, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    uint32_t fakeTotalLen = sizeof(HksKeyMaterialMlDsa) + HKS_ML_DSA_PUB_KEY_SIZE_1312;
    uint8_t *fakeBuf = (uint8_t *)HksMalloc(fakeTotalLen);
    ASSERT_NE(fakeBuf, nullptr);
    (void)memset_s(fakeBuf, fakeTotalLen, 0xBB, fakeTotalLen);
    HksKeyMaterialMlDsa *fakeMaterial = (HksKeyMaterialMlDsa *)fakeBuf;
    fakeMaterial->keyAlg = HKS_ALG_ML_DSA;
    fakeMaterial->keyParamSet = HKS_ML_DSA_KEY_PARAM_SET_44;
    fakeMaterial->pubKeySize = HKS_ML_DSA_PUB_KEY_SIZE_1312;
    fakeMaterial->priKeySize = 0;
    fakeMaterial->reserved = 0;
    HksBlob fakeKey = { .size = fakeTotalLen, .data = fakeBuf };

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_VERIFY,
        .algParam = &contextBlob,
    };

    uint8_t sigData[64] = {0};
    struct HksBlob signature = { .size = 64, .data = sigData };
    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    int32_t ret = HksCryptoHalVerify(&fakeKey, &usageSpec, &message, &signature);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE(fakeBuf);
    HKS_FREE(message.data);
#endif
}
HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_022, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_44,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    HksBlob pubKey = { .size = 0, .data = nullptr };
    uint32_t pubKeyOutLen = key.size;
    pubKey.data = (uint8_t *)HksMalloc(pubKeyOutLen);
    pubKey.size = pubKeyOutLen;
    ASSERT_NE(pubKey.data, nullptr) << "hks malloc fail";
    ret = HksCryptoHalGetPubKey(&key, &pubKey);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t contextData[] = "ml-dsa-context-tdd";
    HksBlob contextBlob = { .size = strlen((const char *)contextData), .data = contextData };

    HksUsageSpec signSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr) << "hks malloc fail";
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr) << "hks malloc fail";

    ret = HksCryptoHalSign(&key, &signSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(signature.size, (uint32_t)0);

    HksUsageSpec verifySpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_VERIFY,
        .algParam = &contextBlob,
    };

    ret = HksCryptoHalVerify(&pubKey, &verifySpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS)<< "HksCryptoHalMlDsa_022 HksCryptoHalVerify fail" << ret;

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(pubKey);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_023, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && \
    defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_44,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    HksBlob pubKey = { .size = 0, .data = nullptr };
    uint32_t pubKeyOutLen = key.size;
    pubKey.data = (uint8_t *)HksMalloc(pubKeyOutLen);
    pubKey.size = pubKeyOutLen;
    ASSERT_NE(pubKey.data, nullptr);
    ret = HksCryptoHalGetPubKey(&key, &pubKey);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t contextA[] = "context-a";
    HksBlob contextBlobA = { .size = strlen((const char *)contextA), .data = contextA };
    uint8_t contextB[] = "context-b";
    HksBlob contextBlobB = { .size = strlen((const char *)contextB), .data = contextB };

    HksUsageSpec signSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlobA,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr);

    ret = HksCryptoHalSign(&key, &signSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksUsageSpec verifySpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_VERIFY,
        .algParam = &contextBlobB,
    };

    ret = HksCryptoHalVerify(&pubKey, &verifySpec, &message, &signature);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(pubKey);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

namespace {
const uint32_t HKS_COUNT_OF_HALF_LOCAL = 2;

int32_t HexToBlob(const char *hex, HksBlob *blob)
{
    size_t len = strlen(hex);
    if ((len == 0) || ((len % HKS_COUNT_OF_HALF_LOCAL) != 0)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    blob->size = (uint32_t)(len / HKS_COUNT_OF_HALF_LOCAL);
    blob->data = (uint8_t *)HksMalloc(blob->size);
    if (blob->data == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    for (uint32_t i = 0; i < blob->size; i++) {
        unsigned int value = 0;
        if (sscanf(hex + HKS_COUNT_OF_HALF_LOCAL * i, "%2x", &value) != 1) {
            HKS_FREE_BLOB(*blob);
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        blob->data[i] = (uint8_t)value;
    }
    return HKS_SUCCESS;
}

HksUsageSpec BuildMlDsaSpec(uint32_t purpose, uint32_t pqcSigMode, uint32_t digest, HksBlob *context)
{
    HksUsageSpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .mgfDigest = 0,
        .digest = digest,
        .purpose = purpose,
        .pssSaltLenType = 0,
        .pqcSigMode = pqcSigMode,
        .algParam = context,
    };
    return spec;
}

int32_t DigestMessage(uint32_t digestAlg, const char *messageData, HksBlob *digest)
{
    HksBlob message = { .size = (uint32_t)strlen(messageData), .data = (uint8_t *)messageData };
    digest->data = (uint8_t *)HksMalloc(HKS_DIGEST_SHA512_LEN);
    if (digest->data == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    digest->size = HKS_DIGEST_SHA512_LEN;
    int32_t ret = HksCryptoHalHash(digestAlg, &message, digest);
    if (ret != HKS_SUCCESS) {
        HKS_FREE_BLOB(*digest);
    }
    return ret;
}

int32_t BuildPublicKeyBlob(const char *pubKeyHex, uint32_t paramSetId, HksBlob *key)
{
    HksBlob pubKey = { 0, nullptr };
    int32_t ret = HexToBlob(pubKeyHex, &pubKey);
    HKS_IF_NOT_SUCC_RETURN(ret, ret);

    uint32_t totalLen = sizeof(HksKeyMaterialMlDsa) + pubKey.size;
    key->data = (uint8_t *)HksMalloc(totalLen);
    if (key->data == nullptr) {
        HKS_FREE_BLOB(pubKey);
        return HKS_ERROR_MALLOC_FAIL;
    }
    key->size = totalLen;
    HksKeyMaterialMlDsa *material = (HksKeyMaterialMlDsa *)key->data;
    material->keyAlg = HKS_ALG_ML_DSA;
    material->keyParamSet = paramSetId;
    material->pubKeySize = pubKey.size;
    material->priKeySize = 0;
    material->reserved = 0;
    if (memcpy_s(key->data + sizeof(HksKeyMaterialMlDsa), totalLen - sizeof(HksKeyMaterialMlDsa),
        pubKey.data, pubKey.size) != EOK) {
        HKS_FREE_BLOB(pubKey);
        HKS_FREE_BLOB(*key);
        return HKS_ERROR_INVALID_OPERATION;
    }
    HKS_FREE_BLOB(pubKey);
    return HKS_SUCCESS;
}

int32_t GenerateMlDsaKey(uint32_t paramSetId, HksBlob *key)
{
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = paramSetId,
        .algParam = nullptr,
    };
    return HksCryptoHalGenerateKey(&spec, key);
}

int32_t SignPreHash(const HksBlob *key, uint32_t digestAlg, const HksBlob *digest, HksBlob *context,
    HksBlob *signature)
{
    HksUsageSpec spec = BuildMlDsaSpec(HKS_KEY_PURPOSE_SIGN, HKS_PQC_SIG_MODE_PREHASH, digestAlg, context);
    return HksCryptoHalSign(key, &spec, digest, signature);
}

int32_t VerifyPreHash(const HksBlob *key, uint32_t digestAlg, const HksBlob *digest, HksBlob *context,
    const HksBlob *signature)
{
    HksUsageSpec spec = BuildMlDsaSpec(HKS_KEY_PURPOSE_VERIFY, HKS_PQC_SIG_MODE_PREHASH, digestAlg, context);
    return HksCryptoHalVerify(key, &spec, digest, signature);
}
} // namespace

/*
 * HashML-DSA (pre-hash) mode: the caller supplies the digest PH(M) and the pre-hash function,
 * HUKS applies the FIPS 204 formatted message 0x01 || len(ctx) || ctx || OID(PH) || PH(M).
 */
HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_024, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksBlob key = { .size = 0, .data = nullptr };
    ASSERT_EQ(GenerateMlDsaKey(HKS_ML_DSA_KEY_PARAM_SET_44, &key), HKS_SUCCESS);

    uint8_t contextData[] = "ml-dsa-prehash";
    HksBlob context = { .size = sizeof(contextData) - 1, .data = contextData };
    HksBlob digest = { 0, nullptr };
    ASSERT_EQ(DigestMessage(HKS_DIGEST_SHA256, "HUKS ML-DSA prehash sign verify message", &digest), HKS_SUCCESS);
    ASSERT_EQ(digest.size, (uint32_t)HKS_DIGEST_SHA256_LEN);

    HksBlob signature = { .size = ML_DSA_MAX_KEY_SIZE, .data = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(signature.data, nullptr);
    ASSERT_EQ(SignPreHash(&key, HKS_DIGEST_SHA256, &digest, &context, &signature), HKS_SUCCESS);
    ASSERT_NE(signature.size, (uint32_t)0);
    ASSERT_EQ(VerifyPreHash(&key, HKS_DIGEST_SHA256, &digest, &context, &signature), HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(digest);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_025, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksBlob key = { .size = 0, .data = nullptr };
    ASSERT_EQ(GenerateMlDsaKey(HKS_ML_DSA_KEY_PARAM_SET_65, &key), HKS_SUCCESS);

    uint8_t contextData[] = "ml-dsa-prehash";
    HksBlob context = { .size = sizeof(contextData) - 1, .data = contextData };
    HksBlob digest = { 0, nullptr };
    ASSERT_EQ(DigestMessage(HKS_DIGEST_SHA384, "HUKS ML-DSA prehash sign verify message", &digest), HKS_SUCCESS);
    ASSERT_EQ(digest.size, (uint32_t)HKS_DIGEST_SHA384_LEN);

    HksBlob signature = { .size = ML_DSA_MAX_KEY_SIZE, .data = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(signature.data, nullptr);
    ASSERT_EQ(SignPreHash(&key, HKS_DIGEST_SHA384, &digest, &context, &signature), HKS_SUCCESS);
    ASSERT_EQ(VerifyPreHash(&key, HKS_DIGEST_SHA384, &digest, &context, &signature), HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(digest);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_026, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksBlob key = { .size = 0, .data = nullptr };
    ASSERT_EQ(GenerateMlDsaKey(HKS_ML_DSA_KEY_PARAM_SET_87, &key), HKS_SUCCESS);

    HksBlob digest = { 0, nullptr };
    ASSERT_EQ(DigestMessage(HKS_DIGEST_SHA512, "HUKS ML-DSA prehash message without context", &digest), HKS_SUCCESS);
    ASSERT_EQ(digest.size, (uint32_t)HKS_DIGEST_SHA512_LEN);

    HksBlob signature = { .size = ML_DSA_MAX_KEY_SIZE, .data = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(signature.data, nullptr);
    ASSERT_EQ(SignPreHash(&key, HKS_DIGEST_SHA512, &digest, nullptr, &signature), HKS_SUCCESS);
    ASSERT_EQ(VerifyPreHash(&key, HKS_DIGEST_SHA512, &digest, nullptr, &signature), HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(digest);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_027, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksBlob key = { .size = 0, .data = nullptr };
    ASSERT_EQ(GenerateMlDsaKey(HKS_ML_DSA_KEY_PARAM_SET_44, &key), HKS_SUCCESS);

    uint8_t digestData[HKS_DIGEST_SHA256_LEN] = { 0 };
    HksBlob digest = { .size = sizeof(digestData), .data = digestData };
    HksBlob signature = { .size = ML_DSA_MAX_KEY_SIZE, .data = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(signature.data, nullptr);

    /* SM3 is not an approved HashML-DSA pre-hash function */
    ASSERT_EQ(SignPreHash(&key, HKS_DIGEST_SM3, &digest, nullptr, &signature), HKS_ERROR_INVALID_DIGEST);

    HKS_FREE_BLOB(key);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_028, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksBlob key = { .size = 0, .data = nullptr };
    ASSERT_EQ(GenerateMlDsaKey(HKS_ML_DSA_KEY_PARAM_SET_44, &key), HKS_SUCCESS);

    uint8_t digestData[HKS_DIGEST_SHA256_LEN + 1] = { 0 };
    HksBlob signature = { .size = ML_DSA_MAX_KEY_SIZE, .data = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(signature.data, nullptr);

    /* the digest length must match the selected pre-hash function */
    const uint32_t invalidLens[] = { HKS_DIGEST_SHA256_LEN - 1, HKS_DIGEST_SHA256_LEN + 1 };
    for (uint32_t len : invalidLens) {
        HksBlob digest = { .size = len, .data = digestData };
        ASSERT_EQ(SignPreHash(&key, HKS_DIGEST_SHA256, &digest, nullptr, &signature), HKS_ERROR_INVALID_ARGUMENT);
        ASSERT_EQ(VerifyPreHash(&key, HKS_DIGEST_SHA256, &digest, nullptr, &signature), HKS_ERROR_INVALID_ARGUMENT);
    }

    HKS_FREE_BLOB(key);
    HKS_FREE(signature.data);
#endif
}

/*
 * External mu mode: the input is the 64-byte message representative mu. The context string is
 * already part of mu and must be ignored by the engine.
 */
HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_029, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    const uint32_t paramSetIds[] = { HKS_ML_DSA_KEY_PARAM_SET_44, HKS_ML_DSA_KEY_PARAM_SET_65,
        HKS_ML_DSA_KEY_PARAM_SET_87 };
    for (uint32_t paramSetId : paramSetIds) {
        HksBlob key = { .size = 0, .data = nullptr };
        ASSERT_EQ(GenerateMlDsaKey(paramSetId, &key), HKS_SUCCESS);

        uint8_t mu[ML_DSA_MU_SIZE] = { 0 };
        for (uint32_t i = 0; i < ML_DSA_MU_SIZE; i++) {
            mu[i] = (uint8_t)(i + paramSetId);
        }
        HksBlob message = { .size = ML_DSA_MU_SIZE, .data = mu };
        HksUsageSpec signSpec = BuildMlDsaSpec(HKS_KEY_PURPOSE_SIGN, HKS_PQC_SIG_MODE_EXTERNAL_MU,
            HKS_DIGEST_NONE, nullptr);
        HksUsageSpec verifySpec = BuildMlDsaSpec(HKS_KEY_PURPOSE_VERIFY, HKS_PQC_SIG_MODE_EXTERNAL_MU,
            HKS_DIGEST_NONE, nullptr);
        HksBlob signature = { .size = ML_DSA_MAX_KEY_SIZE, .data = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
        ASSERT_NE(signature.data, nullptr);

        ASSERT_EQ(HksCryptoHalSign(&key, &signSpec, &message, &signature), HKS_SUCCESS);
        ASSERT_EQ(HksCryptoHalVerify(&key, &verifySpec, &message, &signature), HKS_SUCCESS);

        /* mu is context independent */
        uint8_t otherContextData[] = "another-context";
        HksBlob otherContext = { .size = sizeof(otherContextData) - 1, .data = otherContextData };
        HksUsageSpec verifyOtherCtx = BuildMlDsaSpec(HKS_KEY_PURPOSE_VERIFY, HKS_PQC_SIG_MODE_EXTERNAL_MU,
            HKS_DIGEST_NONE, &otherContext);
        ASSERT_EQ(HksCryptoHalVerify(&key, &verifyOtherCtx, &message, &signature), HKS_SUCCESS);

        HKS_FREE_BLOB(key);
        HKS_FREE(signature.data);
    }
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_030, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksBlob key = { .size = 0, .data = nullptr };
    ASSERT_EQ(GenerateMlDsaKey(HKS_ML_DSA_KEY_PARAM_SET_44, &key), HKS_SUCCESS);

    uint8_t mu[ML_DSA_MU_SIZE + 1] = { 0 };
    HksUsageSpec signSpec = BuildMlDsaSpec(HKS_KEY_PURPOSE_SIGN, HKS_PQC_SIG_MODE_EXTERNAL_MU,
        HKS_DIGEST_NONE, nullptr);
    HksUsageSpec verifySpec = BuildMlDsaSpec(HKS_KEY_PURPOSE_VERIFY, HKS_PQC_SIG_MODE_EXTERNAL_MU,
        HKS_DIGEST_NONE, nullptr);
    HksBlob signature = { .size = ML_DSA_MAX_KEY_SIZE, .data = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(signature.data, nullptr);

    const uint32_t invalidSizes[] = { ML_DSA_MU_SIZE - 1, ML_DSA_MU_SIZE + 1 };
    for (uint32_t size : invalidSizes) {
        HksBlob message = { .size = size, .data = mu };
        ASSERT_EQ(HksCryptoHalSign(&key, &signSpec, &message, &signature), HKS_ERROR_INVALID_ARGUMENT);
        ASSERT_EQ(HksCryptoHalVerify(&key, &verifySpec, &message, &signature), HKS_ERROR_INVALID_ARGUMENT);
    }

    HKS_FREE_BLOB(key);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_031, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksBlob key = { .size = 0, .data = nullptr };
    ASSERT_EQ(GenerateMlDsaKey(HKS_ML_DSA_KEY_PARAM_SET_44, &key), HKS_SUCCESS);

    uint8_t contextData[] = "ml-dsa-mode-mismatch";
    HksBlob context = { .size = sizeof(contextData) - 1, .data = contextData };
    HksBlob digest = { 0, nullptr };
    ASSERT_EQ(DigestMessage(HKS_DIGEST_SHA256, "HUKS ML-DSA mode mismatch message", &digest), HKS_SUCCESS);

    HksBlob signature = { .size = ML_DSA_MAX_KEY_SIZE, .data = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(signature.data, nullptr);
    ASSERT_EQ(SignPreHash(&key, HKS_DIGEST_SHA256, &digest, &context, &signature), HKS_SUCCESS);

    /* the same signature must not verify as pure ML-DSA or as external mu */
    HksUsageSpec pureVerify = BuildMlDsaSpec(HKS_KEY_PURPOSE_VERIFY, HKS_PQC_SIG_MODE_PURE, HKS_DIGEST_NONE, &context);
    ASSERT_NE(HksCryptoHalVerify(&key, &pureVerify, &digest, &signature), HKS_SUCCESS);

    HksUsageSpec muVerify = BuildMlDsaSpec(HKS_KEY_PURPOSE_VERIFY, HKS_PQC_SIG_MODE_EXTERNAL_MU,
        HKS_DIGEST_NONE, nullptr);
    ASSERT_NE(HksCryptoHalVerify(&key, &muVerify, &digest, &signature), HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(digest);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_032, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksBlob key = { .size = 0, .data = nullptr };
    ASSERT_EQ(GenerateMlDsaKey(HKS_ML_DSA_KEY_PARAM_SET_44, &key), HKS_SUCCESS);

    uint8_t contextData[] = "ml-dsa-tamper";
    HksBlob context = { .size = sizeof(contextData) - 1, .data = contextData };
    HksBlob digest = { 0, nullptr };
    ASSERT_EQ(DigestMessage(HKS_DIGEST_SHA256, "HUKS ML-DSA prehash tampered message", &digest), HKS_SUCCESS);

    HksBlob signature = { .size = ML_DSA_MAX_KEY_SIZE, .data = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(signature.data, nullptr);
    ASSERT_EQ(SignPreHash(&key, HKS_DIGEST_SHA256, &digest, &context, &signature), HKS_SUCCESS);

    /* tamper the digest */
    digest.data[0] ^= 0xFF;
    ASSERT_NE(VerifyPreHash(&key, HKS_DIGEST_SHA256, &digest, &context, &signature), HKS_SUCCESS);

    /* restore the digest and tamper the signature */
    digest.data[0] ^= 0xFF;
    signature.data[10] ^= 0xFF;
    ASSERT_NE(VerifyPreHash(&key, HKS_DIGEST_SHA256, &digest, &context, &signature), HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(digest);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_033, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksBlob key = { .size = 0, .data = nullptr };
    ASSERT_EQ(GenerateMlDsaKey(HKS_ML_DSA_KEY_PARAM_SET_44, &key), HKS_SUCCESS);

    HksUsageSpec signSpec = BuildMlDsaSpec(HKS_KEY_PURPOSE_SIGN, 99, HKS_DIGEST_SHA256, nullptr);
    uint8_t digestData[HKS_DIGEST_SHA256_LEN] = { 0 };
    HksBlob digest = { .size = sizeof(digestData), .data = digestData };
    HksBlob signature = { .size = ML_DSA_MAX_KEY_SIZE, .data = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(signature.data, nullptr);

    ASSERT_EQ(HksCryptoHalSign(&key, &signSpec, &digest, &signature), HKS_ERROR_INVALID_MODE);

    HKS_FREE_BLOB(key);
    HKS_FREE(signature.data);
#endif
}

/*
 * Known-answer tests from an independent FIPS 204 implementation. Verify only: HUKS signatures
 * are randomized and therefore cannot be compared byte by byte. The input data of the pre-hash
 * mode is the digest PH(M).
 */
HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_034, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksBlob key = { .size = 0, .data = nullptr };
    HksBlob context = { .size = 0, .data = nullptr };
    HksBlob digest = { .size = 0, .data = nullptr };
    HksBlob signature = { .size = 0, .data = nullptr };
    ASSERT_EQ(BuildPublicKeyBlob(g_mlDsaKatPubKeyHex, HKS_ML_DSA_KEY_PARAM_SET_44, &key), HKS_SUCCESS);
    ASSERT_EQ(HexToBlob(g_mlDsaKatCtxHex, &context), HKS_SUCCESS);
    ASSERT_EQ(HexToBlob(g_mlDsaKatPhSha256Hex, &digest), HKS_SUCCESS);
    ASSERT_EQ(HexToBlob(g_mlDsaKatPreHashSha256SigHex, &signature), HKS_SUCCESS);
    ASSERT_EQ(digest.size, (uint32_t)HKS_DIGEST_SHA256_LEN);

    ASSERT_EQ(VerifyPreHash(&key, HKS_DIGEST_SHA256, &digest, &context, &signature), HKS_SUCCESS);

    /* the vector must not verify with a different pre-hash function or context */
    ASSERT_NE(VerifyPreHash(&key, HKS_DIGEST_SHA384, &digest, &context, &signature), HKS_SUCCESS);

    uint8_t otherContextData[] = "other-kat-context";
    HksBlob otherContext = { .size = sizeof(otherContextData) - 1, .data = otherContextData };
    ASSERT_NE(VerifyPreHash(&key, HKS_DIGEST_SHA256, &digest, &otherContext, &signature), HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(context);
    HKS_FREE_BLOB(digest);
    HKS_FREE_BLOB(signature);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_035, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksBlob key = { .size = 0, .data = nullptr };
    HksBlob mu = { .size = 0, .data = nullptr };
    HksBlob signature = { .size = 0, .data = nullptr };
    ASSERT_EQ(BuildPublicKeyBlob(g_mlDsaKatPubKeyHex, HKS_ML_DSA_KEY_PARAM_SET_44, &key), HKS_SUCCESS);
    ASSERT_EQ(HexToBlob(g_mlDsaKatMuHex, &mu), HKS_SUCCESS);
    ASSERT_EQ(HexToBlob(g_mlDsaKatMuSigHex, &signature), HKS_SUCCESS);
    ASSERT_EQ(mu.size, (uint32_t)ML_DSA_MU_SIZE);

    HksUsageSpec verifySpec = BuildMlDsaSpec(HKS_KEY_PURPOSE_VERIFY, HKS_PQC_SIG_MODE_EXTERNAL_MU,
        HKS_DIGEST_NONE, nullptr);
    ASSERT_EQ(HksCryptoHalVerify(&key, &verifySpec, &mu, &signature), HKS_SUCCESS);

    /* a single flipped bit of mu must be rejected */
    mu.data[0] ^= 0x01;
    ASSERT_NE(HksCryptoHalVerify(&key, &verifySpec, &mu, &signature), HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(mu);
    HKS_FREE_BLOB(signature);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_036, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksBlob key = { .size = 0, .data = nullptr };
    HksBlob context = { .size = 0, .data = nullptr };
    ASSERT_EQ(BuildPublicKeyBlob(g_mlDsaKatPubKeyHex, HKS_ML_DSA_KEY_PARAM_SET_44, &key), HKS_SUCCESS);
    ASSERT_EQ(HexToBlob(g_mlDsaKatCtxHex, &context), HKS_SUCCESS);

    /* SHAKE128 pre-hash vector, 32-byte digest */
    HksBlob shake128Digest = { .size = 0, .data = nullptr };
    HksBlob shake128Sig = { .size = 0, .data = nullptr };
    ASSERT_EQ(HexToBlob(g_mlDsaKatPhShake128Hex, &shake128Digest), HKS_SUCCESS);
    ASSERT_EQ(HexToBlob(g_mlDsaKatPreHashShake128SigHex, &shake128Sig), HKS_SUCCESS);
    ASSERT_EQ(shake128Digest.size, (uint32_t)HKS_DIGEST_SHAKE128_LEN);
    ASSERT_EQ(VerifyPreHash(&key, HKS_DIGEST_SHAKE128, &shake128Digest, &context, &shake128Sig), HKS_SUCCESS);

    /* SHAKE256 pre-hash vector, 64-byte digest */
    HksBlob shake256Digest = { .size = 0, .data = nullptr };
    HksBlob shake256Sig = { .size = 0, .data = nullptr };
    ASSERT_EQ(HexToBlob(g_mlDsaKatPhShake256Hex, &shake256Digest), HKS_SUCCESS);
    ASSERT_EQ(HexToBlob(g_mlDsaKatPreHashShake256SigHex, &shake256Sig), HKS_SUCCESS);
    ASSERT_EQ(shake256Digest.size, (uint32_t)HKS_DIGEST_SHAKE256_LEN);
    ASSERT_EQ(VerifyPreHash(&key, HKS_DIGEST_SHAKE256, &shake256Digest, &context, &shake256Sig), HKS_SUCCESS);

    /* SHAKE128 and SHAKE256 produce digests of different lengths, they must not be interchangeable */
    ASSERT_NE(VerifyPreHash(&key, HKS_DIGEST_SHAKE128, &shake256Digest, &context, &shake256Sig), HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(context);
    HKS_FREE_BLOB(shake128Digest);
    HKS_FREE_BLOB(shake128Sig);
    HKS_FREE_BLOB(shake256Digest);
    HKS_FREE_BLOB(shake256Sig);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_037, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksBlob key = { .size = 0, .data = nullptr };
    HksBlob context = { .size = 0, .data = nullptr };
    ASSERT_EQ(BuildPublicKeyBlob(g_mlDsaKatPubKeyHex, HKS_ML_DSA_KEY_PARAM_SET_44, &key), HKS_SUCCESS);
    ASSERT_EQ(HexToBlob(g_mlDsaKatCtxHex, &context), HKS_SUCCESS);

    HksBlob sha384Digest = { .size = 0, .data = nullptr };
    HksBlob sha384Sig = { .size = 0, .data = nullptr };
    ASSERT_EQ(HexToBlob(g_mlDsaKatPhSha384Hex, &sha384Digest), HKS_SUCCESS);
    ASSERT_EQ(HexToBlob(g_mlDsaKatPreHashSha384SigHex, &sha384Sig), HKS_SUCCESS);
    ASSERT_EQ(VerifyPreHash(&key, HKS_DIGEST_SHA384, &sha384Digest, &context, &sha384Sig), HKS_SUCCESS);

    HksBlob sha512Digest = { .size = 0, .data = nullptr };
    HksBlob sha512Sig = { .size = 0, .data = nullptr };
    ASSERT_EQ(HexToBlob(g_mlDsaKatPhSha512Hex, &sha512Digest), HKS_SUCCESS);
    ASSERT_EQ(HexToBlob(g_mlDsaKatPreHashSha512SigHex, &sha512Sig), HKS_SUCCESS);
    ASSERT_EQ(VerifyPreHash(&key, HKS_DIGEST_SHA512, &sha512Digest, &context, &sha512Sig), HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(context);
    HKS_FREE_BLOB(sha384Digest);
    HKS_FREE_BLOB(sha384Sig);
    HKS_FREE_BLOB(sha512Digest);
    HKS_FREE_BLOB(sha512Sig);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_038, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksBlob key = { .size = 0, .data = nullptr };
    ASSERT_EQ(GenerateMlDsaKey(HKS_ML_DSA_KEY_PARAM_SET_44, &key), HKS_SUCCESS);

    uint8_t contextData[] = "ml-dsa-shake";
    HksBlob context = { .size = sizeof(contextData) - 1, .data = contextData };
    uint8_t digestData[HKS_DIGEST_SHAKE256_LEN] = { 0 };
    for (uint32_t i = 0; i < sizeof(digestData); i++) {
        digestData[i] = (uint8_t)i;
    }
    HksBlob signature = { .size = ML_DSA_MAX_KEY_SIZE, .data = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(signature.data, nullptr);

    const uint32_t shakeDigests[] = { HKS_DIGEST_SHAKE128, HKS_DIGEST_SHAKE256 };
    const uint32_t shakeLens[] = { HKS_DIGEST_SHAKE128_LEN, HKS_DIGEST_SHAKE256_LEN };
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(shakeDigests); i++) {
        HksBlob digest = { .size = shakeLens[i], .data = digestData };
        ASSERT_EQ(SignPreHash(&key, shakeDigests[i], &digest, &context, &signature), HKS_SUCCESS);
        ASSERT_EQ(VerifyPreHash(&key, shakeDigests[i], &digest, &context, &signature), HKS_SUCCESS);
    }

    HKS_FREE_BLOB(key);
    HKS_FREE(signature.data);
#endif
}
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS
