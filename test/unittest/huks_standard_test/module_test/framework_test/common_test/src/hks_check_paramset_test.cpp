/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hks_check_paramset_test.h"

#include <gtest/gtest.h>

#include "base/security/huks/frameworks/huks_standard/main/common/src/hks_check_paramset.c"

#include "file_ex.h"
#include "hks_log.h"
#include "hks_mem.h"

#include <cstring>

using namespace testing::ext;
namespace Unittest::HksCheckParamsetTest {
constexpr uint32_t DEFAULT_VALUE = 16;

class HksCheckParamsetTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksCheckParamsetTest::SetUpTestCase(void)
{
}

void HksCheckParamsetTest::TearDownTestCase(void)
{
}

void HksCheckParamsetTest::SetUp()
{
}

void HksCheckParamsetTest::TearDown()
{
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest001
 * @tc.desc: test CheckMutableParams with rsa
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest001");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_RSA, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest002
 * @tc.desc: test CheckMutableParams with ecc
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest002");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_ECC, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest003
 * @tc.desc: test CheckMutableParams with sm2
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest003");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_SM2, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest004
 * @tc.desc: test CheckMutableParams with dsa
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest004");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_DSA, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest005
 * @tc.desc: test CheckMutableParams with ed255129
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest005");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_ED25519, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest007
 * @tc.desc: test CheckMutableParams with x255129
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest007");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_X25519, keyType, &params);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest008
 * @tc.desc: test CheckMutableParams with dh
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest008");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_DH, keyType, &params);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest009
 * @tc.desc: test CheckMutableParams with dh
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest009");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_SM4, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest010
 * @tc.desc: tdd HksCheckParamsetTest010, function is CheckImportKeySize
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest010");
    HksBlob key = {
        .size = 0,
        .data = nullptr,
    };
    int32_t ret = CheckImportKeySize(HKS_ALG_ED25519, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest010 failed, ret = " << ret;

    ret = CheckImportKeySize(HKS_ALG_X25519, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest010 failed, ret = " << ret;

    ret = CheckImportKeySize(HKS_ALG_RSA, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest010 failed, ret = " << ret;

    ret = CheckImportKeySize(HKS_ALG_ECC, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest010 failed, ret = " << ret;

    ret = CheckImportKeySize(HKS_ALG_SM2, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest010 failed, ret = " << ret;

    ret = CheckImportKeySize(HKS_ALG_DH, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest010 failed, ret = " << ret;

    ret = CheckImportKeySize(HKS_ALG_DSA, nullptr, &key);
    ASSERT_EQ(ret, HKS_SUCCESS) << "HksCheckParamsetTest010 failed, ret = " << ret;

    ret = CheckImportKeySize(0, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM) << "HksCheckParamsetTest010 failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest011
 * @tc.desc: tdd HksCheckParamsetTest011, function is CheckRsaKeyLen
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest011");
    HksBlob key = {
        .size = 0, .data = nullptr,
    };
    int32_t ret = CheckRsaKeyLen(HKS_ALG_ED25519, 0, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest011 failed, ret = " << ret;

    struct HksKeyMaterialRsa materialRsa = {
        .keyAlg = HKS_ALG_RSA,
        .keySize = 0,
        .nSize = HKS_RSA_KEY_SIZE_4096,
        .eSize = HKS_RSA_KEY_SIZE_4096,
        .dSize = HKS_RSA_KEY_SIZE_4096,
    };
    key.size = sizeof(struct HksKeyMaterialRsa);
    key.data = reinterpret_cast<uint8_t *>(&materialRsa);
    ret = CheckRsaKeyLen(HKS_ALG_ED25519, 0, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest011 failed, ret = " << ret;

    ParamsValues values = {
        {.needCheck = true, .value = DEFAULT_VALUE, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest011 failed, ret = " << ret;

    materialRsa.keySize = DEFAULT_VALUE;
    materialRsa.nSize = HKS_RSA_KEY_SIZE_4096 + 1;
    ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest011 failed, ret = " << ret;

    materialRsa.nSize = HKS_RSA_KEY_SIZE_4096;
    materialRsa.dSize = HKS_RSA_KEY_SIZE_4096 + 1;
    ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest011 failed, ret = " << ret;

    materialRsa.dSize = HKS_RSA_KEY_SIZE_4096;
    materialRsa.eSize = HKS_RSA_KEY_SIZE_4096 + 1;
    ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest011 failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest012
 * @tc.desc: tdd HksCheckParamsetTest012, function is CheckRsaKeyLen
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest012");
    struct HksKeyMaterialRsa materialRsa = {
        .keyAlg = HKS_ALG_RSA,
        .keySize = DEFAULT_VALUE,
        .nSize = HKS_RSA_KEY_SIZE_4096,
        .eSize = HKS_RSA_KEY_SIZE_4096,
        .dSize = HKS_RSA_KEY_SIZE_4096,
    };

    HksBlob key = {
        .size = sizeof(struct HksKeyMaterialRsa),
        .data = reinterpret_cast<uint8_t *>(&materialRsa),
    };

    ParamsValues values = {
        {.needCheck = true, .value = DEFAULT_VALUE, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    materialRsa.nSize = 0;
    int32_t ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest012 failed, ret = " << ret;

    materialRsa.nSize = HKS_RSA_KEY_SIZE_4096;
    materialRsa.dSize = 0;
    ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest012 failed, ret = " << ret;

    materialRsa.dSize = HKS_RSA_KEY_SIZE_4096;
    materialRsa.eSize = 0;
    ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest012 failed, ret = " << ret;

    materialRsa.eSize = HKS_RSA_KEY_SIZE_4096;
    ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest012 failed, ret = " << ret;
}


/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest013
 * @tc.desc: tdd HksCheckParamsetTest013, function is CheckEccKeyLen
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest013");
    struct HksKeyMaterialEcc materialEcc = {
        .keyAlg = HKS_ALG_ECC,
        .keySize = 0,
        .xSize = HKS_ECC_KEY_SIZE_521,
        .ySize = HKS_ECC_KEY_SIZE_521,
        .zSize = HKS_ECC_KEY_SIZE_521,
    };
    HksBlob key = {
        .size = sizeof(struct HksKeyMaterialRsa),
        .data = reinterpret_cast<uint8_t *>(&materialEcc),
    };
    ParamsValues values = {
        {.needCheck = true, .value = DEFAULT_VALUE, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    int32_t ret = CheckEccKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;

    ret = CheckEccKeyLen(HKS_ALG_ECC, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;

    materialEcc.keySize = DEFAULT_VALUE;
    materialEcc.xSize = HKS_ECC_KEY_SIZE_521 + 1;
    ret = CheckEccKeyLen(HKS_ALG_ECC, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;

    materialEcc.xSize = HKS_ECC_KEY_SIZE_521;
    materialEcc.ySize = HKS_ECC_KEY_SIZE_521 + 1;
    ret = CheckEccKeyLen(HKS_ALG_ECC, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;

    materialEcc.ySize = HKS_ECC_KEY_SIZE_521;
    materialEcc.zSize = HKS_ECC_KEY_SIZE_521 + 1;
    ret = CheckEccKeyLen(HKS_ALG_ECC, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;

    materialEcc.zSize = HKS_ECC_KEY_SIZE_521;
    materialEcc.xSize = 0;
    ret = CheckEccKeyLen(HKS_ALG_ECC, HKS_KEY_TYPE_KEY_PAIR, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;

    materialEcc.xSize = HKS_ECC_KEY_SIZE_521;
    materialEcc.ySize = 0;
    ret = CheckEccKeyLen(HKS_ALG_ECC, HKS_KEY_TYPE_KEY_PAIR, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;

    materialEcc.ySize = HKS_ECC_KEY_SIZE_521;
    ret = CheckEccKeyLen(HKS_ALG_ECC, HKS_KEY_TYPE_KEY_PAIR, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest014
 * @tc.desc: tdd HksCheckParamsetTest014, function is CheckDsaKeyLen
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest014");
    struct HksKeyMaterialDsa materialDsa = {
        .keyAlg = HKS_ALG_DSA,
        .keySize = 0,
        .xSize = MAX_KEY_SIZE + 1,
        .ySize = MAX_KEY_SIZE + 1,
        .pSize = MAX_KEY_SIZE + 1,
        .qSize = MAX_KEY_SIZE + 1,
        .gSize = MAX_KEY_SIZE + 1,
    };
    HksBlob key = {
        .size = sizeof(struct HksKeyMaterialDsa),
        .data = reinterpret_cast<uint8_t *>(&materialDsa),
    };
    ParamsValues values = {
        {.needCheck = true, .value = DEFAULT_VALUE, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    int32_t ret = CheckDsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;

    materialDsa.keySize = DEFAULT_VALUE;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;

    materialDsa.xSize = MAX_KEY_SIZE;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;

    materialDsa.ySize = MAX_KEY_SIZE;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;

    materialDsa.pSize = MAX_KEY_SIZE;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;

    materialDsa.qSize = MAX_KEY_SIZE;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;

    materialDsa.gSize = MAX_KEY_SIZE;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest015
 * @tc.desc: tdd HksCheckParamsetTest015, function is CheckDsaKeyLen
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest015");
    struct HksKeyMaterialDsa materialDsa = {
        .keyAlg = HKS_ALG_DSA,
        .keySize = DEFAULT_VALUE,
        .xSize = MAX_KEY_SIZE,
        .ySize = MAX_KEY_SIZE,
        .pSize = MAX_KEY_SIZE,
        .qSize = MAX_KEY_SIZE,
        .gSize = MAX_KEY_SIZE,
    };
    HksBlob key = {
        .size = sizeof(struct HksKeyMaterialDsa),
        .data = reinterpret_cast<uint8_t *>(&materialDsa),
    };
    ParamsValues values = {
        {.needCheck = true, .value = DEFAULT_VALUE, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };

    materialDsa.xSize = 0;
    int32_t ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest015 failed, ret = " << ret;

    materialDsa.xSize = MAX_KEY_SIZE;
    materialDsa.pSize = 0;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest015 failed, ret = " << ret;

    materialDsa.pSize = MAX_KEY_SIZE;
    materialDsa.qSize = 0;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest015 failed, ret = " << ret;

    materialDsa.qSize = MAX_KEY_SIZE;
    materialDsa.gSize = 0;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest015 failed, ret = " << ret;

    materialDsa.gSize = MAX_KEY_SIZE;
    materialDsa.ySize = 0;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, HKS_KEY_TYPE_KEY_PAIR, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest015 failed, ret = " << ret;

    materialDsa.ySize = MAX_KEY_SIZE;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest015 failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest016
 * @tc.desc: tdd CheckMlDsaKeyLen and CheckMlKemKeyLen
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest016, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest016");

    /* --- CheckMlDsaKeyLen --- */
    /* key too small */
    uint8_t smallBuf[4] = {0};
    HksBlob smallKey = { .size = sizeof(smallBuf), .data = smallBuf };
    ParamsValues mldsaValues = {
        {.needCheck = true, .value = HKS_ML_DSA_KEY_PARAM_SET_44, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    int32_t ret = CheckMlDsaKeyLen(HKS_ALG_ML_DSA, 0, &mldsaValues, &smallKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO);

    /* invalid keyAlg */
    struct HksKeyMaterialMlDsa mldsaMat = {
        .keyAlg = HKS_ALG_RSA, .keyParamSet = HKS_ML_DSA_KEY_PARAM_SET_44,
        .pubKeySize = 0, .priKeySize = HKS_ML_DSA_PRI_KEY_SIZE_2560,
    };
    HksBlob mldsaKey = { .size = sizeof(mldsaMat), .data = reinterpret_cast<uint8_t *>(&mldsaMat) };
    ret = CheckMlDsaKeyLen(HKS_ALG_ML_DSA, HKS_KEY_TYPE_PRIVATE_KEY, &mldsaValues, &mldsaKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO);

    /* invalid keyParamSet -> GetMlDsaExpectedSize fails */
    mldsaMat.keyAlg = HKS_ALG_ML_DSA;
    mldsaMat.keyParamSet = 999;
    ret = CheckMlDsaKeyLen(HKS_ALG_ML_DSA, HKS_KEY_TYPE_PRIVATE_KEY, &mldsaValues, &mldsaKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO);

    /* private key with non-zero pubKeySize */
    mldsaMat.keyParamSet = HKS_ML_DSA_KEY_PARAM_SET_44;
    mldsaMat.pubKeySize = 1;
    ret = CheckMlDsaKeyLen(HKS_ALG_ML_DSA, HKS_KEY_TYPE_PRIVATE_KEY, &mldsaValues, &mldsaKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO);

    /* private key success: need buffer >= sizeof(struct) + 0 + priKeySize */
    mldsaMat.pubKeySize = 0;
    mldsaMat.priKeySize = HKS_ML_DSA_PRI_KEY_SIZE_2560;
    uint8_t priKeyBuf[sizeof(struct HksKeyMaterialMlDsa) + HKS_ML_DSA_PRI_KEY_SIZE_2560] = {0};
    (void)memcpy_s(priKeyBuf, sizeof(priKeyBuf), &mldsaMat, sizeof(mldsaMat));
    HksBlob priKeyBlob = { .size = sizeof(priKeyBuf), .data = priKeyBuf };
    ret = CheckMlDsaKeyLen(HKS_ALG_ML_DSA, HKS_KEY_TYPE_PRIVATE_KEY, &mldsaValues, &priKeyBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    /* key pair success (param set 65): need buffer >= sizeof(struct) + pubKeySize + priKeySize */
    mldsaMat.keyParamSet = HKS_ML_DSA_KEY_PARAM_SET_65;
    mldsaMat.pubKeySize = HKS_ML_DSA_PUB_KEY_SIZE_1952;
    mldsaMat.priKeySize = HKS_ML_DSA_PRI_KEY_SIZE_4032;
    ParamsValues mldsaValues65 = {
        {.needCheck = true, .value = HKS_ML_DSA_KEY_PARAM_SET_65, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    uint8_t keyPairBuf[sizeof(struct HksKeyMaterialMlDsa) + HKS_ML_DSA_PUB_KEY_SIZE_1952 +
        HKS_ML_DSA_PRI_KEY_SIZE_4032] = {0};
    (void)memcpy_s(keyPairBuf, sizeof(keyPairBuf), &mldsaMat, sizeof(mldsaMat));
    HksBlob keyPairBlob = { .size = sizeof(keyPairBuf), .data = keyPairBuf };
    ret = CheckMlDsaKeyLen(HKS_ALG_ML_DSA, HKS_KEY_TYPE_KEY_PAIR, &mldsaValues65, &keyPairBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    /* key pair wrong pubKeySize */
    mldsaMat.pubKeySize = 1;
    (void)memcpy_s(keyPairBuf, sizeof(keyPairBuf), &mldsaMat, sizeof(mldsaMat));
    ret = CheckMlDsaKeyLen(HKS_ALG_ML_DSA, HKS_KEY_TYPE_KEY_PAIR, &mldsaValues65, &keyPairBlob);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO);

    /* key->size < keySize: use struct-only blob with full sizes */
    mldsaMat.pubKeySize = HKS_ML_DSA_PUB_KEY_SIZE_1952;
    mldsaMat.priKeySize = HKS_ML_DSA_PRI_KEY_SIZE_4032;
    HksBlob truncatedKey = { .size = sizeof(mldsaMat), .data = reinterpret_cast<uint8_t *>(&mldsaMat) };
    ret = CheckMlDsaKeyLen(HKS_ALG_ML_DSA, HKS_KEY_TYPE_KEY_PAIR, &mldsaValues65, &truncatedKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO);

    /* --- CheckMlKemKeyLen --- */
    /* key too small */
    ret = CheckMlKemKeyLen(HKS_ALG_ML_KEM, 0, &mldsaValues, &smallKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO);

    /* invalid keyAlg */
    struct HksKeyMaterialMlKem mlkemMat = {
        .keyAlg = HKS_ALG_RSA, .keyParamSet = HKS_ML_KEM_KEY_PARAM_SET_768,
        .pubKeySize = 0, .priKeySize = HKS_ML_KEM_PRI_KEY_SIZE_2400,
    };
    HksBlob mlkemKey = { .size = sizeof(mlkemMat), .data = reinterpret_cast<uint8_t *>(&mlkemMat) };
    ParamsValues mlkemValues = {
        {.needCheck = true, .value = HKS_ML_KEM_KEY_PARAM_SET_768, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    ret = CheckMlKemKeyLen(HKS_ALG_ML_KEM, HKS_KEY_TYPE_PRIVATE_KEY, &mlkemValues, &mlkemKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO);

    /* private key success: need buffer >= sizeof(struct) + 0 + priKeySize */
    mlkemMat.keyAlg = HKS_ALG_ML_KEM;
    mlkemMat.pubKeySize = 0;
    mlkemMat.priKeySize = HKS_ML_KEM_PRI_KEY_SIZE_2400;
    uint8_t kemPriBuf[sizeof(struct HksKeyMaterialMlKem) + HKS_ML_KEM_PRI_KEY_SIZE_2400] = {0};
    (void)memcpy_s(kemPriBuf, sizeof(kemPriBuf), &mlkemMat, sizeof(mlkemMat));
    HksBlob kemPriBlob = { .size = sizeof(kemPriBuf), .data = kemPriBuf };
    ret = CheckMlKemKeyLen(HKS_ALG_ML_KEM, HKS_KEY_TYPE_PRIVATE_KEY, &mlkemValues, &kemPriBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    /* key pair success (param set 1024) */
    mlkemMat.keyParamSet = HKS_ML_KEM_KEY_PARAM_SET_1024;
    mlkemMat.pubKeySize = HKS_ML_KEM_PUB_KEY_SIZE_1568;
    mlkemMat.priKeySize = HKS_ML_KEM_PRI_KEY_SIZE_3168;
    ParamsValues mlkemValues1024 = {
        {.needCheck = true, .value = HKS_ML_KEM_KEY_PARAM_SET_1024, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    uint8_t kemPairBuf[sizeof(struct HksKeyMaterialMlKem) + HKS_ML_KEM_PUB_KEY_SIZE_1568 +
        HKS_ML_KEM_PRI_KEY_SIZE_3168] = {0};
    (void)memcpy_s(kemPairBuf, sizeof(kemPairBuf), &mlkemMat, sizeof(mlkemMat));
    HksBlob kemPairBlob = { .size = sizeof(kemPairBuf), .data = kemPairBuf };
    ret = CheckMlKemKeyLen(HKS_ALG_ML_KEM, HKS_KEY_TYPE_KEY_PAIR, &mlkemValues1024, &kemPairBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    /* key pair wrong priKeySize */
    mlkemMat.priKeySize = 1;
    ret = CheckMlKemKeyLen(HKS_ALG_ML_KEM, HKS_KEY_TYPE_KEY_PAIR, &mlkemValues1024, &mlkemKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest017
 * @tc.desc: tdd HandleKeyClassTag branches
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest017, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest017");

    /* no KEY_CLASS tag -> returns via HksGetParamSet */
    struct HksParamSet *paramSetIn = nullptr;
    struct HksParamSet *paramSetOut = nullptr;
    int32_t ret = HksInitParamSet(&paramSetIn);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam algParam = { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES };
    ret = HksAddParams(paramSetIn, &algParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSetIn);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HandleKeyClassTag(paramSetIn, &paramSetOut);
    ASSERT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSetOut);

    /* KEY_CLASS_DEFAULT */
    struct HksParamSet *paramSet2 = nullptr;
    ret = HksInitParamSet(&paramSet2);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam classParam = { .tag = HKS_TAG_KEY_CLASS, .uint32Param = HKS_KEY_CLASS_DEFAULT };
    ret = HksAddParams(paramSet2, &classParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet2);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *out2 = nullptr;
    ret = HandleKeyClassTag(paramSet2, &out2);
    ASSERT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&out2);
    HksFreeParamSet(&paramSet2);

    /* KEY_CLASS_EXTENSION -> NOT_SUPPORTED */
    struct HksParamSet *paramSet3 = nullptr;
    ret = HksInitParamSet(&paramSet3);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam extParam = { .tag = HKS_TAG_KEY_CLASS, .uint32Param = HKS_KEY_CLASS_EXTENSION };
    ret = HksAddParams(paramSet3, &extParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet3);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *out3 = nullptr;
    ret = HandleKeyClassTag(paramSet3, &out3);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);
    HksFreeParamSet(&paramSet3);

    /* invalid keyClass -> INVALID_ARGUMENT */
    struct HksParamSet *paramSet4 = nullptr;
    ret = HksInitParamSet(&paramSet4);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam invalidParam = { .tag = HKS_TAG_KEY_CLASS, .uint32Param = 99 };
    ret = HksAddParams(paramSet4, &invalidParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet4);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *out4 = nullptr;
    ret = HandleKeyClassTag(paramSet4, &out4);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet4);

    HksFreeParamSet(&paramSetIn);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest018
 * @tc.desc: tdd HksCheckOptionalParam derive/mac purpose and invalid tag
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest018, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest018");
    struct HksParam param = { 0 };
    // DERIVE + RSA (not in allow list) -> INVALID_PURPOSE
    ASSERT_EQ(HksCheckOptionalParam(HKS_TAG_BLOCK_MODE, HKS_ALG_RSA, HKS_KEY_PURPOSE_DERIVE, false, &param),
        HKS_ERROR_INVALID_PURPOSE);
    // MAC + ECC (not in allow list) -> INVALID_PURPOSE
    ASSERT_EQ(HksCheckOptionalParam(HKS_TAG_DIGEST, HKS_ALG_ECC, HKS_KEY_PURPOSE_MAC, false, &param),
        HKS_ERROR_INVALID_PURPOSE);
    // invalid tag -> HKS_FAILURE
    ASSERT_EQ(HksCheckOptionalParam(9999, HKS_ALG_AES, HKS_KEY_PURPOSE_ENCRYPT, false, &param), HKS_FAILURE);
    // DERIVE + AES (allowed) -> not INVALID_PURPOSE
    ASSERT_NE(HksCheckOptionalParam(HKS_TAG_BLOCK_MODE, HKS_ALG_AES, HKS_KEY_PURPOSE_DERIVE, false, &param),
        HKS_ERROR_INVALID_PURPOSE);
    // MAC + HMAC (allowed) -> not INVALID_PURPOSE
    ASSERT_NE(HksCheckOptionalParam(HKS_TAG_DIGEST, HKS_ALG_HMAC, HKS_KEY_PURPOSE_MAC, false, &param),
        HKS_ERROR_INVALID_PURPOSE);
    // DERIVE + 3DES (allowed) -> not INVALID_PURPOSE
    ASSERT_NE(HksCheckOptionalParam(HKS_TAG_PADDING, HKS_ALG_3DES, HKS_KEY_PURPOSE_DERIVE, false, &param),
        HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest019
 * @tc.desc: tdd HksCheckOptionalParam with absent optional param
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest019, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest019");
    struct HksParam param = { 0 };
    // absent optional param (padding) for AES encrypt -> success or get-fail, but not failure
    int32_t ret = HksCheckOptionalParam(HKS_TAG_PADDING, HKS_ALG_AES, HKS_KEY_PURPOSE_ENCRYPT, true, &param);
    ASSERT_NE(ret, HKS_FAILURE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest020
 * @tc.desc: tdd CheckCurve25519KeyLen branches
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest020, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest020");
    ParamsValues values = {
        {.needCheck = true, .value = HKS_CURVE25519_KEY_SIZE_256, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };

    /* key blob too small */
    uint8_t small[4] = {0};
    HksBlob smallKey = { .size = sizeof(small), .data = small };
    int32_t ret = CheckCurve25519KeyLen(HKS_ALG_X25519, HKS_KEY_TYPE_PRIVATE_KEY, &values, &smallKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "020 small size failed, ret = " << ret;

    /* keyAlg/keySize mismatch */
    struct HksKeyMaterial25519 mat = {
        .keyAlg = HKS_ALG_RSA, .keySize = HKS_CURVE25519_KEY_SIZE_256,
        .pubKeySize = 0, .priKeySize = HKS_KEY_BYTES(HKS_CURVE25519_KEY_SIZE_256), .reserved = 0,
    };
    HksBlob key = { .size = sizeof(mat), .data = reinterpret_cast<uint8_t *>(&mat) };
    ret = CheckCurve25519KeyLen(HKS_ALG_X25519, HKS_KEY_TYPE_PRIVATE_KEY, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "020 keyAlg mismatch failed, ret = " << ret;

    /* pubKeySize > 256 */
    mat.keyAlg = HKS_ALG_X25519;
    mat.pubKeySize = HKS_CURVE25519_KEY_SIZE_256 + 1;
    ret = CheckCurve25519KeyLen(HKS_ALG_X25519, HKS_KEY_TYPE_PRIVATE_KEY, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "020 pubKey size failed, ret = " << ret;

    /* priKeySize == 0 */
    mat.pubKeySize = 0;
    mat.priKeySize = 0;
    ret = CheckCurve25519KeyLen(HKS_ALG_X25519, HKS_KEY_TYPE_PRIVATE_KEY, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "020 priKey zero failed, ret = " << ret;

    /* key->size < keySize */
    mat.priKeySize = HKS_KEY_BYTES(HKS_CURVE25519_KEY_SIZE_256);
    HksBlob truncatedKey = { .size = sizeof(mat), .data = reinterpret_cast<uint8_t *>(&mat) };
    ret = CheckCurve25519KeyLen(HKS_ALG_X25519, HKS_KEY_TYPE_PRIVATE_KEY, &values, &truncatedKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "020 truncated failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest021
 * @tc.desc: tdd CheckDHKeyLen branches
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest021, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest021");
    ParamsValues values = {
        {.needCheck = true, .value = HKS_DH_KEY_SIZE_4096, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };

    /* key blob too small */
    uint8_t small[4] = {0};
    HksBlob smallKey = { .size = sizeof(small), .data = small };
    int32_t ret = CheckDHKeyLen(HKS_ALG_DH, HKS_KEY_TYPE_PRIVATE_KEY, &values, &smallKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "021 small size failed, ret = " << ret;

    /* keyAlg/keySize mismatch */
    struct HksKeyMaterialDh mat = {
        .keyAlg = HKS_ALG_RSA, .keySize = HKS_DH_KEY_SIZE_4096,
        .pubKeySize = 0, .priKeySize = HKS_KEY_BYTES(HKS_DH_KEY_SIZE_4096), .reserved = 0,
    };
    HksBlob key = { .size = sizeof(mat), .data = reinterpret_cast<uint8_t *>(&mat) };
    ret = CheckDHKeyLen(HKS_ALG_DH, HKS_KEY_TYPE_PRIVATE_KEY, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "021 keyAlg mismatch failed, ret = " << ret;

    /* pubKeySize > 4096 */
    mat.keyAlg = HKS_ALG_DH;
    mat.pubKeySize = HKS_DH_KEY_SIZE_4096 + 1;
    ret = CheckDHKeyLen(HKS_ALG_DH, HKS_KEY_TYPE_PRIVATE_KEY, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "021 pubKey size failed, ret = " << ret;

    /* priKeySize == 0 */
    mat.pubKeySize = 0;
    mat.priKeySize = 0;
    ret = CheckDHKeyLen(HKS_ALG_DH, HKS_KEY_TYPE_PRIVATE_KEY, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "021 priKey zero failed, ret = " << ret;

    /* key->size < keySize */
    mat.priKeySize = HKS_KEY_BYTES(HKS_DH_KEY_SIZE_4096);
    HksBlob truncatedKey = { .size = sizeof(mat), .data = reinterpret_cast<uint8_t *>(&mat) };
    ret = CheckDHKeyLen(HKS_ALG_DH, HKS_KEY_TYPE_PRIVATE_KEY, &values, &truncatedKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "021 truncated failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest022
 * @tc.desc: tdd CheckEccKeyLen small size and zero zSize
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest022, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest022");
    ParamsValues values = {
        {.needCheck = true, .value = HKS_ECC_KEY_SIZE_521, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };

    /* key blob too small */
    uint8_t small[4] = {0};
    HksBlob smallKey = { .size = sizeof(small), .data = small };
    int32_t ret = CheckEccKeyLen(HKS_ALG_ECC, HKS_KEY_TYPE_PRIVATE_KEY, &values, &smallKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "022 small size failed, ret = " << ret;

    /* zSize == 0 */
    struct HksKeyMaterialEcc mat = {
        .keyAlg = HKS_ALG_ECC, .keySize = HKS_ECC_KEY_SIZE_521,
        .xSize = HKS_ECC_KEY_SIZE_521, .ySize = HKS_ECC_KEY_SIZE_521, .zSize = 0,
    };
    HksBlob key = { .size = sizeof(mat), .data = reinterpret_cast<uint8_t *>(&mat) };
    ret = CheckEccKeyLen(HKS_ALG_ECC, HKS_KEY_TYPE_PRIVATE_KEY, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "022 zero zSize failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest023
 * @tc.desc: tdd CheckDsaKeyLen small size
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest023, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest023");
    ParamsValues values = {
        {.needCheck = true, .value = DEFAULT_VALUE, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    uint8_t small[4] = {0};
    HksBlob smallKey = { .size = sizeof(small), .data = small };
    int32_t ret = CheckDsaKeyLen(HKS_ALG_DSA, HKS_KEY_TYPE_PRIVATE_KEY, &values, &smallKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "023 small size failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest024
 * @tc.desc: tdd CheckKeyLen switch dispatch and default
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest024, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest024");
    ParamsValues values = {
        {.needCheck = true, .value = HKS_CURVE25519_KEY_SIZE_256, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };

    uint8_t small[4] = {0};
    HksBlob smallKey = { .size = sizeof(small), .data = small };

    /* dispatch to CheckCurve25519KeyLen (returns INVALID_KEY_INFO for small blob) */
    int32_t ret = CheckKeyLen(HKS_ALG_X25519, HKS_KEY_TYPE_PRIVATE_KEY, &values, &smallKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "024 dispatch failed, ret = " << ret;

    /* default -> INVALID_ALGORITHM */
    ret = CheckKeyLen(0, HKS_KEY_TYPE_PRIVATE_KEY, &values, &smallKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM) << "024 default failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest025
 * @tc.desc: tdd CheckImportKeySize keyAlg mismatch
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest025, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest025");
    ParamsValues values = {
        {.needCheck = true, .value = DEFAULT_VALUE, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    struct HksPubKeyInfo info = {
        .keyAlg = HKS_ALG_RSA, .keySize = DEFAULT_VALUE,
        .nOrXSize = 0, .eOrYSize = 0, .placeHolder = 0,
    };
    HksBlob key = { .size = sizeof(info), .data = reinterpret_cast<uint8_t *>(&info) };
    int32_t ret = CheckImportKeySize(HKS_ALG_ECC, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "025 keyAlg mismatch failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest026
 * @tc.desc: tdd CheckImportSymmetricKeySize size mismatch
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest026, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest026");
    ParamsValues values = {
        {.needCheck = true, .value = HKS_AES_KEY_SIZE_128, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = CheckImportSymmetricKeySize(&values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "026 symmetric size failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest027
 * @tc.desc: tdd CheckGenKeyMacDeriveParams invalid alg
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest027, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest027");
    ParamsValues params;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));
    int32_t ret = CheckGenKeyMacDeriveParams(HKS_ALG_RSA, HKS_KEY_PURPOSE_MAC, nullptr, &params, 0);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE) << "027 invalid alg failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest028
 * @tc.desc: tdd CheckPbkdf2DeriveKeyParams iteration and salt
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest028, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest028");

    /* iteration too small */
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam iteration = { .tag = HKS_TAG_ITERATION, .uint32Param = 1 };
    ret = HksAddParams(paramSet, &iteration, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = CheckPbkdf2DeriveKeyParams(paramSet);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ITERATION) << "028 iteration failed, ret = " << ret;
    HksFreeParamSet(&paramSet);

    /* salt blob too small */
    struct HksParamSet *paramSet2 = nullptr;
    ret = HksInitParamSet(&paramSet2);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam iteration2 = { .tag = HKS_TAG_ITERATION, .uint32Param = 1000 };
    ret = HksAddParams(paramSet2, &iteration2, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    uint8_t saltBuf[4] = {0};
    struct HksParam salt = {0};
    salt.tag = HKS_TAG_SALT;
    salt.blob.size = sizeof(saltBuf);
    salt.blob.data = saltBuf;
    ret = HksAddParams(paramSet2, &salt, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet2);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = CheckPbkdf2DeriveKeyParams(paramSet2);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_SALT) << "028 salt failed, ret = " << ret;
    HksFreeParamSet(&paramSet2);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest029
 * @tc.desc: tdd RsaCheckKeySize flex key size
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest029, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest029");
    /* flexible key size divisible by HKS_RSA_KEYSIZE_CNT in [1024, 2048] */
    int32_t ret = RsaCheckKeySize(1040);
    ASSERT_EQ(ret, HKS_SUCCESS) << "029 flex success failed, ret = " << ret;

    /* not divisible and not a supported size */
    ret = RsaCheckKeySize(1025);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_SIZE) << "029 invalid key size failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest030
 * @tc.desc: tdd CheckAesAeCipherData branches
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest030, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest030");
    struct HksBlob outData = { .size = 0, .data = nullptr };

    /* encrypt with overflow inSize */
    struct HksBlob bigIn = { .size = UINT32_MAX, .data = nullptr };
    int32_t ret = CheckAesAeCipherData(HKS_CMD_ID_ENCRYPT, &bigIn, &outData, HKS_AE_TAG_LEN);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "030 encrypt overflow failed, ret = " << ret;

    /* encrypt with out buffer too small */
    struct HksBlob normalIn = { .size = 16, .data = nullptr };
    ret = CheckAesAeCipherData(HKS_CMD_ID_ENCRYPT, &normalIn, &outData, HKS_AE_TAG_LEN);
    ASSERT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL) << "030 encrypt buf failed, ret = " << ret;

    /* decrypt with inSize smaller than tag len */
    struct HksBlob tinyIn = { .size = 4, .data = nullptr };
    ret = CheckAesAeCipherData(HKS_CMD_ID_DECRYPT, &tinyIn, &outData, HKS_AE_TAG_LEN);
    ASSERT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL) << "030 decrypt buf failed, ret = " << ret;

    /* unsupported cmd id */
    ret = CheckAesAeCipherData(0, &normalIn, &outData, HKS_AE_TAG_LEN);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "030 default cmd failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest031
 * @tc.desc: tdd IsValidCcmTagLen and IsValidGcmTagLen
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest031, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest031");
    int32_t ret = IsValidCcmTagLen(4);
    ASSERT_EQ(ret, HKS_SUCCESS) << "031 ccm valid failed, ret = " << ret;
    ret = IsValidCcmTagLen(5);
    ASSERT_EQ(ret, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID) << "031 ccm invalid failed, ret = " << ret;

    ret = IsValidGcmTagLen(16);
    ASSERT_EQ(ret, HKS_SUCCESS) << "031 gcm valid failed, ret = " << ret;
    ret = IsValidGcmTagLen(12);
    ASSERT_EQ(ret, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID) << "031 gcm invalid failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest032
 * @tc.desc: tdd CheckMacPurpose and CheckMacOutput branches
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest032, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest032");

    /* purpose != MAC */
    struct HksParamSet *purposeSet = nullptr;
    int32_t ret = HksInitParamSet(&purposeSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam purposeParam = { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT };
    ret = HksAddParams(purposeSet, &purposeParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&purposeSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = CheckMacPurpose(purposeSet);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE) << "032 purpose failed, ret = " << ret;
    HksFreeParamSet(&purposeSet);

    /* mac buffer too small */
    struct HksParamSet *digestSet = nullptr;
    ret = HksInitParamSet(&digestSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam digestParam = { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 };
    ret = HksAddParams(digestSet, &digestParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&digestSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t keyBuf[4] = {0};
    struct HksBlob key = { .size = sizeof(keyBuf), .data = keyBuf };
    struct HksBlob mac = { .size = 0, .data = nullptr };
    ret = CheckMacOutput(&key, digestSet, &mac, false);
    ASSERT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL) << "032 mac buf failed, ret = " << ret;

    /* local check with key too small */
    uint8_t macBuf[HKS_DIGEST_SHA256_LEN] = {0};
    struct HksBlob macOk = { .size = sizeof(macBuf), .data = macBuf };
    struct HksBlob smallKey = { 0, nullptr };
    ret = CheckMacOutput(&smallKey, digestSet, &macOk, true);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_SIZE) << "032 key size failed, ret = " << ret;
    HksFreeParamSet(&digestSet);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest033
 * @tc.desc: tdd CheckMutableParams ml-dsa and ml-kem
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest033, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest033");
    struct ParamsValues params;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));

    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_ML_DSA, HKS_KEY_TYPE_PRIVATE_KEY, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE) << "033 ml-dsa invalid failed, ret = " << ret;

    params.purpose.value = HKS_KEY_PURPOSE_SIGN;
    ret = CheckMutableParams(HKS_ALG_ML_DSA, HKS_KEY_TYPE_PRIVATE_KEY, &params);
    ASSERT_EQ(ret, HKS_SUCCESS) << "033 ml-dsa success failed, ret = " << ret;

    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    ret = CheckMutableParams(HKS_ALG_ML_KEM, HKS_KEY_TYPE_PRIVATE_KEY, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE) << "033 ml-kem invalid failed, ret = " << ret;

    params.purpose.value = HKS_KEY_PURPOSE_UNWRAP;
    ret = CheckMutableParams(HKS_ALG_ML_KEM, HKS_KEY_TYPE_PRIVATE_KEY, &params);
    ASSERT_EQ(ret, HKS_SUCCESS) << "033 ml-kem success failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest034
 * @tc.desc: tdd HksCoreCheckAgreeKeyParams local check branches
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest034, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest034");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam algParam = { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH };
    ret = HksAddParams(paramSet, &algParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    /* private key blob too small to hold header */
    struct HksBlob priv = { .size = 0, .data = nullptr };
    struct HksBlob peer = { .size = 0, .data = nullptr };
    struct HksBlob agreed = { .size = 0, .data = nullptr };
    ret = HksCoreCheckAgreeKeyParams(paramSet, &priv, &peer, &agreed, true);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "034 header too small failed, ret = " << ret;

    /* agreed key buffer too small */
    struct HksKeyMaterialHeader header = { .keyAlg = HKS_ALG_ECDH, .keySize = 2048 };
    struct HksBlob privOk = { .size = sizeof(header), .data = reinterpret_cast<uint8_t *>(&header) };
    ret = HksCoreCheckAgreeKeyParams(paramSet, &privOk, &peer, &agreed, true);
    ASSERT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL) << "034 agreed buf failed, ret = " << ret;

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest035
 * @tc.desc: tdd HksCoreCheckDeriveKeyParams invalid purpose
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest035, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest035");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam algParam = { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HKDF };
    struct HksParam purposeParam = { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT };
    struct HksParam params[] = { algParam, purposeParam };
    ret = HksAddParams(paramSet, params, 2);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob mainKey = { .size = 0, .data = nullptr };
    struct HksBlob derivedKey = { .size = 0, .data = nullptr };
    ret = HksCoreCheckDeriveKeyParams(paramSet, &mainKey, &derivedKey, false);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE) << "035 invalid purpose failed, ret = " << ret;

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest036
 * @tc.desc: tdd HksCoreCheckAgreeDeriveFinishParams non-symmetric alg
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest036, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest036");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam keySizeParam = { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 };
    struct HksParam algParam = { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA };
    struct HksParam params[] = { keySizeParam, algParam };
    ret = HksAddParams(paramSet, params, 2);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t keyBuf[HKS_KEY_BYTES(HKS_AES_KEY_SIZE_128)] = {0};
    struct HksBlob key = { .size = sizeof(keyBuf), .data = keyBuf };
    ret = HksCoreCheckAgreeDeriveFinishParams(&key, paramSet);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "036 non-symmetric failed, ret = " << ret;

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest037
 * @tc.desc: tdd HksLocalCheckCipherParams aes invalid key size
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest037, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest037");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam algParam = { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES };
    ret = HksAddParams(paramSet, &algParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob inData = { .size = 0, .data = nullptr };
    struct HksBlob outData = { .size = 0, .data = nullptr };
    ret = HksLocalCheckCipherParams(HKS_CMD_ID_ENCRYPT, 0, paramSet, &inData, &outData);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_SIZE) << "037 aes key size failed, ret = " << ret;

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest038
 * @tc.desc: tdd CheckAsyKeyMaterialSize invalid blob and default alg
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest038, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest038");

    /* invalid keyIn blob */
    struct HksBlob invalidBlob = { .size = 0, .data = nullptr };
    int32_t ret = CheckAsyKeyMaterialSize(HKS_ALG_RSA, &invalidBlob, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "038 invalid blob failed, ret = " << ret;

    /* symmetric/unknown alg skips material validation */
    uint8_t buf[4] = {0};
    struct HksBlob validBlob = { .size = sizeof(buf), .data = buf };
    ret = CheckAsyKeyMaterialSize(HKS_ALG_AES, &validBlob, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS) << "038 default alg failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest039
 * @tc.desc: tdd CheckMlKemKeyLen truncated key blob
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest039, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest039");
    ParamsValues mlkemValues = {
        {.needCheck = true, .value = HKS_ML_KEM_KEY_PARAM_SET_768, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    struct HksKeyMaterialMlKem mlkemMat = {
        .keyAlg = HKS_ALG_ML_KEM, .keyParamSet = HKS_ML_KEM_KEY_PARAM_SET_768,
        .pubKeySize = 0, .priKeySize = HKS_ML_KEM_PRI_KEY_SIZE_2400, .reserved = 0,
    };
    HksBlob truncatedKey = { .size = sizeof(mlkemMat), .data = reinterpret_cast<uint8_t *>(&mlkemMat) };
    int32_t ret = CheckMlKemKeyLen(HKS_ALG_ML_KEM, HKS_KEY_TYPE_PRIVATE_KEY, &mlkemValues, &truncatedKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "039 ml-kem truncated failed, ret = " << ret;
}

}
