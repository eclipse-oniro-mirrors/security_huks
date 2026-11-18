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

#include "hks_base_check_test.h"

#include <gtest/gtest.h>

#include "hks_base_check.h"

#include "file_ex.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_cmd_id.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_param.h"

#include <cstring>

using namespace testing::ext;
namespace Unittest::HksFrameworkCommonBaseCheckTest {
class HksBaseCheckTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksBaseCheckTest::SetUpTestCase(void)
{
}

void HksBaseCheckTest::TearDownTestCase(void)
{
}

void HksBaseCheckTest::SetUp()
{
}

void HksBaseCheckTest::TearDown()
{
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest001
 * @tc.desc: tdd HksCheckCipherMaterialParams, expecting HKS_ERROR_CHECK_GET_IV_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest001");
    struct ParamsValues values;
    struct Params param = { true, HKS_MODE_CBC };
    values.mode = param;
    int32_t ret = HksCheckCipherMaterialParams(HKS_ALG_SM4, &values, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_CHECK_GET_IV_FAIL) << "HksCheckCipherMaterialParams failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest002
 * @tc.desc: tdd HksCheckCipherData, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest002");
    struct ParamsValues values;
    struct Params param = { true, HKS_MODE_OFB };
    values.mode = param;
    int32_t ret = HksCheckCipherData(0, HKS_ALG_SM4, &values, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksCheckCipherData failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest003
 * @tc.desc: tdd HksCheckCipherData, expecting HKS_ERROR_INVALID_ALGORITHM
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest003");
    int32_t ret = HksCheckCipherData(0, HKS_ALG_PBKDF2, nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM) << "HksCheckCipherData failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest004
 * @tc.desc: tdd HksCheckCipherMutableParams, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest004");
    int32_t ret = HksCheckCipherMutableParams(0, HKS_ALG_SM4, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksCheckCipherMutableParams failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest005
 * @tc.desc: tdd HksCheckCipherMutableParams, expecting HKS_ERROR_INVALID_PADDING
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest005");
    struct ParamsValues values;
    struct Params purParam = { true, HKS_KEY_PURPOSE_ENCRYPT };
    values.purpose = purParam;
    struct Params modeParam = { true, HKS_MODE_OFB };
    values.mode = modeParam;
    struct Params paddingParam = { true, HKS_PADDING_PKCS7 };
    values.padding = paddingParam;
    int32_t ret = HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_SM4, &values);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PADDING) << "HksCheckCipherMutableParams failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest020
 * @tc.desc: tdd HksCheckValue, expecting HKS_SUCCESS and HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest020, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest020");
    uint32_t expectVals[] = {1, 2, 3};
    ASSERT_EQ(HksCheckValue(2, expectVals, HKS_ARRAY_SIZE(expectVals)), HKS_SUCCESS);
    ASSERT_EQ(HksCheckValue(99, expectVals, HKS_ARRAY_SIZE(expectVals)), HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest021
 * @tc.desc: tdd HksCheckNeedCache, expecting HKS_SUCCESS for ed25519/sm2/ML_DSA/ML_KEM/digest_none, HKS_FAILURE otherwise
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest021, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest021");
    ASSERT_EQ(HksCheckNeedCache(HKS_ALG_ED25519, HKS_DIGEST_SHA256), HKS_SUCCESS);
    ASSERT_EQ(HksCheckNeedCache(HKS_ALG_SM2, HKS_DIGEST_SHA256), HKS_SUCCESS);
    ASSERT_EQ(HksCheckNeedCache(HKS_ALG_ML_DSA, HKS_DIGEST_SHA256), HKS_SUCCESS);
    ASSERT_EQ(HksCheckNeedCache(HKS_ALG_ML_KEM, HKS_DIGEST_SHA256), HKS_SUCCESS);
    ASSERT_EQ(HksCheckNeedCache(HKS_ALG_AES, HKS_DIGEST_NONE), HKS_SUCCESS);
    ASSERT_EQ(HksCheckNeedCache(HKS_ALG_AES, HKS_DIGEST_SHA256), HKS_FAILURE);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest022
 * @tc.desc: tdd HksCheckGenKeyPurpose, expecting HKS_SUCCESS for unique valid purpose, HKS_ERROR_INVALID_PURPOSE for multi-purpose
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest022, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest022");
    // unique purpose → success
    ASSERT_EQ(HksCheckGenKeyPurpose(HKS_ALG_AES, HKS_KEY_PURPOSE_ENCRYPT, HKS_KEY_FLAG_GENERATE_KEY), HKS_SUCCESS);
    // multi-purpose (encrypt + mac) → invalid
    ASSERT_EQ(HksCheckGenKeyPurpose(HKS_ALG_AES, HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_MAC,
        HKS_KEY_FLAG_GENERATE_KEY), HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest023
 * @tc.desc: tdd HksCheckSignVerifyMutableParams, expecting HKS_ERROR_INVALID_PURPOSE / HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest023, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest023");
    struct ParamsValues values = {};
    struct Params purParam = { true, HKS_KEY_PURPOSE_SIGN };
    values.purpose = purParam;
    // sign with SIGN purpose → success
    ASSERT_EQ(HksCheckSignVerifyMutableParams(HKS_CMD_ID_SIGN, HKS_ALG_ECC, &values), HKS_SUCCESS);
    // verify without VERIFY purpose → invalid
    values.purpose.value = HKS_KEY_PURPOSE_SIGN;
    ASSERT_EQ(HksCheckSignVerifyMutableParams(HKS_CMD_ID_VERIFY, HKS_ALG_ECC, &values), HKS_ERROR_INVALID_PURPOSE);
    // invalid cmdId → invalid argument
    ASSERT_EQ(HksCheckSignVerifyMutableParams(0, HKS_ALG_ECC, &values), HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest024
 * @tc.desc: tdd InitInputParamsByAlg, expecting HKS_SUCCESS for known alg, HKS_ERROR_INVALID_ALGORITHM for unknown
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest024, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest024");
    struct ParamsValues inputParams = {};
    ASSERT_EQ(InitInputParamsByAlg(HKS_ALG_AES, HKS_CHECK_TYPE_GEN_KEY, &inputParams), HKS_SUCCESS);
    ASSERT_EQ(InitInputParamsByAlg(0xFFFF, HKS_CHECK_TYPE_GEN_KEY, &inputParams), HKS_ERROR_INVALID_ALGORITHM);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest025
 * @tc.desc: tdd GetExpectParams, expecting HKS_SUCCESS for known alg, HKS_ERROR_INVALID_ALGORITHM for unknown
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest025, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest025");
    struct ExpectParamsValues expectValues = {};
    ASSERT_EQ(GetExpectParams(HKS_ALG_AES, HKS_CHECK_TYPE_GEN_KEY, &expectValues), HKS_SUCCESS);
    ASSERT_EQ(GetExpectParams(0xFFFF, HKS_CHECK_TYPE_GEN_KEY, &expectValues), HKS_ERROR_INVALID_ALGORITHM);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest026
 * @tc.desc: tdd GetInputParams, expecting HKS_SUCCESS and HKS_ERROR_CHECK_GET_KEY_SIZE_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest026, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest026");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam keySizeParam = { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 };
    ret = HksAddParams(paramSet, &keySizeParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct ParamsValues inputParams = {};
    inputParams.keyLen.needCheck = true;
    // paramSet has KEY_SIZE → success
    ASSERT_EQ(GetInputParams(paramSet, &inputParams), HKS_SUCCESS);
    ASSERT_EQ(inputParams.keyLen.value, HKS_AES_KEY_SIZE_128);

    // paramSet missing PURPOSE → fail
    inputParams.purpose.needCheck = true;
    ASSERT_EQ(GetInputParams(paramSet, &inputParams), HKS_ERROR_CHECK_GET_PURPOSE_FAIL);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest028
 * @tc.desc: tdd HksCheckCipherMutableParams, expecting HKS_SUCCESS for AES/CBC/PKCS7 encrypt
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest028, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest028");
    struct ParamsValues values = {};
    values.purpose = { true, HKS_KEY_PURPOSE_ENCRYPT };
    values.mode = { true, HKS_MODE_CBC };
    values.padding = { true, HKS_PADDING_PKCS7 };
    int32_t ret = HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_AES, &values);
    ASSERT_EQ(ret, HKS_SUCCESS) << "HksCheckCipherMutableParams AES CBC success failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest029
 * @tc.desc: tdd HksCheckCipherMutableParams, expecting HKS_ERROR_INVALID_PURPOSE for wrong purpose
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest029, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest029");
    struct ParamsValues values = {};
    values.purpose = { true, HKS_KEY_PURPOSE_SIGN };
    int32_t ret = HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_AES, &values);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE) << "HksCheckCipherMutableParams wrong purpose, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest030
 * @tc.desc: tdd CheckImportMutableParams, expecting HKS_ERROR_INVALID_PURPOSE for DSA non-verify, HKS_SUCCESS for DSA verify
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest030, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest030");
    struct ParamsValues values = {};
    values.purpose = { true, HKS_KEY_PURPOSE_VERIFY };
    ASSERT_EQ(CheckImportMutableParams(HKS_ALG_DSA, &values), HKS_SUCCESS);
    values.purpose.value = HKS_KEY_PURPOSE_SIGN;
    ASSERT_EQ(CheckImportMutableParams(HKS_ALG_DSA, &values), HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest031
 * @tc.desc: tdd CheckImportMutableParams, expecting HKS_ERROR_INVALID_PURPOSE for ED25519 non-verify
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest031, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest031");
    struct ParamsValues values = {};
    values.purpose = { true, HKS_KEY_PURPOSE_SIGN };
    ASSERT_EQ(CheckImportMutableParams(HKS_ALG_ED25519, &values), HKS_ERROR_INVALID_PURPOSE);
    values.purpose.value = HKS_KEY_PURPOSE_VERIFY;
    ASSERT_EQ(CheckImportMutableParams(HKS_ALG_ED25519, &values), HKS_SUCCESS);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest032
 * @tc.desc: tdd CheckImportMutableParams, expecting HKS_ERROR_INVALID_PURPOSE for ECC non-verify/non-agree/non-unwrap
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest032, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest032");
    struct ParamsValues values = {};
    values.purpose = { true, HKS_KEY_PURPOSE_ENCRYPT };
    ASSERT_EQ(CheckImportMutableParams(HKS_ALG_ECC, &values), HKS_ERROR_INVALID_PURPOSE);
    values.purpose.value = HKS_KEY_PURPOSE_VERIFY;
    ASSERT_EQ(CheckImportMutableParams(HKS_ALG_ECC, &values), HKS_SUCCESS);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest033
 * @tc.desc: tdd HksCheckGenKeyMutableParams, expecting HKS_SUCCESS for default alg (no padding check)
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest033, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest033");
    struct ParamsValues values = {};
    int32_t ret = HksCheckGenKeyMutableParams(HKS_ALG_HMAC, &values);
    ASSERT_EQ(ret, HKS_SUCCESS) << "HksCheckGenKeyMutableParams default alg failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest034
 * @tc.desc: tdd HksCheckSecureSignParams, expecting HKS_SUCCESS or HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest034, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest034");
    // invalid secureSignType → error
    ASSERT_NE(HksCheckSecureSignParams(0xFFFF), HKS_SUCCESS);
}
/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest006
 * @tc.desc: tdd HksCheckSignature, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest006");

    int32_t ret = HksCheckSignature(0, HKS_ALG_RSA, HKS_ECC_KEY_SIZE_256, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksCheckSignature failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest007
 * @tc.desc: tdd HksCheckSignature, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest007");

    int32_t ret = HksCheckSignature(0, HKS_ALG_ECC, HKS_RSA_KEY_SIZE_1024, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksCheckSignature failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest008
 * @tc.desc: tdd HksCheckSignature, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest008");
    int32_t ret = HksCheckSignature(0, HKS_ALG_SM2, HKS_RSA_KEY_SIZE_1024, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksCheckSignature failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest009
 * @tc.desc: tdd CheckImportMutableParams, expecting HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest009");
    struct ParamsValues values;
    struct Params param = { true, HKS_KEY_PURPOSE_ENCRYPT };
    values.purpose = param;
    int32_t ret = CheckImportMutableParams(HKS_ALG_SM2, &values);
    ASSERT_EQ(ret, HKS_SUCCESS) << "CheckImportMutableParams failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest010
 * @tc.desc: tdd CheckImportMutableParams, expecting HKS_ERROR_INVALID_PURPOSE
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest010");
    struct ParamsValues values;
    struct Params param = { true, HKS_KEY_PURPOSE_ENCRYPT };
    values.purpose = param;
    int32_t ret = CheckImportMutableParams(HKS_ALG_ECC, &values);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE) << "CheckImportMutableParams failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest011
 * @tc.desc: tdd CheckImportMutableParams, expecting HKS_ERROR_INVALID_PURPOSE
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest011");
    struct ParamsValues values;
    struct Params param = { true, HKS_KEY_PURPOSE_DERIVE };
    values.purpose = param;
    int32_t ret = CheckImportMutableParams(HKS_ALG_RSA, &values);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE) << "CheckImportMutableParams failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest012
 * @tc.desc: tdd HksCheckGenKeyMutableParams, expecting HKS_ERROR_INVALID_PADDING
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest012");
    struct ParamsValues values;
    struct Params purParam = { true, HKS_KEY_PURPOSE_ENCRYPT };
    values.purpose = purParam;
    struct Params paddingParam = { true, HKS_PADDING_PSS };
    values.padding = paddingParam;
    int32_t ret = HksCheckGenKeyMutableParams(HKS_ALG_RSA, &values);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PADDING) << "CheckImportMutableParams failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest013
 * @tc.desc: tdd HksCheckGenKeyMutableParams, expecting HKS_ERROR_INVALID_PADDING
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest013");
    struct ParamsValues values;
    struct Params modeParam = { true, HKS_MODE_CBC };
    values.mode = modeParam;
    struct Params purParam = { true, HKS_KEY_PURPOSE_ENCRYPT };
    values.purpose = purParam;
    struct Params paddingParam = { true, HKS_PADDING_PSS };
    values.padding = paddingParam;
    int32_t ret = HksCheckGenKeyMutableParams(HKS_ALG_AES, &values);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PADDING) << "CheckImportMutableParams failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest014
 * @tc.desc: tdd HksGetKeySize, expecting HKS_ERROR_INVALID_KEY_FILE
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest014");
    struct HksBlob key = { .size = 0, .data = nullptr};
    uint32_t keySize = 0;
    int32_t ret = HksGetKeySize(HKS_ALG_RSA, &key, &keySize);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_FILE) << "HksGetKeySize failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest015
 * @tc.desc: tdd HksGetKeySize, expecting HKS_ERROR_INVALID_KEY_FILE
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest015");
    struct HksBlob key = { .size = sizeof(struct HksParamSet), .data = nullptr};
    uint32_t keySize = 0;
    int32_t ret = HksGetKeySize(HKS_ALG_RSA, &key, &keySize);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_FILE) << "HksGetKeySize failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest016
 * @tc.desc: tdd HksCheckCipherMaterialParams, expecting HKS_ERROR_INVALID_AAD
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest016, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest016");
    struct ParamsValues values;
    struct Params modeParam = { true, HKS_MODE_CCM };
    values.mode = modeParam;
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    const char* aadData = "0";
    struct HksBlob aad = { .size = strlen(aadData), .data = (uint8_t *)aadData };
    struct HksParam aadParam = { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = aad };
    ret = HksAddParams(paramSet, &aadParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksCheckCipherMaterialParams(HKS_ALG_AES, &values, paramSet);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_AAD) << "HksCheckCipherMaterialParams failed, ret = " << ret;
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest017
 * @tc.desc: tdd HksCheckCipherMaterialParams, expecting HKS_ERROR_CHECK_GET_IV_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest017, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest017");
    struct ParamsValues values;
    struct Params modeParam = { true, HKS_MODE_CCM };
    values.mode = modeParam;
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    const char* aadData = "00000";
    struct HksBlob aad = { .size = strlen(aadData), .data = (uint8_t *)aadData };
    struct HksParam aadParam = { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = aad };
    ret = HksAddParams(paramSet, &aadParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    const char* nonceData = "000";
    struct HksBlob nonce = { .size = strlen(aadData), .data = (uint8_t *)nonceData };
    struct HksParam param = { .tag = HKS_TAG_NONCE, .blob = nonce };
    ret = HksAddParams(paramSet, &param, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksCheckCipherMaterialParams(HKS_ALG_AES, &values, paramSet);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_NONCE) << "HksCheckCipherMaterialParams failed, ret = " << ret;
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest018
 * @tc.desc: tdd HksGetKeySize, expecting HKS_ERROR_INVALID_KEY_FILE
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest018, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest018");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam param = { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 };
    ret = HksAddParams(paramSet, &param, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksBlob key = { .size = sizeof(paramSet), .data = (uint8_t *)paramSet};
    uint32_t keySize = 0;
    ret = HksGetKeySize(HKS_ALG_RSA, &key, &keySize);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_FILE) << "HksGetKeySize failed, ret = " << ret;
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest019
 * @tc.desc: tdd HksCheckCipherMutableParams, expecting HKS_ERROR_INVALID_PADDING
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest019, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest019");
    struct ParamsValues values;
    struct Params purParam = { true, HKS_KEY_PURPOSE_ENCRYPT };
    values.purpose = purParam;
    struct Params modeParam = { true, HKS_MODE_CFB };
    values.mode = modeParam;
    struct Params paddingParam = { true, HKS_PADDING_PKCS7 };
    values.padding = paddingParam;
    int32_t ret = HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_SM4, &values);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PADDING) << "HksCheckCipherMutableParams failed, ret = " << ret;
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest035
 * @tc.desc: tdd HksCheckSignature RSA SIGN/VERIFY size check
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest035, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest035");
    uint8_t data[512] = { 0 };
    struct HksBlob sigSmall = { .size = 10, .data = data };
    struct HksBlob sigExact = { .size = 128, .data = data };
    struct HksBlob sigLarge = { .size = 256, .data = data };
    // RSA 1024: keySize / 8 = 128
    ASSERT_EQ(HksCheckSignature(HKS_CMD_ID_SIGN, HKS_ALG_RSA, HKS_RSA_KEY_SIZE_1024, &sigSmall),
        HKS_ERROR_BUFFER_TOO_SMALL);
    ASSERT_EQ(HksCheckSignature(HKS_CMD_ID_SIGN, HKS_ALG_RSA, HKS_RSA_KEY_SIZE_1024, &sigExact), HKS_SUCCESS);
    ASSERT_EQ(HksCheckSignature(HKS_CMD_ID_VERIFY, HKS_ALG_RSA, HKS_RSA_KEY_SIZE_1024, &sigLarge),
        HKS_ERROR_INVALID_SIGNATURE_SIZE);
    ASSERT_EQ(HksCheckSignature(HKS_CMD_ID_VERIFY, HKS_ALG_RSA, HKS_RSA_KEY_SIZE_1024, &sigExact), HKS_SUCCESS);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest036
 * @tc.desc: tdd HksCheckSignature ECC SIGN/VERIFY size check
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest036, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest036");
    uint8_t data[256] = { 0 };
    struct HksBlob sigSmall = { .size = 10, .data = data };
    struct HksBlob sigExact = { .size = 72, .data = data };
    struct HksBlob sigLarge = { .size = 128, .data = data };
    // ECC 256: r=32, s=32, threshold = 72
    ASSERT_EQ(HksCheckSignature(HKS_CMD_ID_SIGN, HKS_ALG_ECC, HKS_ECC_KEY_SIZE_256, &sigSmall),
        HKS_ERROR_BUFFER_TOO_SMALL);
    ASSERT_EQ(HksCheckSignature(HKS_CMD_ID_SIGN, HKS_ALG_ECC, HKS_ECC_KEY_SIZE_256, &sigExact), HKS_SUCCESS);
    ASSERT_EQ(HksCheckSignature(HKS_CMD_ID_VERIFY, HKS_ALG_ECC, HKS_ECC_KEY_SIZE_256, &sigLarge),
        HKS_ERROR_INVALID_SIGNATURE_SIZE);
    ASSERT_EQ(HksCheckSignature(HKS_CMD_ID_VERIFY, HKS_ALG_ECC, HKS_ECC_KEY_SIZE_256, &sigExact), HKS_SUCCESS);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest037
 * @tc.desc: tdd HksCheckSignature ED25519 SIGN/VERIFY size check
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest037, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest037");
    uint8_t data[128] = { 0 };
    struct HksBlob sigSmall = { .size = 63, .data = data };
    struct HksBlob sigExact = { .size = 64, .data = data };
    // ED25519: HKS_SIGNATURE_MIN_SIZE = 64
    ASSERT_EQ(HksCheckSignature(HKS_CMD_ID_SIGN, HKS_ALG_ED25519, 0, &sigSmall), HKS_ERROR_BUFFER_TOO_SMALL);
    ASSERT_EQ(HksCheckSignature(HKS_CMD_ID_SIGN, HKS_ALG_ED25519, 0, &sigExact), HKS_SUCCESS);
    ASSERT_EQ(HksCheckSignature(HKS_CMD_ID_VERIFY, HKS_ALG_ED25519, 0, &sigSmall), HKS_ERROR_INVALID_SIGNATURE_SIZE);
    ASSERT_EQ(HksCheckSignature(HKS_CMD_ID_VERIFY, HKS_ALG_ED25519, 0, &sigExact), HKS_SUCCESS);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest038
 * @tc.desc: tdd HksCheckCipherData AES block cipher size check
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest038, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest038");
    uint8_t in[64] = { 0 };
    uint8_t out[64] = { 0 };
    struct HksBlob inData = { .size = 17, .data = in };
    struct HksBlob inlineData = { .size = 16, .data = in };
    struct HksBlob outSmall = { .size = 15, .data = out };
    struct HksBlob outOk = { .size = 64, .data = out };

    struct ParamsValues values = {};
    values.mode = { true, HKS_MODE_CBC };
    values.padding = { true, HKS_PADDING_NONE };
    // ENCRYPT + NONE + inSize(17) not multiple of 16
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_ENCRYPT, HKS_ALG_AES, &values, &inData, &outOk),
        HKS_ERROR_INVALID_ARGUMENT);
    // DECRYPT + NONE + inSize(17) not multiple of 16
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_DECRYPT, HKS_ALG_AES, &values, &inData, &outOk),
        HKS_ERROR_INVALID_ARGUMENT);
    // ENCRYPT + PKCS7 + outData too small
    values.padding.value = HKS_PADDING_PKCS7;
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_ENCRYPT, HKS_ALG_AES, &values, &inlineData, &outSmall),
        HKS_ERROR_BUFFER_TOO_SMALL);
    // DECRYPT + outData too small
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_DECRYPT, HKS_ALG_AES, &values, &inlineData, &outSmall),
        HKS_ERROR_BUFFER_TOO_SMALL);
    // ENCRYPT success path (NONE, inSize multiple of 16, outData large enough)
    values.padding.value = HKS_PADDING_NONE;
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_ENCRYPT, HKS_ALG_AES, &values, &inlineData, &outOk), HKS_SUCCESS);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest039
 * @tc.desc: tdd HksCheckCipherData DES/3DES/SM4 block cipher dispatch
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest039, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest039");
    uint8_t in[32] = { 0 };
    uint8_t out[32] = { 0 };
    struct HksBlob inData = { .size = 16, .data = in };
    struct HksBlob outData = { .size = 32, .data = out };
    struct ParamsValues values = {};
    values.mode = { true, HKS_MODE_CBC };
    values.padding = { true, HKS_PADDING_PKCS7 };
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_ENCRYPT, HKS_ALG_DES, &values, &inData, &outData), HKS_SUCCESS);
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_ENCRYPT, HKS_ALG_3DES, &values, &inData, &outData), HKS_SUCCESS);
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_ENCRYPT, HKS_ALG_SM4, &values, &inData, &outData), HKS_SUCCESS);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest040
 * @tc.desc: tdd HksCheckCipherData RSA NONE no-pad size check
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest040, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest040");
    uint8_t in[300] = { 0 };
    uint8_t out[300] = { 0 };
    struct ParamsValues values = {};
    values.keyLen = { true, HKS_RSA_KEY_SIZE_2048 };
    values.padding = { true, HKS_PADDING_NONE };
    // keySize = 2048 / 8 = 256
    struct HksBlob inBig = { .size = 257, .data = in };
    struct HksBlob inOk = { .size = 256, .data = in };
    struct HksBlob outOk = { .size = 300, .data = out };
    struct HksBlob outSmall = { .size = 255, .data = out };
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_ENCRYPT, HKS_ALG_RSA, &values, &inBig, &outOk),
        HKS_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_ENCRYPT, HKS_ALG_RSA, &values, &inOk, &outSmall),
        HKS_ERROR_BUFFER_TOO_SMALL);
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_ENCRYPT, HKS_ALG_RSA, &values, &inOk, &outOk), HKS_SUCCESS);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest041
 * @tc.desc: tdd HksCheckCipherData RSA OAEP size check
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest041, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest041");
    uint8_t in[300] = { 0 };
    uint8_t out[300] = { 0 };
    struct ParamsValues values = {};
    values.keyLen = { true, HKS_RSA_KEY_SIZE_2048 };
    values.padding = { true, HKS_PADDING_OAEP };
    values.digest = { true, HKS_DIGEST_SHA256 };
    // keySize=256, digestLen=32, size=256-66=190
    struct HksBlob in191 = { .size = 191, .data = in };
    struct HksBlob in100 = { .size = 100, .data = in };
    struct HksBlob in257 = { .size = 257, .data = in };
    struct HksBlob in256 = { .size = 256, .data = in };
    struct HksBlob out300 = { .size = 300, .data = out };
    struct HksBlob out255 = { .size = 255, .data = out };
    struct HksBlob out189 = { .size = 189, .data = out };
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_ENCRYPT, HKS_ALG_RSA, &values, &in191, &out300),
        HKS_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_ENCRYPT, HKS_ALG_RSA, &values, &in100, &out255),
        HKS_ERROR_BUFFER_TOO_SMALL);
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_DECRYPT, HKS_ALG_RSA, &values, &in257, &out300),
        HKS_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_DECRYPT, HKS_ALG_RSA, &values, &in256, &out189),
        HKS_ERROR_BUFFER_TOO_SMALL);
    // small key (512/8=64 <= 2*32+2=66) → INVALID_KEY_FILE
    struct ParamsValues smallKey = {};
    smallKey.keyLen = { true, HKS_RSA_KEY_SIZE_512 };
    smallKey.padding = { true, HKS_PADDING_OAEP };
    smallKey.digest = { true, HKS_DIGEST_SHA256 };
    struct HksBlob inSmall = { .size = 10, .data = in };
    ASSERT_EQ(HksCheckCipherData(HKS_CMD_ID_ENCRYPT, HKS_ALG_RSA, &smallKey, &inSmall, &out300),
        HKS_ERROR_INVALID_KEY_FILE);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest042
 * @tc.desc: tdd HksCheckCipherMutableParams AES CTR/ECB/GCM padding
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest042, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest042");
    struct ParamsValues values = {};
    values.purpose = { true, HKS_KEY_PURPOSE_ENCRYPT };
    values.mode = { true, HKS_MODE_CTR };
    values.padding = { true, HKS_PADDING_NONE };
    ASSERT_EQ(HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_AES, &values), HKS_SUCCESS);
    values.mode.value = HKS_MODE_ECB;
    ASSERT_EQ(HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_AES, &values), HKS_SUCCESS);
    values.mode.value = HKS_MODE_GCM;
    ASSERT_EQ(HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_AES, &values), HKS_SUCCESS);
    values.mode.value = HKS_MODE_CBC;
    values.padding.value = HKS_PADDING_PSS;
    ASSERT_EQ(HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_AES, &values), HKS_ERROR_INVALID_PADDING);
    values.mode.isAbsent = true;
    ASSERT_EQ(HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_AES, &values), HKS_SUCCESS);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest043
 * @tc.desc: tdd HksCheckCipherMutableParams SM4 padding modes
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest043, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest043");
    struct ParamsValues values = {};
    values.purpose = { true, HKS_KEY_PURPOSE_ENCRYPT };
    values.mode = { true, HKS_MODE_CTR };
    values.padding = { true, HKS_PADDING_NONE };
    ASSERT_EQ(HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_SM4, &values), HKS_SUCCESS);
    values.mode.value = HKS_MODE_ECB;
    ASSERT_EQ(HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_SM4, &values), HKS_SUCCESS);
    values.mode.value = HKS_MODE_OFB;
    ASSERT_EQ(HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_SM4, &values), HKS_SUCCESS);
    values.mode.value = HKS_MODE_CBC;
    values.padding.value = HKS_PADDING_PSS;
    ASSERT_EQ(HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_SM4, &values), HKS_ERROR_INVALID_PADDING);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest044
 * @tc.desc: tdd HksCheckCipherMutableParams DES/3DES padding
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest044, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest044");
    struct ParamsValues values = {};
    values.purpose = { true, HKS_KEY_PURPOSE_ENCRYPT };
    values.mode = { true, HKS_MODE_CBC };
    values.padding = { true, HKS_PADDING_NONE };
    ASSERT_EQ(HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_DES, &values), HKS_SUCCESS);
    ASSERT_EQ(HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_3DES, &values), HKS_SUCCESS);
    values.mode.value = HKS_MODE_ECB;
    ASSERT_EQ(HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_DES, &values), HKS_SUCCESS);
    ASSERT_EQ(HksCheckCipherMutableParams(HKS_CMD_ID_ENCRYPT, HKS_ALG_3DES, &values), HKS_SUCCESS);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest045
 * @tc.desc: tdd HksCheckSignVerifyMutableParams RSA padding
 * @tc.type: FUNC
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest045, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest045");
    struct ParamsValues values = {};
    values.purpose = { true, HKS_KEY_PURPOSE_SIGN };
    values.padding = { true, HKS_PADDING_PSS };
    ASSERT_EQ(HksCheckSignVerifyMutableParams(HKS_CMD_ID_SIGN, HKS_ALG_RSA, &values), HKS_SUCCESS);
    values.padding.value = HKS_PADDING_PKCS7;
    ASSERT_EQ(HksCheckSignVerifyMutableParams(HKS_CMD_ID_SIGN, HKS_ALG_RSA, &values),
        HKS_ERROR_INVALID_PADDING);
    ASSERT_EQ(HksCheckSignVerifyMutableParams(HKS_CMD_ID_SIGN, HKS_ALG_ECC, &values), HKS_SUCCESS);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest046
 * @tc.desc: tdd HksCheckCipherMaterialParams DES CBC 无 IV, expect HKS_ERROR_CHECK_GET_IV_FAIL
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest046, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest046");
    struct ParamsValues values = {};
    values.mode = { true, HKS_MODE_CBC };
    struct HksParamSet *paramSet = nullptr;
    ASSERT_EQ(HksInitParamSet(&paramSet), HKS_SUCCESS);
    ASSERT_EQ(HksBuildParamSet(&paramSet), HKS_SUCCESS);
    ASSERT_EQ(HksCheckCipherMaterialParams(HKS_ALG_DES, &values, paramSet), HKS_ERROR_CHECK_GET_IV_FAIL);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest047
 * @tc.desc: tdd HksCheckCipherMaterialParams DES CBC IV 尺寸错, expect HKS_ERROR_INVALID_IV
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest047, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest047");
    struct ParamsValues values = {};
    values.mode = { true, HKS_MODE_CBC };
    struct HksParamSet *paramSet = nullptr;
    ASSERT_EQ(HksInitParamSet(&paramSet), HKS_SUCCESS);
    uint8_t iv[8] = { 0 };
    struct HksBlob ivBlob = { .size = sizeof(iv), .data = iv };
    struct HksParam ivParam = { .tag = HKS_TAG_IV, .blob = ivBlob };
    ASSERT_EQ(HksAddParams(paramSet, &ivParam, 1), HKS_SUCCESS);
    ASSERT_EQ(HksBuildParamSet(&paramSet), HKS_SUCCESS);
    ASSERT_EQ(HksCheckCipherMaterialParams(HKS_ALG_DES, &values, paramSet), HKS_ERROR_INVALID_IV);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest048
 * @tc.desc: tdd HksCheckCipherMaterialParams 3DES CBC 无 IV, expect HKS_ERROR_CHECK_GET_IV_FAIL
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest048, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest048");
    struct ParamsValues values = {};
    values.mode = { true, HKS_MODE_CBC };
    struct HksParamSet *paramSet = nullptr;
    ASSERT_EQ(HksInitParamSet(&paramSet), HKS_SUCCESS);
    ASSERT_EQ(HksBuildParamSet(&paramSet), HKS_SUCCESS);
    ASSERT_EQ(HksCheckCipherMaterialParams(HKS_ALG_3DES, &values, paramSet), HKS_ERROR_CHECK_GET_IV_FAIL);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksBaseCheckTest.HksBaseCheckTest049
 * @tc.desc: tdd CheckImportMutableParams ML_KEM 非 WRAP, expect HKS_ERROR_INVALID_PURPOSE
 */
HWTEST_F(HksBaseCheckTest, HksBaseCheckTest049, TestSize.Level0)
{
    HKS_LOG_I("enter HksBaseCheckTest049");
    struct ParamsValues values = {};
    values.purpose = { true, HKS_KEY_PURPOSE_VERIFY };
    ASSERT_EQ(CheckImportMutableParams(HKS_ALG_ML_KEM, &values), HKS_ERROR_INVALID_PURPOSE);
    values.purpose.value = HKS_KEY_PURPOSE_WRAP;
    ASSERT_EQ(CheckImportMutableParams(HKS_ALG_ML_KEM, &values), HKS_SUCCESS);
}
}
