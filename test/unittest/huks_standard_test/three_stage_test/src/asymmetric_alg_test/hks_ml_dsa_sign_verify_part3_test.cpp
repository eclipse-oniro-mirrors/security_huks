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

#include "hks_ml_dsa_sign_verify_test_common.h"
#include "hks_common_check.h"
#include "hks_test_adapt_for_de.h"
#include "hks_api.h"
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <gtest/gtest.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::MlDsaPqcMode {
class HksMlDsaSignVerifyPart3Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksMlDsaSignVerifyPart3Test::SetUpTestCase(void)
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksMlDsaSignVerifyPart3Test::TearDownTestCase(void)
{
}

void HksMlDsaSignVerifyPart3Test::SetUp()
{
}

void HksMlDsaSignVerifyPart3Test::TearDown()
{
    std::system("find /data/service/el1/public/huks_service -user root -delete");
}

static uint8_t g_mlDsaContext[] = "ml-dsa-context";
static uint8_t g_mlDsaMu[ML_DSA_MU_SIZE + 1] = { 0 }; /* one spare byte for the oversized mu case */
static uint8_t g_mlDsaPreHashData[HKS_DIGEST_SHA512_LEN] = { 0 };

static void InitPreHashData(void)
{
    for (uint32_t i = 0; i < sizeof(g_mlDsaPreHashData); i++) {
        g_mlDsaPreHashData[i] = (uint8_t)i;
    }
}

static void InitMuData(void)
{
    for (uint32_t i = 0; i < ML_DSA_MU_SIZE; i++) {
        g_mlDsaMu[i] = (uint8_t)i;
    }
}

static struct HksParam g_genParamsTest001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PURE
    }
};
static struct HksParam g_signParamsTest001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_CONTEXT,
        .blob = { .size = sizeof(g_mlDsaContext) - 1, .data = g_mlDsaContext }
    }
};
static struct HksParam g_verifyParamsTest001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA,
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_CONTEXT,
        .blob = { .size = sizeof(g_mlDsaContext) - 1, .data = g_mlDsaContext }
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test001
 * @tc.desc: alg-MlDsa, pur-sign/verify, secId-44, pure mode with context
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test001, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test001";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest001, sizeof(g_genParamsTest001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest001, sizeof(g_signParamsTest001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest001, sizeof(g_verifyParamsTest001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "pure sign failed.";

    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "pure verify failed.";

    ret = HksDeleteKeyForDe(&keyAlias, verifyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

static struct HksParam g_genParamsTest002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }
};
static struct HksParam g_signParamsTest002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_CONTEXT,
        .blob = { .size = sizeof(g_mlDsaContext) - 1, .data = g_mlDsaContext }
    }
};
static struct HksParam g_verifyParamsTest002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA,
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_CONTEXT,
        .blob = { .size = sizeof(g_mlDsaContext) - 1, .data = g_mlDsaContext }
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test002
 * @tc.desc: alg-MlDsa, pur-sign/verify, secId-44, preHash mode with SHA256 digest
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test002, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test002";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest002, sizeof(g_genParamsTest002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest002, sizeof(g_signParamsTest002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest002, sizeof(g_verifyParamsTest002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    InitPreHashData();
    struct HksBlob digest = { HKS_DIGEST_SHA256_LEN, g_mlDsaPreHashData };

    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &digest, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "prehash sign failed.";

    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &digest, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "prehash verify failed.";

    ret = HksDeleteKeyForDe(&keyAlias, verifyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

static struct HksParam g_genParamsTest003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_65
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }
};
static struct HksParam g_signParamsTest003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_65
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }
};
static struct HksParam g_verifyParamsTest003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA,
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_65
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test003
 * @tc.desc: alg-MlDsa, pur-sign/verify, secId-65, preHash mode with SHA384 digest and no context
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test003, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test003";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest003, sizeof(g_genParamsTest003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest003, sizeof(g_signParamsTest003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest003, sizeof(g_verifyParamsTest003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    InitPreHashData();
    struct HksBlob digest = { HKS_DIGEST_SHA384_LEN, g_mlDsaPreHashData };

    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &digest, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "prehash sign failed.";

    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &digest, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "prehash verify failed.";

    ret = HksDeleteKeyForDe(&keyAlias, verifyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

static struct HksParam g_genParamsTest004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_87
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }
};
static struct HksParam g_signParamsTest004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_87
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag = HKS_TAG_CONTEXT,
        .blob = { .size = sizeof(g_mlDsaContext) - 1, .data = g_mlDsaContext }
    }
};
static struct HksParam g_verifyParamsTest004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA,
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_87
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag = HKS_TAG_CONTEXT,
        .blob = { .size = sizeof(g_mlDsaContext) - 1, .data = g_mlDsaContext }
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test004
 * @tc.desc: alg-MlDsa, pur-sign/verify, secId-87, preHash mode with SHA512 digest
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test004, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test004";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest004, sizeof(g_genParamsTest004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest004, sizeof(g_signParamsTest004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest004, sizeof(g_verifyParamsTest004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    InitPreHashData();
    struct HksBlob digest = { HKS_DIGEST_SHA512_LEN, g_mlDsaPreHashData };

    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &digest, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "prehash sign failed.";

    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &digest, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "prehash verify failed.";

    ret = HksDeleteKeyForDe(&keyAlias, verifyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

static struct HksParam g_genParamsTest005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }
};
static struct HksParam g_signParamsTest005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHAKE128
    }, {
        .tag = HKS_TAG_CONTEXT,
        .blob = { .size = sizeof(g_mlDsaContext) - 1, .data = g_mlDsaContext }
    }
};
static struct HksParam g_verifyParamsTest005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA,
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHAKE128
    }, {
        .tag = HKS_TAG_CONTEXT,
        .blob = { .size = sizeof(g_mlDsaContext) - 1, .data = g_mlDsaContext }
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test005
 * @tc.desc: alg-MlDsa, pur-sign/verify, secId-44, preHash mode with SHAKE128 digest
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test005, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test005";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest005, sizeof(g_genParamsTest005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest005, sizeof(g_signParamsTest005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest005, sizeof(g_verifyParamsTest005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    InitPreHashData();
    struct HksBlob digest = { HKS_DIGEST_SHAKE128_LEN, g_mlDsaPreHashData };

    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &digest, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "prehash sign failed.";

    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &digest, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "prehash verify failed.";

    ret = HksDeleteKeyForDe(&keyAlias, verifyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

static struct HksParam g_genParamsTest006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_65
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }
};
static struct HksParam g_signParamsTest006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_65
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHAKE256
    }
};
static struct HksParam g_verifyParamsTest006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA,
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_65
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHAKE256
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test006
 * @tc.desc: alg-MlDsa, pur-sign/verify, secId-65, preHash mode with SHAKE256 digest
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test006, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test006";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest006, sizeof(g_genParamsTest006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest006, sizeof(g_signParamsTest006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest006, sizeof(g_verifyParamsTest006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    InitPreHashData();
    struct HksBlob digest = { HKS_DIGEST_SHAKE256_LEN, g_mlDsaPreHashData };

    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &digest, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "prehash sign failed.";

    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &digest, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "prehash verify failed.";

    ret = HksDeleteKeyForDe(&keyAlias, verifyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

static struct HksParam g_genParamsTest007[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_EXTERNAL_MU
    }
};
static struct HksParam g_signParamsTest007[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_EXTERNAL_MU
    }
};
static struct HksParam g_verifyParamsTest007[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA,
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_EXTERNAL_MU
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test007
 * @tc.desc: alg-MlDsa, pur-sign/verify, secId-44, external mu mode
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test007, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test007";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest007, sizeof(g_genParamsTest007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest007, sizeof(g_signParamsTest007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest007, sizeof(g_verifyParamsTest007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    InitMuData();
    struct HksBlob mu = { ML_DSA_MU_SIZE, g_mlDsaMu };

    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &mu, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "external mu sign failed.";

    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &mu, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "external mu verify failed.";

    /* a different mu must not verify */
    g_mlDsaMu[0] ^= 0xFF;
    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &mu, &outData);
    EXPECT_NE(ret, HKS_SUCCESS) << "external mu verify should fail with a modified mu.";
    g_mlDsaMu[0] ^= 0xFF;

    ret = HksDeleteKeyForDe(&keyAlias, verifyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

static struct HksParam g_genParamsTest008[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }
};
static struct HksParam g_signParamsTest008[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test008
 * @tc.desc: alg-MlDsa, key is bound to preHash mode, signing without the mode tag must be rejected
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test008, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test008";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest008, sizeof(g_genParamsTest008) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest008, sizeof(g_signParamsTest008) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    InitPreHashData();
    struct HksBlob digest = { HKS_DIGEST_SHA256_LEN, g_mlDsaPreHashData };
    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &digest, &outData);
    EXPECT_NE(ret, HKS_SUCCESS) << "signing without the mode tag of the key should be rejected.";

    HksDeleteKeyForDe(&keyAlias, genParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

static struct HksParam g_genParamsTest009[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_EXTERNAL_MU
    }
};
static struct HksParam g_signParamsTest009[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test009
 * @tc.desc: alg-MlDsa, key is bound to external mu mode, signing with another mode must be rejected
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test009, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test009";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest009, sizeof(g_genParamsTest009) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest009, sizeof(g_signParamsTest009) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    InitPreHashData();
    struct HksBlob digest = { HKS_DIGEST_SHA256_LEN, g_mlDsaPreHashData };
    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &digest, &outData);
    EXPECT_NE(ret, HKS_SUCCESS) << "the mode must match the mode stored in the key.";

    HksDeleteKeyForDe(&keyAlias, genParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

static struct HksParam g_genParamsTest010[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }
};
/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test010
 * @tc.desc: alg-MlDsa, a key generated without a mode is not bound, preHash mode must be allowed
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test010, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test010";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest010, sizeof(g_genParamsTest010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest002, sizeof(g_signParamsTest002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest002, sizeof(g_verifyParamsTest002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    InitPreHashData();
    struct HksBlob digest = { HKS_DIGEST_SHA256_LEN, g_mlDsaPreHashData };
    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &digest, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "an unbound key must be allowed to sign in prehash mode.";
    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &digest, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "an unbound key must be allowed to verify in prehash mode.";

    HksDeleteKeyForDe(&keyAlias, verifyParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

static struct HksParam g_genParamsTest011[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }
};
static struct HksParam g_signParamsTest011[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test011
 * @tc.desc: alg-MlDsa, preHash mode without HKS_TAG_DIGEST must be rejected
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test011, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test011";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest011, sizeof(g_genParamsTest011) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest011, sizeof(g_signParamsTest011) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    InitPreHashData();
    struct HksBlob digest = { HKS_DIGEST_SHA256_LEN, g_mlDsaPreHashData };
    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &digest, &outData);
    EXPECT_NE(ret, HKS_SUCCESS) << "prehash without digest should be rejected.";

    HksDeleteKeyForDe(&keyAlias, genParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

static struct HksParam g_genParamsTest012[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }
};
static struct HksParam g_signParamsTest012[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test012
 * @tc.desc: alg-MlDsa, preHash mode with a digest of the wrong length must be rejected
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test012, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test012";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest012, sizeof(g_genParamsTest012) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest012, sizeof(g_signParamsTest012) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    InitPreHashData();
    struct HksBlob shortDigest = { HKS_DIGEST_SHA256_LEN - 1, g_mlDsaPreHashData };
    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &shortDigest, &outData);
    EXPECT_NE(ret, HKS_SUCCESS) << "a wrong digest length should be rejected.";

    HksDeleteKeyForDe(&keyAlias, genParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

static struct HksParam g_genParamsTest013[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }
};
static struct HksParam g_signParamsTest013[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PREHASH
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SM3
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test013
 * @tc.desc: alg-MlDsa, preHash mode with an unsupported digest must be rejected
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test013, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test013";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest013, sizeof(g_genParamsTest013) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest013, sizeof(g_signParamsTest013) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    InitPreHashData();
    struct HksBlob digest = { HKS_DIGEST_SM3_LEN, g_mlDsaPreHashData };
    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &digest, &outData);
    EXPECT_NE(ret, HKS_SUCCESS) << "prehash with SM3 should be rejected.";

    HksDeleteKeyForDe(&keyAlias, genParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

static struct HksParam g_genParamsTest014[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_EXTERNAL_MU
    }
};
static struct HksParam g_signParamsTest014[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_EXTERNAL_MU
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test014
 * @tc.desc: alg-MlDsa, external mu mode with a wrong mu length must be rejected
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test014, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test014";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest014, sizeof(g_genParamsTest014) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest014, sizeof(g_signParamsTest014) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    InitMuData();
    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };

    const uint32_t invalidSizes[] = { ML_DSA_MU_SIZE - 1, ML_DSA_MU_SIZE + 1 };
    for (uint32_t size : invalidSizes) {
        struct HksBlob mu = { size, g_mlDsaMu };
        ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &mu, &outData);
        EXPECT_NE(ret, HKS_SUCCESS) << "an invalid mu length should be rejected.";
    }

    HksDeleteKeyForDe(&keyAlias, genParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

static struct HksParam g_genParamsTest015[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = 99
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test015
 * @tc.desc: alg-MlDsa, an invalid HKS_TAG_PQC_SIG_MODE value must be rejected at key generation
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test015, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test015";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest015, sizeof(g_genParamsTest015) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS) << "an invalid pqc sig mode should be rejected.";

    HksDeleteKeyForDe(&keyAlias, genParamSet);
    HksFreeParamSet(&genParamSet);
}
static struct HksParam g_genParamsTest016[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PURE
    }
};
static struct HksParam g_signParamsTest016[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PURE
    }, {
        .tag = HKS_TAG_CONTEXT,
        .blob = { .size = sizeof(g_mlDsaContext) - 1, .data = g_mlDsaContext }
    }
};
static struct HksParam g_verifyParamsTest016[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA,
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PURE
    }, {
        .tag = HKS_TAG_CONTEXT,
        .blob = { .size = sizeof(g_mlDsaContext) - 1, .data = g_mlDsaContext }
    }
};
static struct HksParam g_importPubParamsTest016[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA,
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PURE
    }, {
        .tag = HKS_TAG_IMPORT_KEY_TYPE,
        .uint32Param = HKS_KEY_TYPE_PUBLIC_KEY
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test016
 * @tc.desc: alg-MlDsa, export the generated public key as X.509 DER and import it back for verify
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test016, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test016";
    const char *pubAliasString = "HksMlDsaSignVerifyPart3Test016Pub";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksBlob pubAlias = { strlen(pubAliasString), (uint8_t *)pubAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    struct HksParamSet *importParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest016, sizeof(g_genParamsTest016) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = InitParamSet(&signParamSet, g_signParamsTest016, sizeof(g_signParamsTest016) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest016, sizeof(g_verifyParamsTest016) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = InitParamSet(&importParamSet, g_importPubParamsTest016,
        sizeof(g_importPubParamsTest016) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob publicKey = { ML_DSA_MAX_KEY_SIZE, (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(publicKey.data, nullptr);
    ret = HksExportPublicKeyForDe(&keyAlias, nullptr, &publicKey);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_NE(publicKey.size, 0u);
    std::ofstream derFile("/data/local/tmp/mldsa_exported_pub.der", std::ios::binary);
    if (derFile.is_open()) {
        derFile.write(reinterpret_cast<const char *>(publicKey.data), publicKey.size);
        derFile.close();
    }

    ret = HksImportKeyForDe(&pubAlias, importParamSet, &publicKey);
    EXPECT_EQ(ret, HKS_SUCCESS) << "import exported X.509 DER public key failed.";

    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "sign failed.";
    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "verify with the original key failed.";

    struct HksBlob pubOut = { ML_DSA_MAX_KEY_SIZE, (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(pubOut.data, nullptr);
    ret = HksExportPublicKeyForDe(&pubAlias, nullptr, &pubOut);
    EXPECT_EQ(ret, HKS_SUCCESS) << "export the imported public key failed.";
    EXPECT_EQ(pubOut.size, publicKey.size) << "imported public key size mismatch.";
    if ((pubOut.size == publicKey.size) && (memcmp(pubOut.data, publicKey.data, pubOut.size) != 0)) {
        EXPECT_EQ(0, 1) << "imported public key content mismatch.";
    }
    HKS_FREE(pubOut.data);

    ret = HksMlDsaTestSignVerify(&pubAlias, verifyParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "verify with the imported public key failed.";

    HksDeleteKeyForDe(&keyAlias, verifyParamSet);
    HksDeleteKeyForDe(&pubAlias, verifyParamSet);
    HKS_FREE(publicKey.data);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
    HksFreeParamSet(&importParamSet);
}

static struct HksParam g_genParamsTest017[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }, {
        .tag = HKS_TAG_PQC_SIG_MODE,
        .uint32Param = HKS_PQC_SIG_MODE_PURE
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test017
 * @tc.desc: alg-MlDsa, an unbound key can sign and verify in external mu mode
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test017, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test017";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest010, sizeof(g_genParamsTest010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest007, sizeof(g_signParamsTest007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest007, sizeof(g_verifyParamsTest007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    InitMuData();
    struct HksBlob mu = { ML_DSA_MU_SIZE, g_mlDsaMu };
    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &mu, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "an unbound key must be allowed to sign in external mu mode.";
    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &mu, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "an unbound key must be allowed to verify in external mu mode.";

    HksDeleteKeyForDe(&keyAlias, verifyParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test018
 * @tc.desc: alg-MlDsa, an explicitly PURE-bound key must reject preHash mode
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test018, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test018";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest017, sizeof(g_genParamsTest017) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest002, sizeof(g_signParamsTest002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    InitPreHashData();
    struct HksBlob digest = { HKS_DIGEST_SHA256_LEN, g_mlDsaPreHashData };
    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &digest, &outData);
    EXPECT_NE(ret, HKS_SUCCESS) << "a key explicitly bound to pure mode must reject prehash mode.";

    HksDeleteKeyForDe(&keyAlias, genParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test019
 * @tc.desc: alg-MlDsa, a PURE-bound key can be used without the mode tag (defaults to pure)
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test019, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test019";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest017, sizeof(g_genParamsTest017) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest001, sizeof(g_signParamsTest001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest001, sizeof(g_verifyParamsTest001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "a PURE-bound key must default to pure mode.";
    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "verify without the mode tag failed.";

    HksDeleteKeyForDe(&keyAlias, verifyParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksMlDsaSignVerifyPart3Test.HksMlDsaSignVerifyPart3Test020
 * @tc.desc: alg-MlDsa, an unbound key can sign and verify in pure mode without the mode tag
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test020, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart3Test020";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest010, sizeof(g_genParamsTest010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest001, sizeof(g_signParamsTest001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest001, sizeof(g_verifyParamsTest001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    uint8_t outDataS[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "an unbound key must default to pure mode.";
    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "pure verify without the mode tag failed.";

    HksDeleteKeyForDe(&keyAlias, verifyParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/* ------------------------------------------------------------------------- */
/* Algorithm combination matrix and key/session API coverage (021 ~ 042).     */
/* ------------------------------------------------------------------------- */

static uint8_t g_mlDsaDigestData[HKS_DIGEST_SHA512_LEN] = { 0 };

static void InitDigestData(void)
{
    for (uint32_t i = 0; i < sizeof(g_mlDsaDigestData); i++) {
        g_mlDsaDigestData[i] = (uint8_t)i;
    }
}

static int32_t BuildMlDsaParamSet(struct HksParamSet **paramSet, uint32_t keySize, uint32_t purpose,
    bool withMode, uint32_t mode, bool withDigest, uint32_t digest, const uint8_t *ctx, uint32_t ctxLen)
{
    struct HksParam params[8];
    (void)memset_s(params, sizeof(params), 0, sizeof(params));
    uint32_t cnt = 0;
    params[cnt].tag = HKS_TAG_ALGORITHM;
    params[cnt++].uint32Param = HKS_ALG_ML_DSA;
    params[cnt].tag = HKS_TAG_PURPOSE;
    params[cnt++].uint32Param = purpose;
    params[cnt].tag = HKS_TAG_KEY_SIZE;
    params[cnt++].uint32Param = keySize;
    if (withMode) {
        params[cnt].tag = HKS_TAG_PQC_SIG_MODE;
        params[cnt++].uint32Param = mode;
    }
    if (withDigest) {
        params[cnt].tag = HKS_TAG_DIGEST;
        params[cnt++].uint32Param = digest;
    }
    if (ctx != nullptr) {
        params[cnt].tag = HKS_TAG_CONTEXT;
        params[cnt].blob.size = ctxLen;
        params[cnt].blob.data = const_cast<uint8_t *>(ctx);
        cnt++;
    }
    return InitParamSet(paramSet, params, cnt);
}

static void RunMlDsaRoundTrip(const char *aliasStr, uint32_t keySize, uint32_t mode,
    uint32_t digest, const uint8_t *data, uint32_t dataLen, bool withCtx)
{
    struct HksBlob alias = { (uint32_t)strlen(aliasStr), (uint8_t *)aliasStr };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    const uint8_t *ctx = withCtx ? g_mlDsaContext : nullptr;
    uint32_t ctxLen = withCtx ? (uint32_t)(sizeof(g_mlDsaContext) - 1) : 0;

    ASSERT_EQ(BuildMlDsaParamSet(&genParamSet, keySize, HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
        true, mode, false, 0, nullptr, 0), HKS_SUCCESS);
    ASSERT_EQ(BuildMlDsaParamSet(&signParamSet, keySize, HKS_KEY_PURPOSE_SIGN, true, mode,
        mode == HKS_PQC_SIG_MODE_PREHASH, digest, ctx, ctxLen), HKS_SUCCESS);
    ASSERT_EQ(BuildMlDsaParamSet(&verifyParamSet, keySize, HKS_KEY_PURPOSE_VERIFY, true, mode,
        mode == HKS_PQC_SIG_MODE_PREHASH, digest, ctx, ctxLen), HKS_SUCCESS);

    ASSERT_EQ(HksGenerateKeyForDe(&alias, genParamSet, nullptr), HKS_SUCCESS);
    struct HksBlob message = { dataLen, const_cast<uint8_t *>(data) };
    uint8_t sigBuf[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { ML_DSA_COMMON_SIZE, sigBuf };
    EXPECT_EQ(HksMlDsaTestSignVerify(&alias, signParamSet, &message, &signature), HKS_SUCCESS);
    EXPECT_EQ(HksMlDsaTestSignVerify(&alias, verifyParamSet, &message, &signature), HKS_SUCCESS);

    (void)HksDeleteKeyForDe(&alias, verifyParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test021, TestSize.Level0)
{
    RunMlDsaRoundTrip("HksMlDsaSignVerifyPart3Test021", HKS_ML_DSA_KEY_PARAM_SET_65,
        HKS_PQC_SIG_MODE_PURE, 0, inData.data, inData.size, true);
}

HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test022, TestSize.Level0)
{
    InitMuData();
    RunMlDsaRoundTrip("HksMlDsaSignVerifyPart3Test022", HKS_ML_DSA_KEY_PARAM_SET_65,
        HKS_PQC_SIG_MODE_EXTERNAL_MU, 0, g_mlDsaMu, ML_DSA_MU_SIZE, false);
}

HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test023, TestSize.Level0)
{
    RunMlDsaRoundTrip("HksMlDsaSignVerifyPart3Test023", HKS_ML_DSA_KEY_PARAM_SET_87,
        HKS_PQC_SIG_MODE_PURE, 0, inData.data, inData.size, true);
}

HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test024, TestSize.Level0)
{
    InitMuData();
    RunMlDsaRoundTrip("HksMlDsaSignVerifyPart3Test024", HKS_ML_DSA_KEY_PARAM_SET_87,
        HKS_PQC_SIG_MODE_EXTERNAL_MU, 0, g_mlDsaMu, ML_DSA_MU_SIZE, false);
}

static void RunPreHashCase(const char *aliasStr, uint32_t keySize, uint32_t digest)
{
    uint32_t digestLen = 0;
    ASSERT_EQ(HksGetDigestLen(digest, &digestLen), HKS_SUCCESS);
    InitDigestData();
    RunMlDsaRoundTrip(aliasStr, keySize, HKS_PQC_SIG_MODE_PREHASH, digest, g_mlDsaDigestData, digestLen, true);
}

HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test025, TestSize.Level0)
{
    RunPreHashCase("HksMlDsaSignVerifyPart3Test025", HKS_ML_DSA_KEY_PARAM_SET_44, HKS_DIGEST_SHA384);
}

HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test026, TestSize.Level0)
{
    RunPreHashCase("HksMlDsaSignVerifyPart3Test026", HKS_ML_DSA_KEY_PARAM_SET_44, HKS_DIGEST_SHA512);
}

HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test027, TestSize.Level0)
{
    RunPreHashCase("HksMlDsaSignVerifyPart3Test027", HKS_ML_DSA_KEY_PARAM_SET_44, HKS_DIGEST_SHAKE256);
}

HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test028, TestSize.Level0)
{
    RunPreHashCase("HksMlDsaSignVerifyPart3Test028", HKS_ML_DSA_KEY_PARAM_SET_65, HKS_DIGEST_SHA256);
}

HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test029, TestSize.Level0)
{
    RunPreHashCase("HksMlDsaSignVerifyPart3Test029", HKS_ML_DSA_KEY_PARAM_SET_65, HKS_DIGEST_SHA512);
}

HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test030, TestSize.Level0)
{
    RunPreHashCase("HksMlDsaSignVerifyPart3Test030", HKS_ML_DSA_KEY_PARAM_SET_65, HKS_DIGEST_SHAKE128);
}

HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test031, TestSize.Level0)
{
    RunPreHashCase("HksMlDsaSignVerifyPart3Test031", HKS_ML_DSA_KEY_PARAM_SET_87, HKS_DIGEST_SHA256);
}

HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test032, TestSize.Level0)
{
    RunPreHashCase("HksMlDsaSignVerifyPart3Test032", HKS_ML_DSA_KEY_PARAM_SET_87, HKS_DIGEST_SHA384);
}

HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test033, TestSize.Level0)
{
    RunPreHashCase("HksMlDsaSignVerifyPart3Test033", HKS_ML_DSA_KEY_PARAM_SET_87, HKS_DIGEST_SHAKE128);
}

HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test034, TestSize.Level0)
{
    RunPreHashCase("HksMlDsaSignVerifyPart3Test034", HKS_ML_DSA_KEY_PARAM_SET_87, HKS_DIGEST_SHAKE256);
}

/* Segmented update: the message is fed in two chunks. */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test037, TestSize.Level0)
{
    const char *aliasStr = "HksMlDsaSignVerifyPart3Test037";
    struct HksBlob alias = { (uint32_t)strlen(aliasStr), (uint8_t *)aliasStr };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    ASSERT_EQ(BuildMlDsaParamSet(&genParamSet, HKS_ML_DSA_KEY_PARAM_SET_44,
        HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY, true, HKS_PQC_SIG_MODE_PURE, false, 0, nullptr, 0),
        HKS_SUCCESS);
    ASSERT_EQ(BuildMlDsaParamSet(&signParamSet, HKS_ML_DSA_KEY_PARAM_SET_44,
        HKS_KEY_PURPOSE_SIGN, true, HKS_PQC_SIG_MODE_PURE, false, 0, g_mlDsaContext,
        (uint32_t)(sizeof(g_mlDsaContext) - 1)), HKS_SUCCESS);
    ASSERT_EQ(BuildMlDsaParamSet(&verifyParamSet, HKS_ML_DSA_KEY_PARAM_SET_44,
        HKS_KEY_PURPOSE_VERIFY, true, HKS_PQC_SIG_MODE_PURE, false, 0, g_mlDsaContext,
        (uint32_t)(sizeof(g_mlDsaContext) - 1)), HKS_SUCCESS);

    ASSERT_EQ(HksGenerateKeyForDe(&alias, genParamSet, nullptr), HKS_SUCCESS);
    uint8_t handleBuf[sizeof(uint64_t)] = { 0 };
    struct HksBlob handle = { sizeof(handleBuf), handleBuf };
    ASSERT_EQ(HksInitForDe(&alias, signParamSet, &handle, nullptr), HKS_SUCCESS);

    uint32_t half = inData.size / 2;
    struct HksBlob part1 = { half, inData.data };
    struct HksBlob part2 = { inData.size - half, inData.data + half };
    uint8_t outBuf[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob out = { ML_DSA_COMMON_SIZE, outBuf };
    EXPECT_EQ(HksUpdateForDe(&handle, signParamSet, &part1, &out), HKS_SUCCESS);
    EXPECT_EQ(HksUpdateForDe(&handle, signParamSet, &part2, &out), HKS_SUCCESS);

    uint8_t sigBuf[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { ML_DSA_COMMON_SIZE, sigBuf };
    struct HksBlob empty = { 0, nullptr };
    EXPECT_EQ(HksFinishForDe(&handle, signParamSet, &empty, &signature), HKS_SUCCESS);
    EXPECT_EQ(HksMlDsaTestSignVerify(&alias, verifyParamSet, &inData, &signature), HKS_SUCCESS);

    (void)HksDeleteKeyForDe(&alias, verifyParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/* Abort session: finish after abort must fail. */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test038, TestSize.Level0)
{
    const char *aliasStr = "HksMlDsaSignVerifyPart3Test038";
    struct HksBlob alias = { (uint32_t)strlen(aliasStr), (uint8_t *)aliasStr };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;

    ASSERT_EQ(BuildMlDsaParamSet(&genParamSet, HKS_ML_DSA_KEY_PARAM_SET_44,
        HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY, true, HKS_PQC_SIG_MODE_PURE, false, 0, nullptr, 0),
        HKS_SUCCESS);
    ASSERT_EQ(BuildMlDsaParamSet(&signParamSet, HKS_ML_DSA_KEY_PARAM_SET_44,
        HKS_KEY_PURPOSE_SIGN, true, HKS_PQC_SIG_MODE_PURE, false, 0, g_mlDsaContext,
        (uint32_t)(sizeof(g_mlDsaContext) - 1)), HKS_SUCCESS);

    ASSERT_EQ(HksGenerateKeyForDe(&alias, genParamSet, nullptr), HKS_SUCCESS);
    uint8_t handleBuf[sizeof(uint64_t)] = { 0 };
    struct HksBlob handle = { sizeof(handleBuf), handleBuf };
    ASSERT_EQ(HksInitForDe(&alias, signParamSet, &handle, nullptr), HKS_SUCCESS);
    struct HksParam abortParams[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE }
    };
    struct HksParamSet *abortParamSet = nullptr;
    ASSERT_EQ(InitParamSet(&abortParamSet, abortParams, HKS_ARRAY_SIZE(abortParams)), HKS_SUCCESS);
    EXPECT_EQ(HksAbort(&handle, abortParamSet), HKS_SUCCESS);

    uint8_t sigBuf[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { ML_DSA_COMMON_SIZE, sigBuf };
    struct HksBlob empty = { 0, nullptr };
    EXPECT_NE(HksFinishForDe(&handle, signParamSet, &empty, &signature), HKS_SUCCESS);

    (void)HksDeleteKeyForDe(&alias, signParamSet);
    HksFreeParamSet(&abortParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

/* Max context size 255 is accepted. */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test039, TestSize.Level0)
{
    uint8_t ctx[HKS_ML_DSA_MAX_CONTEXT_SIZE] = { 0 };
    (void)memset_s(ctx, sizeof(ctx), 0x5A, sizeof(ctx));
    const char *aliasStr = "HksMlDsaSignVerifyPart3Test039";
    struct HksBlob alias = { (uint32_t)strlen(aliasStr), (uint8_t *)aliasStr };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    ASSERT_EQ(BuildMlDsaParamSet(&genParamSet, HKS_ML_DSA_KEY_PARAM_SET_44,
        HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY, true, HKS_PQC_SIG_MODE_PURE, false, 0, nullptr, 0),
        HKS_SUCCESS);
    ASSERT_EQ(BuildMlDsaParamSet(&signParamSet, HKS_ML_DSA_KEY_PARAM_SET_44,
        HKS_KEY_PURPOSE_SIGN, true, HKS_PQC_SIG_MODE_PURE, false, 0, ctx, HKS_ML_DSA_MAX_CONTEXT_SIZE),
        HKS_SUCCESS);
    ASSERT_EQ(HksGenerateKeyForDe(&alias, genParamSet, nullptr), HKS_SUCCESS);
    uint8_t sigBuf[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { ML_DSA_COMMON_SIZE, sigBuf };
    EXPECT_EQ(HksMlDsaTestSignVerify(&alias, signParamSet, &inData, &signature), HKS_SUCCESS);
    (void)HksDeleteKeyForDe(&alias, signParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

/* Context larger than 255 must be rejected. */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test040, TestSize.Level0)
{
    const char *aliasStr = "HksMlDsaSignVerifyPart3Test040";
    struct HksBlob alias = { (uint32_t)strlen(aliasStr), (uint8_t *)aliasStr };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    uint8_t ctx[HKS_ML_DSA_MAX_CONTEXT_SIZE + 1] = { 0 };
    (void)memset_s(ctx, sizeof(ctx), 0x5A, sizeof(ctx));

    ASSERT_EQ(BuildMlDsaParamSet(&genParamSet, HKS_ML_DSA_KEY_PARAM_SET_44,
        HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY, true, HKS_PQC_SIG_MODE_PURE, false, 0, nullptr, 0),
        HKS_SUCCESS);
    ASSERT_EQ(BuildMlDsaParamSet(&signParamSet, HKS_ML_DSA_KEY_PARAM_SET_44,
        HKS_KEY_PURPOSE_SIGN, true, HKS_PQC_SIG_MODE_PURE, false, 0, ctx, sizeof(ctx)), HKS_SUCCESS);
    ASSERT_EQ(HksGenerateKeyForDe(&alias, genParamSet, nullptr), HKS_SUCCESS);
    uint8_t sigBuf[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { ML_DSA_COMMON_SIZE, sigBuf };
    EXPECT_NE(HksMlDsaTestSignVerify(&alias, signParamSet, &inData, &signature), HKS_SUCCESS);

    (void)HksDeleteKeyForDe(&alias, signParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

/* An unsupported ML-DSA parameter set must be rejected at key generation. */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test041, TestSize.Level0)
{
    const char *aliasStr = "HksMlDsaSignVerifyPart3Test041";
    struct HksBlob alias = { (uint32_t)strlen(aliasStr), (uint8_t *)aliasStr };
    struct HksParamSet *genParamSet = nullptr;
    ASSERT_EQ(BuildMlDsaParamSet(&genParamSet, 99,
        HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY, true, HKS_PQC_SIG_MODE_PURE, false, 0, nullptr, 0),
        HKS_SUCCESS);
    EXPECT_NE(HksGenerateKeyForDe(&alias, genParamSet, nullptr), HKS_SUCCESS);
    HksFreeParamSet(&genParamSet);
}

/* The sign operation must use the SIGN purpose. */
HWTEST_F(HksMlDsaSignVerifyPart3Test, HksMlDsaSignVerifyPart3Test042, TestSize.Level0)
{
    const char *aliasStr = "HksMlDsaSignVerifyPart3Test042";
    struct HksBlob alias = { (uint32_t)strlen(aliasStr), (uint8_t *)aliasStr };
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    ASSERT_EQ(BuildMlDsaParamSet(&genParamSet, HKS_ML_DSA_KEY_PARAM_SET_44,
        HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY, true, HKS_PQC_SIG_MODE_PURE, false, 0, nullptr, 0),
        HKS_SUCCESS);
    ASSERT_EQ(BuildMlDsaParamSet(&signParamSet, HKS_ML_DSA_KEY_PARAM_SET_44,
        HKS_KEY_PURPOSE_VERIFY, true, HKS_PQC_SIG_MODE_PURE, false, 0, nullptr, 0), HKS_SUCCESS);
    ASSERT_EQ(HksGenerateKeyForDe(&alias, genParamSet, nullptr), HKS_SUCCESS);
    uint8_t sigBuf[ML_DSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { ML_DSA_COMMON_SIZE, sigBuf };
    EXPECT_NE(HksMlDsaTestSignVerify(&alias, signParamSet, &inData, &signature), HKS_SUCCESS);
    (void)HksDeleteKeyForDe(&alias, genParamSet);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}
} // namespace Unittest::MlDsaPqcMode