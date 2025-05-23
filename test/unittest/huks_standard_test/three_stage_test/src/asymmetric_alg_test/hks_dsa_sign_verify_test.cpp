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

#include "hks_dsa_sign_verify_test.h"
#include "hks_test_adapt_for_de.h"

#include <gtest/gtest.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::DsaSignVerify {
class HksDsaSignVerifyTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksDsaSignVerifyTest::SetUpTestCase(void)
{
}

void HksDsaSignVerifyTest::TearDownTestCase(void)
{
}

void HksDsaSignVerifyTest::SetUp()
{
}

void HksDsaSignVerifyTest::TearDown()
{
}

static struct HksParam g_genParamsTest001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA1
    }
};
static struct HksParam g_signParamsTest001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA1
    }
};
static struct HksParam g_verifyParamsTest001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA1
    }
};

static struct HksParam g_genParamsTest002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA224
    }
};
static struct HksParam g_signParamsTest002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA224
    }
};
static struct HksParam g_verifyParamsTest002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA224
    }
};
static struct HksParam g_genParamsTest003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};
static struct HksParam g_signParamsTest003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};
static struct HksParam g_verifyParamsTest003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static struct HksParam g_genParamsTest004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }
};
static struct HksParam g_signParamsTest004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }
};
static struct HksParam g_verifyParamsTest004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }
};
static struct HksParam g_genParamsTest005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }
};
static struct HksParam g_signParamsTest005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }
};
static struct HksParam g_verifyParamsTest005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }
};
static struct HksParam g_genParamsTest006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA1
    }
};
static struct HksParam g_signParamsTest006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA1
    }
};
static struct HksParam g_verifyParamsTest006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA1
    }
};

static struct HksParam g_genParamsTest007[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA1
    }
};
static struct HksParam g_signParamsTest007[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA1
    }
};
static struct HksParam g_genParamsTest008[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA1
    }
};
static struct HksParam g_signParamsTest008[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_genParamsTest009[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }
};
static struct HksParam g_signParamsTest009[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};
static struct HksParam g_verifyParamsTest009[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_genParamsTest010[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DSA_COMMON_SIZE
    }
};
static struct HksParam g_signParamsTest010[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }
};

int32_t HksTestSignVerify(struct HksBlob *keyAlias, struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData, bool isSign)
{
    uint8_t tmpHandle[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), tmpHandle };
    int32_t ret = HksInitForDe(keyAlias, paramSet, &handle, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    struct HksParam *tmpParamTest = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_PURPOSE, &tmpParamTest);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get tag purpose failed.");
        return HKS_FAILURE;
    }

    ret = TestUpdateFinish(&handle, paramSet, tmpParamTest->uint32Param, inData, outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateFinish failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    if (isSign) {
        uint8_t tmpOut[DSA_COMMON_SIZE] = {0};
        struct HksBlob outData1 = { DSA_COMMON_SIZE, tmpOut };
        ret = HksSignForDe(keyAlias, paramSet, inData, &outData1);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksSign failed.";
    } else {
        ret = HksVerifyForDe(keyAlias, paramSet, inData, outData);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksVerify failed.";
    }

    return ret;
}

static int32_t HksDsaSignVerifyTestNormalCase(struct HksBlob keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *signParamSet, struct HksParamSet *verifyParamSet, uint32_t loopIndex)
{
    struct HksBlob inData = {
        g_inData.length(),
        (uint8_t *)g_inData.c_str()
    };
    int32_t ret = HKS_FAILURE;

    struct HksParam *digestAlg = nullptr;
    ret = HksGetParam(signParamSet, HKS_TAG_DIGEST, &digestAlg);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GetParam failed.";
    if (digestAlg->uint32Param == HKS_DIGEST_NONE) {
        inData.size = DATA_ARRAY_AFTER_HASH_LEN[loopIndex];
        inData.data = const_cast<uint8_t *>(g_inDataArrayAfterHash[loopIndex]);
    }

    /* 1. Generate Key */
    // Generate Key
    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. Sign Three Stage */
    uint8_t outDataS[DSA_COMMON_SIZE] = {0};
    struct HksBlob outDataSign = { DSA_COMMON_SIZE, outDataS };
    ret = HksTestSignVerify(&keyAlias, signParamSet, &inData, &outDataSign, true);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Sign failed.";

    /* 3. Export Public Key */
    uint8_t pubKey[DSA_COMMON_SIZE] = {0};
    struct HksBlob publicKey = { DSA_COMMON_SIZE, pubKey };
    ret = HksExportPublicKeyForDe(&keyAlias, genParamSet, &publicKey);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportPublicKey failed.";

    /* 4. Import Key */
    char newKey[] = "DSA_Sign_Verify_Import_KeyAlias";
    struct HksBlob newKeyAlias = { .size = strlen(newKey), .data = (uint8_t *)newKey };
    ret = HksImportKeyForDe(&newKeyAlias, verifyParamSet, &publicKey);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ImportKey failed";

    /* 5. Verify Three Stage */
    ret = HksTestSignVerify(&newKeyAlias, verifyParamSet, &inData, &outDataSign, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Verify failed.";

    /* 6. Delete New Key */
    int32_t deleteRet = HksDeleteKeyForDe(&newKeyAlias, verifyParamSet);
    EXPECT_EQ(deleteRet, HKS_SUCCESS) << "Delete ImportKey failed.";

    return ret;
}

/**
 * @tc.name: HksDsaSignVerifyTest.HksDsaSignVerifyTest001
 * @tc.desc: alg-DSA pur-Sign-verify dig-SHA1
 * @tc.type: FUNC
 */
HWTEST_F(HksDsaSignVerifyTest, HksDsaSignVerifyTest001, TestSize.Level0)
{
    HKS_LOG_E("Enter HksDsaSignVerifyTest001");
    int32_t ret = HKS_FAILURE;
    const char *keyAliasString = "HksDSASignVerifyKeyAliasTest001";
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_genParamsTest001, sizeof(g_genParamsTest001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest001, sizeof(g_signParamsTest001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest001, sizeof(g_verifyParamsTest001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksDsaSignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet, 0);
    }

    /* 5. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksDsaSignVerifyTest.HksDsaSignVerifyTest002
 * @tc.desc: alg-DSA pur-Sign-verify dig-SHA224
 * @tc.type: FUNC
 */
HWTEST_F(HksDsaSignVerifyTest, HksDsaSignVerifyTest002, TestSize.Level0)
{
    int32_t ret = HKS_FAILURE;
    const char *keyAliasString = "HksDSASignVerifyKeyAliasTest002";
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_genParamsTest002, sizeof(g_genParamsTest002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest002, sizeof(g_signParamsTest002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest002, sizeof(g_verifyParamsTest002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksDsaSignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet, 0);
    }

    /* 5. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksDsaSignVerifyTest.HksDsaSignVerifyTest003
 * @tc.desc: alg-DSA pur-Sign-verify dig-SHA256
 * @tc.type: FUNC
 */
HWTEST_F(HksDsaSignVerifyTest, HksDsaSignVerifyTest003, TestSize.Level0)
{
    int32_t ret = HKS_FAILURE;
    const char *keyAliasString = "HksDSASignVerifyKeyAliasTest003";
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_genParamsTest003, sizeof(g_genParamsTest003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest003, sizeof(g_signParamsTest003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest003, sizeof(g_verifyParamsTest003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksDsaSignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet, 0);
    }

    /* 5. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksDsaSignVerifyTest.HksDsaSignVerifyTest004
 * @tc.desc: alg-DSA pur-Sign-verify dig-SHA384
 * @tc.type: FUNC
 */
HWTEST_F(HksDsaSignVerifyTest, HksDsaSignVerifyTest004, TestSize.Level0)
{
    int32_t ret = HKS_FAILURE;
    const char *keyAliasString = "HksDSASignVerifyKeyAliasTest004";
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_genParamsTest004, sizeof(g_genParamsTest004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest004, sizeof(g_signParamsTest004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest004, sizeof(g_verifyParamsTest004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksDsaSignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet, 0);
    }

    /* 5. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksDsaSignVerifyTest.HksDsaSignVerifyTest005
 * @tc.desc: alg-DSA pur-Sign-verify dig-SHA512
 * @tc.type: FUNC
 */
HWTEST_F(HksDsaSignVerifyTest, HksDsaSignVerifyTest005, TestSize.Level0)
{
    int32_t ret = HKS_FAILURE;
    const char *keyAliasString = "HksDSASignVerifyKeyAliasTest005";
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_genParamsTest005, sizeof(g_genParamsTest005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest005, sizeof(g_signParamsTest005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest005, sizeof(g_verifyParamsTest005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksDsaSignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet, 0);
    }

    /* 5. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksDsaSignVerifyTest.HksDsaSignVerifyTest006
 * @tc.desc: alg-DSA pur-Sign-verify dig-SHA1 Verify-Abort
 * @tc.type: FUNC
 */
HWTEST_F(HksDsaSignVerifyTest, HksDsaSignVerifyTest006, TestSize.Level0)
{
    int32_t ret = HKS_FAILURE;
    const char *keyAliasString = "HksDSASignVerifyKeyAliasTest006";
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_genParamsTest006, sizeof(g_genParamsTest006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest006, sizeof(g_signParamsTest006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest006, sizeof(g_verifyParamsTest006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksDsaSignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet, 0);
    }

    /* 5. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksDsaSignVerifyTest.HksDsaSignVerifyTest007
 * @tc.desc: alg-DSA pur-Sign-verify dig-SHA1 Sign-Abort
 * @tc.type: FUNC
 */
HWTEST_F(HksDsaSignVerifyTest, HksDsaSignVerifyTest007, TestSize.Level0)
{
    const char *keyAliasString = "HksDSASignVerifyKeyAliasTest007";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksBlob inData = { g_inData.length(),
                              (uint8_t *)g_inData.c_str() };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParamsTest007, sizeof(g_genParamsTest007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // Generate Key
    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. Sign Three Stage (Abort) */
    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest007, sizeof(g_signParamsTest007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init
    uint8_t handleS[sizeof(uint64_t)] = {0};
    struct HksBlob handleSign = { sizeof(uint64_t), handleS };

    ret = HksInitForDe(&keyAlias, signParamSet, &handleSign, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";

    // Update loop
    ret = HksTestUpdate(&handleSign, signParamSet, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Update failed.";

    // Abort
    ret = HksAbort(&handleSign, signParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Abort failed.";

    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

/**
 * @tc.name: HksDsaSignVerifyTest.HksDsaSignVerifyTest008
 * @tc.desc: alg-DSA pur-Sign-verify dig-NONE abnormal
 * @tc.type: FUNC
 */
HWTEST_F(HksDsaSignVerifyTest, HksDsaSignVerifyTest008, TestSize.Level0)
{
    const char *keyAliasString = "HksDSASignVerifyKeyAliasTest008";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParamsTest008, sizeof(g_genParamsTest008) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // Generate Key
    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. Sign Three Stage */
    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest008, sizeof(g_signParamsTest008) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init
    uint8_t handleS[sizeof(uint64_t)] = {0};
    struct HksBlob handleSign = { sizeof(uint64_t), handleS };
    ret = HksInitForDe(NULL, signParamSet, &handleSign, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS) << "Init should failed.";

    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

/**
 * @tc.name: HksDsaSignVerifyTest.HksDsaSignVerifyTest009
 * @tc.desc: alg-DSA pur-Sign-verify dig-NONE
 * @tc.type: FUNC
 * @tc.require:issueI611S5
 */
HWTEST_F(HksDsaSignVerifyTest, HksDsaSignVerifyTest009, TestSize.Level0)
{
    HKS_LOG_E("Enter HksDsaSignVerifyTest009");
    int32_t ret = HKS_FAILURE;
    const char *keyAliasString = "HksDsaSignVerifyTest009";
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_genParamsTest009, sizeof(g_genParamsTest009) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest009, sizeof(g_signParamsTest009) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest009, sizeof(g_verifyParamsTest009) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        for (uint32_t i = 1; i < (sizeof(g_inDataArrayAfterHash) / sizeof(g_inDataArrayAfterHash[0])); i++) {
            HKS_LOG_E("HksDsaSignVerifyTest009 loop: %d", i);
            ret = HksDsaSignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet, i);
        }
    }

    /* 5. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksDsaSignVerifyTest.HksDsaSignVerifyTest010
 * @tc.desc: alg-DSA pur-Sign-verify. Result will be failed because degist is absent.
 * @tc.type: FUNC
 * @tc.require:issueI611S5
 */
HWTEST_F(HksDsaSignVerifyTest, HksDsaSignVerifyTest010, TestSize.Level0)
{
    HKS_LOG_E("Enter HksDsaSignVerifyTest010");
    const char *keyAliasString = "HksDSASignVerifyKeyAliasTest010";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParamsTest010, sizeof(g_genParamsTest010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // Generate Key
    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. Sign Three Stage  */
    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest010, sizeof(g_signParamsTest010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init. Result will be faied because of less degist.
    uint8_t handleS[sizeof(uint64_t)] = {0};
    struct HksBlob handleSign = { sizeof(uint64_t), handleS };

    ret = HksInitForDe(&keyAlias, signParamSet, &handleSign, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS) << "Init failed.";
} // namespace Unittest::DsaSignVerify
}