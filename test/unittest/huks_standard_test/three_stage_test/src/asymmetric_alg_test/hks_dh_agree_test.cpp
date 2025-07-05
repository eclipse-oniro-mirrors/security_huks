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
#include "hks_struct_macro_def.h"

#include "hks_dh_agree_test.h"

#include "hks_agree_test_common.h"
#include "hks_test_adapt_for_de.h"

#include <gtest/gtest.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::DhAgree {
class HksDhAgreeTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksDhAgreeTest::SetUpTestCase(void)
{
}

void HksDhAgreeTest::TearDownTestCase(void)
{
}

void HksDhAgreeTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksDhAgreeTest::TearDown()
{
    std::system("find /data/service/el1/public/huks_service -user root -delete");
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
static struct HksBlob g_keyAlias01006 = {
    strlen("HksDHAgreeKeyAliasTest006_1"),
    (uint8_t *)"HksDHAgreeKeyAliasTest006_1"
};
static struct HksBlob g_keyAlias02006 = {
    strlen("HksDHAgreeKeyAliasTest006_2"),
    (uint8_t *)"HksDHAgreeKeyAliasTest006_2"
};
static struct HksParam g_genParams006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DH
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DH_KEY_SIZE_4096
    }
};
static struct HksParam g_agreeParams01Init006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DH
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DH_KEY_SIZE_4096
    }
};
static struct HksParam g_agreeParams01Finish006[] = {
    {
        .tag = HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_TEMP
    }
};
static struct HksParam g_agreeParams02Init006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DH
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DH_KEY_SIZE_4096
    }
};
static struct HksParam g_agreeParams02Finish006[] = {
    {
        .tag = HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_TEMP
    }
};

static struct HksBlob g_keyAlias01007 = {
    strlen("HksDHAgreeKeyAliasTest007_1"),
    (uint8_t *)"HksDHAgreeKeyAliasTest007_1"
};
static struct HksBlob g_keyAlias02007 = {
    strlen("HksDHAgreeKeyAliasTest007_2"),
    (uint8_t *)"HksDHAgreeKeyAliasTest007_2"
};
static struct HksParam g_genParams007[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DH
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DH_KEY_SIZE_4096
    }
};
static struct HksParam g_agreeParams01Init007[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DH
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DH_KEY_SIZE_4096
    }
};
static struct HksParam g_agreeParams02Init007[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DH
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DH_KEY_SIZE_4096
    }
};

static struct HksBlob g_keyAlias01008 = {
    strlen("HksDHAgreeKeyAliasTest008_1"),
    (uint8_t *)"HksDHAgreeKeyAliasTest008_1"
};
static struct HksBlob g_keyAlias02008 = {
    strlen("HksDHAgreeKeyAliasTest008_2"),
    (uint8_t *)"HksDHAgreeKeyAliasTest008_2"
};
static struct HksParam g_genParams008[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DH
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DH_KEY_SIZE_4096
    }
};
static struct HksParam g_agreeParams01Init008[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DH
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DH_KEY_SIZE_4096
    }
};
static struct HksParam g_agreeParams02Init008[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DH
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DH_KEY_SIZE_4096
    }
};

static struct HksBlob g_keyAlias01009 = {
    strlen("HksDHAgreeKeyAliasTest009_1"),
    (uint8_t *)"HksDHAgreeKeyAliasTest009_1"
};
static struct HksBlob g_keyAlias02009 = {
    strlen("HksDHAgreeKeyAliasTest009_2"),
    (uint8_t *)"HksDHAgreeKeyAliasTest009_2"
};
static struct HksParam g_genParams009[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DH
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DH_KEY_SIZE_2048
    }, {
        .tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS
    }
};

static struct HksParam g_agreeParams01Finish009[] = {
    {
        .tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS
    },
    HKS_DERIVE_FINISH_AES_256_COMMON_02
    {
        .tag = HKS_TAG_KEY_ALIAS,
        .blob = g_keyAliasFinal1001
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }
};

static struct HksParam g_agreeParams02Finish009[] = {
    {
        .tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS
    },
    HKS_DERIVE_FINISH_AES_256_COMMON_02
    {
        .tag = HKS_TAG_KEY_ALIAS,
        .blob = g_keyAliasFinal2001
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }
};
#endif

static struct HksBlob g_keyAlias01010 = {
    strlen("HksDHAgreeKeyAliasTest010_1"),
    (uint8_t *)"HksDHAgreeKeyAliasTest010_1"
};
static struct HksBlob g_keyAlias02010 = {
    strlen("HksDHAgreeKeyAliasTest010_2"),
    (uint8_t *)"HksDHAgreeKeyAliasTest010_2"
};
static struct HksParam g_genParams010[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DH
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DH_KEY_SIZE_2048
    }, {
        .tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ALLOW_KEY_EXPORTED
    }
};

static struct HksParam g_agreeParamsFinish010[] = {
    {
        .tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ALLOW_KEY_EXPORTED
    }
};

static struct HksBlob g_keyAlias01011 = {
    strlen("HksDHAgreeKeyAliasTest011_1"),
    (uint8_t *)"HksDHAgreeKeyAliasTest011_1"
};
static struct HksBlob g_keyAlias02011 = {
    strlen("HksDHAgreeKeyAliasTest011_2"),
    (uint8_t *)"HksDHAgreeKeyAliasTest011_2"
};
static struct HksParam g_genParams011[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DH
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DH_KEY_SIZE_2048
    }, {
        .tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS
    }
};

int32_t HksDhAgreeFinish(const struct HksBlob *keyAlias, const struct HksBlob *publicKey,
                         const struct HksParamSet *initParamSet, const struct HksParamSet *finishParamSet,
                         struct HksBlob *outData)
{
    struct HksBlob inData = { g_inData.length(), (uint8_t *)g_inData.c_str() };

    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    int32_t ret = HksInitForDe(keyAlias, initParamSet, &handle, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    uint8_t outDataU[DH_COMMON_SIZE] = {0};
    struct HksBlob outDataUpdate = { DH_COMMON_SIZE, outDataU };
    ret = HksUpdateForDe(&handle, initParamSet, publicKey, &outDataUpdate);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Update failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    return HksFinishForDe(&handle, finishParamSet, &inData, outData);
}

int32_t HksDhAgreeAbort(const struct HksBlob *keyAlias, const struct HksBlob *publicKey,
                        const struct HksParamSet *initParamSet)
{
    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    int32_t ret = HksInitForDe(keyAlias, initParamSet, &handle, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    uint8_t outDataU[DH_COMMON_SIZE] = {0};
    struct HksBlob outDataUpdate = { DH_COMMON_SIZE, outDataU };
    ret = HksUpdateForDe(&handle, initParamSet, publicKey, &outDataUpdate);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Update failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    ret = HksAbort(&handle, initParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Finish failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

int32_t HksDhAgreeExport(const struct HksBlob *keyAlias1, const struct HksBlob *keyAlias2,
                         struct HksBlob *publicKey1, struct HksBlob *publicKey2,
                         const struct HksParamSet *genParamSet)
{
    int32_t ret = HksExportPublicKeyForDe(keyAlias1, genParamSet, publicKey1);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportPublicKey01 failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }
    ret = HksExportPublicKeyForDe(keyAlias2, genParamSet, publicKey2);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportPublicKey02 failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

void HksDhAgreeFreeParamSet(struct HksParamSet *paramSet1, struct HksParamSet *paramSet2,
                            struct HksParamSet *paramSet3)
{
    HksFreeParamSet(&paramSet1);
    HksFreeParamSet(&paramSet2);
    HksFreeParamSet(&paramSet3);
}

void HksDhAgreeFreeParamSet(struct HksParamSet *paramSet1, struct HksParamSet *paramSet2,
                            struct HksParamSet *paramSet3, struct HksParamSet *paramSet4,
                            struct HksParamSet *paramSet5)
{
    HksFreeParamSet(&paramSet1);
    HksFreeParamSet(&paramSet2);
    HksFreeParamSet(&paramSet3);
    HksFreeParamSet(&paramSet4);
    HksFreeParamSet(&paramSet5);
}

void HksDhAgreeFreeBlob(struct HksBlob *blob1, struct HksBlob *blob2)
{
    HKS_FREE(blob1->data);
    HKS_FREE(blob2->data);
}

void HksDhAgreeFreeBlob(struct HksBlob *blob1, struct HksBlob *blob2, struct HksBlob *blob3, struct HksBlob *blob4)
{
    HKS_FREE(blob1->data);
    HKS_FREE(blob2->data);
    HKS_FREE(blob3->data);
    HKS_FREE(blob4->data);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.name: HksDhAgreeTest.HksDhAgree001
 * @tc.desc: alg-DH, pur-AGREE
 * @tc.type: FUNC
 */
HWTEST_F(HksDhAgreeTest, HksDhAgree001, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSetTest02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_agreeParams01Init001, sizeof(g_agreeParams01Init001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_agreeParams01Finish001,
        sizeof(g_agreeParams01Finish001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSetTest02, g_agreeParams02Init001, sizeof(g_agreeParams02Init001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_agreeParams02Finish001,
        sizeof(g_agreeParams02Finish001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKeyForDe(&g_keyAlias01001, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKeyForDe(&g_keyAlias02001, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksDhAgreeExport(&g_keyAlias01001, &g_keyAlias02001, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = DH_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = DH_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksDhAgreeFinish(&g_keyAlias01001, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeFinish01 failed.";
    ret = HksDhAgreeFinish(&g_keyAlias02001, &publicKey01, initParamSetTest02, finishParamSet02, &outData02);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeFinish02 failed.";

    ret = TestAgreedKeyUse(&g_keyAliasFinal1001, &g_keyAliasFinal2001);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestAgreedKeyUse failed.";

    HksDeleteKeyForDe(&g_keyAlias01001, genParamSet);
    HksDeleteKeyForDe(&g_keyAlias02001, genParamSet);
    HksDeleteKeyForDe(&g_keyAliasFinal1001, NULL);
    HksDeleteKeyForDe(&g_keyAliasFinal2001, NULL);
    HksDhAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSetTest02, finishParamSet02);
    HksDhAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}

/**
 * @tc.name: HksDhAgreeTest.HksDhAgree002
 * @tc.desc: alg-DH, pur-AGREE, size-3072
 * @tc.type: FUNC
 */
HWTEST_F(HksDhAgreeTest, HksDhAgree002, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    struct HksParamSet *finishParamSetTest02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams002, sizeof(g_genParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_agreeParams01Init002, sizeof(g_agreeParams01Init002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_agreeParams01Finish002,
        sizeof(g_agreeParams01Finish002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSet02, g_agreeParams02Init002, sizeof(g_agreeParams02Init002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSetTest02, g_agreeParams02Finish002,
        sizeof(g_agreeParams02Finish002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKeyForDe(&g_keyAlias01002, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKeyForDe(&g_keyAlias02002, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksDhAgreeExport(&g_keyAlias01002, &g_keyAlias02002, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = DH_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = DH_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksDhAgreeFinish(&g_keyAlias01002, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeFinish01 failed.";
    ret = HksDhAgreeFinish(&g_keyAlias02002, &publicKey01, initParamSet02, finishParamSetTest02, &outData02);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeFinish02 failed.";

    HksDeleteKeyForDe(&g_keyAlias01002, genParamSet);
    HksDeleteKeyForDe(&g_keyAlias02002, genParamSet);
    HksDeleteKeyForDe(&g_keyAliasFinal1002, NULL);
    HksDeleteKeyForDe(&g_keyAliasFinal2002, NULL);
    HksDhAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSet02, finishParamSetTest02);
    HksDhAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}

/**
 * @tc.name: HksDhAgreeTest.HksDhAgree003
 * @tc.desc: alg-DH, pur-AGREE, size-4096
 * @tc.type: FUNC
 */
HWTEST_F(HksDhAgreeTest, HksDhAgree003, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams003, sizeof(g_genParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_agreeParams01Init003, sizeof(g_agreeParams01Init003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_agreeParams01Finish003,
        sizeof(g_agreeParams01Finish003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSet02, g_agreeParams02Init003, sizeof(g_agreeParams02Init003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_agreeParams02Finish003,
        sizeof(g_agreeParams02Finish003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKeyForDe(&g_keyAlias01003, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKeyForDe(&g_keyAlias02003, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksDhAgreeExport(&g_keyAlias01003, &g_keyAlias02003, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = DH_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = DH_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksDhAgreeFinish(&g_keyAlias01003, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeFinish01 failed.";
    ret = HksDhAgreeFinish(&g_keyAlias02003, &publicKey01, initParamSet02, finishParamSet02, &outData02);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeFinish02 failed.";

    HksDeleteKeyForDe(&g_keyAlias01003, genParamSet);
    HksDeleteKeyForDe(&g_keyAlias02003, genParamSet);
    HksDeleteKeyForDe(&g_keyAliasFinal1003, NULL);
    HksDeleteKeyForDe(&g_keyAliasFinal2003, NULL);
    HksDhAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSet02, finishParamSet02);
    HksDhAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}

/**
 * @tc.name: HksDhAgreeTest.HksDhAgree004
 * @tc.desc: alg-DH, pur-AGREE
 * @tc.type: FUNC
 */
HWTEST_F(HksDhAgreeTest, HksDhAgree004, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams004, sizeof(g_genParams004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_agreeParams01Init004, sizeof(g_agreeParams01Init004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_agreeParams01Finish004,
        sizeof(g_agreeParams01Finish004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSet02, g_agreeParams02Init004, sizeof(g_agreeParams02Init004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_agreeParams02Finish004,
        sizeof(g_agreeParams02Finish004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKeyForDe(&g_keyAlias01004, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKeyForDe(&g_keyAlias02004, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksDhAgreeExport(&g_keyAlias01004, &g_keyAlias02004, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = DH_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = DH_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksDhAgreeFinish(&g_keyAlias01004, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeFinish01 failed.";
    ret = HksAgreeKeyForDe(initParamSet02, &g_keyAlias02004, &publicKey01, &outData02);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAgreeKey02 failed.";
    EXPECT_EQ(TestCmpKeyAliasHash(&outData01, &outData02), HKS_SUCCESS) << "outData01 not equals outData02";

    HksDeleteKeyForDe(&g_keyAlias01004, genParamSet);
    HksDeleteKeyForDe(&g_keyAlias02004, genParamSet);
    HksDhAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSet02, finishParamSet02);
    HksDhAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}

/**
 * @tc.name: HksDhAgreeTest.HksDhAgree005
 * @tc.desc: alg-DH, pur-AGREE
 * @tc.type: FUNC
 */
HWTEST_F(HksDhAgreeTest, HksDhAgree005, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSetTest02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams005, sizeof(g_genParams005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_agreeParams01Init005, sizeof(g_agreeParams01Init005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_agreeParams01Finish005,
        sizeof(g_agreeParams01Finish005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSetTest02, g_agreeParams02Init005, sizeof(g_agreeParams02Init005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_agreeParams02Finish005,
        sizeof(g_agreeParams02Finish005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKeyForDe(&g_keyAlias01005, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKeyForDe(&g_keyAlias02005, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksDhAgreeExport(&g_keyAlias01005, &g_keyAlias02005, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = DH_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = DH_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksDhAgreeFinish(&g_keyAlias01005, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeFinish01 failed.";
    ret = HksAgreeKeyForDe(initParamSetTest02, &g_keyAlias02005, &publicKey01, &outData02);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAgreeKey02 failed.";
    EXPECT_EQ(TestCmpKeyAliasHash(&outData01, &outData02), HKS_SUCCESS) << "outData01 not equals outData02";

    HksDeleteKeyForDe(&g_keyAlias01005, genParamSet);
    HksDeleteKeyForDe(&g_keyAlias02005, genParamSet);
    HksDhAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSetTest02, finishParamSet02);
    HksDhAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}

/**
 * @tc.name: HksDhAgreeTest.HksDhAgree006
 * @tc.desc: alg-DH, pur-AGREE, size-3072
 * @tc.type: FUNC
 */
HWTEST_F(HksDhAgreeTest, HksDhAgree006, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSetTest02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams006, sizeof(g_genParams006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_agreeParams01Init006, sizeof(g_agreeParams01Init006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_agreeParams01Finish006,
        sizeof(g_agreeParams01Finish006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSetTest02, g_agreeParams02Init006, sizeof(g_agreeParams02Init006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_agreeParams02Finish006,
        sizeof(g_agreeParams02Finish006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKeyForDe(&g_keyAlias01006, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKeyForDe(&g_keyAlias02006, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksDhAgreeExport(&g_keyAlias01006, &g_keyAlias02006, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = DH_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = DH_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksDhAgreeFinish(&g_keyAlias01006, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeFinish01 failed.";
    ret = HksAgreeKeyForDe(initParamSetTest02, &g_keyAlias02006, &publicKey01, &outData02);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAgreeKey02 failed.";
    EXPECT_EQ(TestCmpKeyAliasHash(&outData01, &outData02), HKS_SUCCESS) << "outData01 not equals outData02";

    HksDeleteKeyForDe(&g_keyAlias01006, genParamSet);
    HksDeleteKeyForDe(&g_keyAlias02006, genParamSet);
    HksDhAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSetTest02, finishParamSet02);
    HksDhAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}

/**
 * @tc.name: HksDhAgreeTest.HksDhAgree007
 * @tc.desc: alg-DH, pur-AGREE, size-3072
 * @tc.type: FUNC  Abort
 */
HWTEST_F(HksDhAgreeTest, HksDhAgree007, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams007, sizeof(g_genParams007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_agreeParams01Init007, sizeof(g_agreeParams01Init007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&initParamSet02, g_agreeParams02Init007, sizeof(g_agreeParams02Init007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";

    ret = HksGenerateKeyForDe(&g_keyAlias01007, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKeyForDe(&g_keyAlias02007, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksDhAgreeExport(&g_keyAlias01007, &g_keyAlias02007, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    ret = HksDhAgreeAbort(&g_keyAlias01007, &publicKey02, initParamSet01);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeAbort01 failed.";
    ret = HksDhAgreeAbort(&g_keyAlias02007, &publicKey01, initParamSet02);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeAbort02 failed.";

    HksDeleteKeyForDe(&g_keyAlias01007, genParamSet);
    HksDeleteKeyForDe(&g_keyAlias02007, genParamSet);
    HksDhAgreeFreeParamSet(genParamSet, initParamSet01, initParamSet02);
    HksDhAgreeFreeBlob(&publicKey01, &publicKey02);
}

/**
 * @tc.name: HksDhAgreeTest.HksDhAgree008
 * @tc.desc: alg-DH, pur-AGREE, size-3072
 * @tc.type: FUNC  abnormal
 */
HWTEST_F(HksDhAgreeTest, HksDhAgree008, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams008, sizeof(g_genParams008) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_agreeParams01Init008, sizeof(g_agreeParams01Init008) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&initParamSet02, g_agreeParams02Init008, sizeof(g_agreeParams02Init008) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";

    ret = HksGenerateKeyForDe(&g_keyAlias01008, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKeyForDe(&g_keyAlias02008, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    ret = HksInitForDe(NULL, initParamSet01, &handle, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS) << "HksInit01 should failed.";
    ret = HksInitForDe(NULL, initParamSet02, &handle, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS) << "HksInit02 should failed.";

    HksDeleteKeyForDe(&g_keyAlias01008, genParamSet);
    HksDeleteKeyForDe(&g_keyAlias02008, genParamSet);
    HksDhAgreeFreeParamSet(genParamSet, initParamSet01, initParamSet02);
}

/**
 * @tc.name: HksDhAgreeTest.HksDhAgree009
 * @tc.desc: alg-DH, genKey storage flag and use storage flag do match(key store in)
 * @tc.type: FUNC
 * @tc.require:issueI6DHXT
 */
HWTEST_F(HksDhAgreeTest, HksDhAgree009, TestSize.Level0)
{
    HKS_LOG_E("Enter HksDhAgree009");
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams009, sizeof(g_genParams009) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_agreeParams01Init001, sizeof(g_agreeParams01Init001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_agreeParams01Finish009,
        sizeof(g_agreeParams01Finish009) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSet02, g_agreeParams02Init001, sizeof(g_agreeParams02Init001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_agreeParams02Finish009,
        sizeof(g_agreeParams02Finish009) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKeyForDe(&g_keyAlias01009, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKeyForDe(&g_keyAlias02009, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksDhAgreeExport(&g_keyAlias01009, &g_keyAlias02009, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = DH_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = DH_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksDhAgreeFinish(&g_keyAlias01009, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeFinish01 failed.";
    ret = HksDhAgreeFinish(&g_keyAlias02009, &publicKey01, initParamSet02, finishParamSet02, &outData02);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeFinish02 failed.";

    HksDeleteKeyForDe(&g_keyAlias01009, genParamSet);
    HksDeleteKeyForDe(&g_keyAlias02009, genParamSet);
    HksDeleteKeyForDe(&g_keyAliasFinal1001, NULL);
    HksDeleteKeyForDe(&g_keyAliasFinal2001, NULL);
    HksDhAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSet02, finishParamSet02);
    HksDhAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}
#endif

/**
 * @tc.name: HksDhAgreeTest.HksDhAgree010
 * @tc.desc: alg-DH, genKey storage flag and use storage flag do match(key out)
 * @tc.type: FUNC
 * @tc.require:issueI6DHXT
 */
HWTEST_F(HksDhAgreeTest, HksDhAgree010, TestSize.Level0)
{
    HKS_LOG_E("Enter HksDhAgree010");
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams010, sizeof(g_genParams010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_agreeParams01Init004, sizeof(g_agreeParams01Init004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_agreeParamsFinish010, sizeof(g_agreeParamsFinish010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSet02, g_agreeParams02Init004, sizeof(g_agreeParams02Init004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_agreeParamsFinish010, sizeof(g_agreeParamsFinish010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKeyForDe(&g_keyAlias01010, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKeyForDe(&g_keyAlias02010, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksDhAgreeExport(&g_keyAlias01010, &g_keyAlias02010, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = DH_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = DH_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksDhAgreeFinish(&g_keyAlias01010, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeFinish01 failed.";
    ret = HksAgreeKeyForDe(initParamSet02, &g_keyAlias02010, &publicKey01, &outData02);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAgreeKey02 failed.";
    EXPECT_EQ(TestCmpKeyAliasHash(&outData01, &outData02), HKS_SUCCESS) << "outData01 not equals outData02";

    HksDeleteKeyForDe(&g_keyAlias01010, genParamSet);
    HksDeleteKeyForDe(&g_keyAlias02010, genParamSet);
    HksDhAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSet02, finishParamSet02);
    HksDhAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}

/**
 * @tc.name: HksDhAgreeTest.HksDhAgree011
 * @tc.desc: alg-DH, genKey storage flag and use storage flag do not match
 * @tc.type: FUNC
 * @tc.require:issueI6DHXT
 */
HWTEST_F(HksDhAgreeTest, HksDhAgree011, TestSize.Level0)
{
    HKS_LOG_E("Enter HksDhAgree011");
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams011, sizeof(g_genParams011) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_agreeParams01Init004, sizeof(g_agreeParams01Init004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_agreeParamsFinish010,
        sizeof(g_agreeParamsFinish010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";

    ret = HksGenerateKeyForDe(&g_keyAlias01011, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKeyForDe(&g_keyAlias02011, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksDhAgreeExport(&g_keyAlias01011, &g_keyAlias02011, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = DH_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = DH_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    ret = HksDhAgreeFinish(&g_keyAlias01011, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_ERROR_BAD_STATE) << "HksDhAgree011 failed.";

    HksDeleteKeyForDe(&g_keyAlias01011, genParamSet);
    HksDeleteKeyForDe(&g_keyAlias02011, genParamSet);
    HksDhAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSet02, finishParamSet02);
    HksDhAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}
} // namespace Unittest::DhAgree