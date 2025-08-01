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

#include "hks_hkdf_derive_part2_test.h"
#include "hks_hkdf_derive_test_common.h"
#include "hks_test_adapt_for_de.h"

#include <gtest/gtest.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::HkdfDerive {
class HksHkdfDerivePart2Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksHkdfDerivePart2Test::SetUpTestCase(void)
{
}

void HksHkdfDerivePart2Test::TearDownTestCase(void)
{
}

void HksHkdfDerivePart2Test::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksHkdfDerivePart2Test::TearDown()
{
    std::system("find /data/service/el1/public/huks_service -user root -delete");
}

static struct HksParam g_hkdfStorageParams[] = {
    {
        .tag =  HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_TEMP
    }
};

static struct HksParam g_hkdfFinishStorageParams[] = {
    {
        .tag =  HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ALLOW_KEY_EXPORTED
    }
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
static struct HksParam g_genParams010[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }
};
static struct HksParam g_hkdfParams010[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_32
    }
};
static struct HksParam g_genParams011[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }
};
static struct HksParam g_hkdfParams011[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_48
    }
};
static struct HksParam g_genParams012[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }
};
static struct HksParam g_hkdfParams012[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_64
    }
};
#endif
static struct HksParam g_genParams013[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_192
    }
};
static struct HksParam g_hkdfParams013[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_32
    }
};
#ifdef HKS_UNTRUSTED_RUNNING_ENV
static struct HksParam g_genParams014[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_192
    }
};
static struct HksParam g_hkdfParams014[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_48
    }
};
static struct HksParam g_genParams015[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_192
    }
};
static struct HksParam g_hkdfParams015[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_64
    }
};
#endif
static struct HksParam g_genParams016[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};
static struct HksParam g_hkdfParams016[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_32
    }
};
static struct HksParam g_genParams017[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};
static struct HksParam g_hkdfParams017[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_48
    }
};
static struct HksParam g_genParams018[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};
static struct HksParam g_hkdfParams018[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_64
    }
};
static struct HksParam g_genParams019[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};
static struct HksParam g_hkdfParams019[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_64
    }
};
static struct HksParam g_genParams020[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};
static struct HksParam g_hkdfParams020[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
#ifdef L2_STANDARD
        .uint32Param = HKS_ALG_DSA
#else
        .uint32Param = HKS_ALG_HKDF
#endif
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = 256
    }
};

static struct HksParam g_genParams021[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};
static struct HksParam g_hkdfParams021[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_64
    }
};

static struct HksParam g_genParams022[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }, {
        .tag =  HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS
    }
};
static struct HksParam g_hkdfParams022[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_64
    }
};

static struct HksParam g_genParams023[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }, {
        .tag =  HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ALLOW_KEY_EXPORTED
    }
};
static struct HksParam g_hkdfParams023[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_64
    }
};
#ifdef HKS_UNTRUSTED_RUNNING_ENV
static struct HksParam g_genParams024[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag =  HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS
    }
};
static struct HksParam g_hkdfParams024[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_32
    }
};
static struct HksParam g_hkdfFinishParams024[] = {
    {
        .tag =  HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS
    }, {
        .tag =  HKS_TAG_KEY_ALIAS,
        .blob = {
            strlen("HksHKDFDeriveKeyAliasFinalTest024"),
            (uint8_t *)"HksHKDFDeriveKeyAliasFinalTest024"
        }
    }, {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }
};
#endif

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.name: HksHkdfDerivePart2Test.HksHKDFDerive0010
 * @tc.desc: alg-HKDF pur-Derive dig-SHA256 KEY_SIZE-128
 * @tc.type: FUNC
 */
HWTEST_F(HksHkdfDerivePart2Test, HksHKDFDerive0010, TestSize.Level0)
{
    struct HksBlob keyAlias = { (uint32_t)strlen("HksHKDFDeriveKeyAliasTest0010"),
        (uint8_t *)"HksHKDFDeriveKeyAliasTest0010" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams010, sizeof(g_genParams010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams010, sizeof(g_hkdfParams010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfStorageParams, sizeof(g_hkdfStorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
#ifdef L2_STANDARD
    HksHkdfDeriveTestCmpCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet);
#else
    HksHkdfDeriveTestNormalCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}
/**
 * @tc.name: HksHkdfDerivePart2Test.HksHKDFDerive0011
 * @tc.desc: alg-HKDF pur-Derive dig-SHA384 KEY_SIZE-128
 * @tc.type: FUNC
 */
HWTEST_F(HksHkdfDerivePart2Test, HksHKDFDerive0011, TestSize.Level0)
{
    struct HksBlob keyAlias = { (uint32_t)strlen("HksHKDFDeriveKeyAliasTest0011"),
        (uint8_t *)"HksHKDFDeriveKeyAliasTest0011" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams011, sizeof(g_genParams011) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams011, sizeof(g_hkdfParams011) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfStorageParams, sizeof(g_hkdfStorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
#ifdef L2_STANDARD
    HksHkdfDeriveTestCmpCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet);
#else
    HksHkdfDeriveTestNormalCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}
/**
 * @tc.name: HksHkdfDerivePart2Test.HksHKDFDerive0012
 * @tc.desc: alg-HKDF pur-Derive dig-SHA384 KEY_SIZE-192
 * @tc.type: FUNC
 */
HWTEST_F(HksHkdfDerivePart2Test, HksHKDFDerive0012, TestSize.Level0)
{
    struct HksBlob keyAlias = { (uint32_t)strlen("HksHKDFDeriveKeyAliasTest0012"),
        (uint8_t *)"HksHKDFDeriveKeyAliasTest0012" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams012, sizeof(g_genParams012) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams012, sizeof(g_hkdfParams012) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfStorageParams, sizeof(g_hkdfStorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
#ifdef L2_STANDARD
    HksHkdfDeriveTestCmpCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet);
#else
    HksHkdfDeriveTestNormalCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}
#endif
/**
 * @tc.name: HksHkdfDerivePart2Test.HksHKDFDerive0013  unnormal
 * @tc.desc: alg-HMAC pur-MAC dig-SHA512.
 * @tc.type: FUNC
 */
HWTEST_F(HksHkdfDerivePart2Test, HksHKDFDerive0013, TestSize.Level0)
{
    struct HksBlob keyAlias = { (uint32_t)strlen("HksHKDFDeriveKeyAliasTest0013"),
        (uint8_t *)"HksHKDFDeriveKeyAliasTest0013" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams013, sizeof(g_genParams013) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams013, sizeof(g_hkdfParams013) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfStorageParams, sizeof(g_hkdfStorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
#ifdef L2_STANDARD
    HksHkdfDeriveTestCmpCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet);
#else
    HksHkdfDeriveTestNormalCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.name: HksHkdfDerivePart2Test.HksHKDFDerive0014
 * @tc.desc: alg-HKDF pur-Derive dig-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksHkdfDerivePart2Test, HksHKDFDerive0014, TestSize.Level0)
{
    struct HksBlob keyAlias = { (uint32_t)strlen("HksHKDFDeriveKeyAliasTest0014"),
        (uint8_t *)"HksHKDFDeriveKeyAliasTest0014" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams014, sizeof(g_genParams014) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams014, sizeof(g_hkdfParams014) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfStorageParams, sizeof(g_hkdfStorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
#ifdef L2_STANDARD
    HksHkdfDeriveTestCmpCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet);
#else
    HksHkdfDeriveTestNormalCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}
/**
 * @tc.name: HksHkdfDerivePart2Test.HksHKDFDerive0015
 * @tc.desc: alg-HKDF pur-Derive dig-SHA384.
 * @tc.type: FUNC
 */
HWTEST_F(HksHkdfDerivePart2Test, HksHKDFDerive0015, TestSize.Level0)
{
    struct HksBlob keyAlias = { (uint32_t)strlen("HksHKDFDeriveKeyAliasTest0015"),
        (uint8_t *)"HksHKDFDeriveKeyAliasTest0015" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams015, sizeof(g_genParams015) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams015, sizeof(g_hkdfParams015) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfStorageParams, sizeof(g_hkdfStorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
#ifdef L2_STANDARD
    HksHkdfDeriveTestCmpCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet);
#else
    HksHkdfDeriveTestNormalCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}
#endif
/**
 * @tc.name: HksHkdfDerivePart2Test.HksHKDFDerive0016
 * @tc.desc: alg-HKDF pur-Derive dig-SHA512.
 * @tc.type: FUNC
 */
HWTEST_F(HksHkdfDerivePart2Test, HksHKDFDerive0016, TestSize.Level0)
{
    struct HksBlob keyAlias = { (uint32_t)strlen("HksHKDFDeriveKeyAliasTest0016"),
        (uint8_t *)"HksHKDFDeriveKeyAliasTest0016" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams016, sizeof(g_genParams016) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams016, sizeof(g_hkdfParams016) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfStorageParams, sizeof(g_hkdfStorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
#ifdef L2_STANDARD
    HksHkdfDeriveTestCmpCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet);
#else
    HksHkdfDeriveTestNormalCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}
/**
 * @tc.name: HksHkdfDerivePart2Test.HksHKDFDerive0017
 * @tc.desc: alg-HKDF pur-Derive dig-SHA512.
 * @tc.type: FUNC
 */
HWTEST_F(HksHkdfDerivePart2Test, HksHKDFDerive0017, TestSize.Level0)
{
    struct HksBlob keyAlias = { (uint32_t)strlen("HksHKDFDeriveKeyAliasTest0017"),
        (uint8_t *)"HksHKDFDeriveKeyAliasTest0017" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams017, sizeof(g_genParams017) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams017, sizeof(g_hkdfParams017) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfStorageParams, sizeof(g_hkdfStorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
#ifdef L2_STANDARD
    HksHkdfDeriveTestCmpCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet);
#else
    HksHkdfDeriveTestNormalCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}
/**
 * @tc.name: HksHkdfDerivePart2Test.HksHKDFDerive0018
 * @tc.desc: alg-HKDF pur-Derive dig-SHA512.
 * @tc.type: FUNC
 */
HWTEST_F(HksHkdfDerivePart2Test, HksHKDFDerive0018, TestSize.Level0)
{
    struct HksBlob keyAlias = { (uint32_t)strlen("HksHKDFDeriveKeyAliasTest0018"),
        (uint8_t *)"HksHKDFDeriveKeyAliasTest0018" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams018, sizeof(g_genParams018) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams018, sizeof(g_hkdfParams018) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfStorageParams, sizeof(g_hkdfStorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
#ifdef L2_STANDARD
    HksHkdfDeriveTestCmpCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet);
#else
    HksHkdfDeriveTestNormalCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}
/**
 * @tc.name: HksHkdfDerivePart2Test.HksHKDFDerive0019
 * @tc.desc: alg-HKDF pur-Derive dig-SHA512.  Abort
 * @tc.type: FUNC
 */
HWTEST_F(HksHkdfDerivePart2Test, HksHKDFDerive0019, TestSize.Level0)
{
    struct HksBlob keyAlias = { (uint32_t)strlen("HksHKDFDeriveKeyAliasTest0019"),
        (uint8_t *)"HksHKDFDeriveKeyAliasTest0019" };
    struct HksBlob inData = { (uint32_t)g_inData.length(),
                              (uint8_t *)g_inData.c_str() };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams019, sizeof(g_genParams019) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // Generate Key
    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams019, sizeof(g_hkdfParams019) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init
    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    ret = HksInitForDe(&keyAlias, hkdfParamSet, &handle, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";

    // Update
    uint8_t outUpdateU[DERIVE_KEY_SIZE_64] = {0};
    struct HksBlob outUpdate = { DERIVE_KEY_SIZE_64, outUpdateU };
    ret = HksUpdateForDe(&handle, hkdfParamSet, &inData, &outUpdate);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Update failed.";

    // Abort
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfStorageParams, sizeof(g_hkdfStorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = HksAbort(&handle, hkdfFinishParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Finish failed.";

    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}
/**
 * @tc.name: HksHkdfDerivePart2Test.HksHKDFDerive0020
 * @tc.desc: alg-HKDF pur-Derive dig-SHA512.  Abort
 * @tc.type: FUNC
 */
HWTEST_F(HksHkdfDerivePart2Test, HksHKDFDerive0020, TestSize.Level0)
{
    struct HksBlob keyAlias = { (uint32_t)strlen("HksHKDFDeriveKeyAliasTest0020"),
        (uint8_t *)"HksHKDFDeriveKeyAliasTest0020" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams020, sizeof(g_genParams020) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // Generate Key
    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams020, sizeof(g_hkdfParams020) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init
    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    ret = HksInitForDe(NULL, hkdfParamSet, &handle, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS) << "Init failed.";

    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
}

/**
 * @tc.name: HksHkdfDerivePart2Test.HksHKDFDerive021
 * @tc.desc: alg-HKDF pur-Derive dig-SHA512.
 * @tc.type: FUNC
 * @tc.require:issueI611S5
 */
HWTEST_F(HksHkdfDerivePart2Test, HksHKDFDerive021, TestSize.Level0)
{
    HKS_LOG_E("Enter HksHKDFDerive021");
    struct HksBlob keyAlias = { (uint32_t)strlen("HksHKDFDeriveKeyAliasTest021"),
        (uint8_t *)"HksHKDFDeriveKeyAliasTest021" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams021, sizeof(g_genParams021) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams021, sizeof(g_hkdfParams021) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfStorageParams, sizeof(g_hkdfStorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
#ifdef L2_STANDARD
    HksHkdfDeriveTestCmpCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet);
#else
    HksHkdfDeriveTestNormalCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}

/**
 * @tc.name: HksHkdfDerivePart2Test.HksHKDFDerive022
 * @tc.desc: alg-HKDF genKey storage flag and use storage flag do not match
 * @tc.type: FUNC
 * @tc.require:issueI6DHXT
 */
HWTEST_F(HksHkdfDerivePart2Test, HksHKDFDerive022, TestSize.Level0)
{
    HKS_LOG_E("Enter HksHKDFDerive022");
    struct HksBlob keyAlias = { (uint32_t)strlen("HksHKDFDeriveKeyAliasTest022"),
        (uint8_t *)"HksHKDFDeriveKeyAliasTest022" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams022, sizeof(g_genParams022) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams022, sizeof(g_hkdfParams022) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfFinishStorageParams,
        sizeof(g_hkdfFinishStorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    HksHkdfDeriveTestNormalCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_ERROR_BAD_STATE);
    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}

/**
 * @tc.name: HksHkdfDerivePart2Test.HksHKDFDerive023
 * @tc.desc: alg-HKDF genKey storage flag and use storage flag do match(HKS_STORAGE_TEMP)
 * @tc.type: FUNC
 * @tc.require:issueI6DHXT
 */
HWTEST_F(HksHkdfDerivePart2Test, HksHKDFDerive023, TestSize.Level0)
{
    HKS_LOG_E("Enter HksHKDFDerive023");
    struct HksBlob keyAlias = { (uint32_t)strlen("HksHKDFDeriveKeyAliasTest023"),
        (uint8_t *)"HksHKDFDeriveKeyAliasTest023" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams023, sizeof(g_genParams023) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams023, sizeof(g_hkdfParams023) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfFinishStorageParams,
        sizeof(g_hkdfFinishStorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
    HksHkdfDeriveTestNormalCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);

    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.name: HksHkdfDerivePart1Test.HksHKDFDerive024
 * @tc.desc: alg-HKDF genKey storage flag and use storage flag do match(storage)
 * @tc.type: FUNC
 * @tc.require:issueI6DHXT
 */
HWTEST_F(HksHkdfDerivePart2Test, HksHKDFDerive024, TestSize.Level0)
{
    struct HksBlob keyAlias = { (uint32_t)strlen("HksHKDFDeriveKeyAliasTest024"),
        (uint8_t *)"HksHKDFDeriveKeyAliasTest024" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams024, sizeof(g_genParams024) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams024, sizeof(g_hkdfParams024) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfFinishParams024, sizeof(g_hkdfFinishParams024) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
    HksHkdfDeriveTestNormalCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);

    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    struct HksBlob deleteKeyAlias = { .size = (uint32_t)strlen("HksHKDFDeriveKeyAliasFinalTest024"),
        .data = (uint8_t *)"HksHKDFDeriveKeyAliasFinalTest024"};
    ret = HksDeleteKeyForDe(&deleteKeyAlias, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Delete Final Key failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}
#endif
} // namespace Unittest::HkdfDerive
