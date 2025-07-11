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

#include "hks_hmac_test.h"
#include "hks_test_adapt_for_de.h"

#include <gtest/gtest.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::Hmac {
class HksHmacTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksHmacTest::SetUpTestCase(void)
{
}

void HksHmacTest::TearDownTestCase(void)
{
}

void HksHmacTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksHmacTest::TearDown()
{
    std::system("find /data/service/el1/public/huks_service -user root -delete");
}

#ifdef L2_STANDARD
#ifdef HKS_UNTRUSTED_RUNNING_ENV
static struct HksParam g_genParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA1
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = Unittest::Hmac::COMMON_SIZE
    }
};
static struct HksParam g_hmacParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA1
    }
};

static struct HksParam g_genParams002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA224
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = Unittest::Hmac::COMMON_SIZE
    }
};
static struct HksParam g_hmacParams002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA224
    }
};
#endif // HKS_UNTRUSTED_RUNNING_ENV
#endif
#ifdef L2_STANDARD
static struct HksParam g_genParams003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = Unittest::Hmac::COMMON_SIZE
    }
};
#else
static struct HksParam g_genParams003 [] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = COMMON_SIZE
    }
};
#endif
static struct HksParam g_hmacParams003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

#ifdef L2_STANDARD
static struct HksParam g_genParams004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = Unittest::Hmac::COMMON_SIZE
    }
};
static struct HksParam g_hmacParams004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }
};

static struct HksParam g_genParams005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = Unittest::Hmac::COMMON_SIZE
    }
};
static struct HksParam g_hmacParams005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }
};

#ifdef _USE_OPENSSL_
static struct HksParam g_genParams006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SM3
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = Unittest::Hmac::COMMON_SIZE
    }
};
static struct HksParam g_hmacParams006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SM3
    }
};

static struct HksParam g_genParams007[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_SM3
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SM3
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = Unittest::Hmac::COMMON_SIZE
    }
};
static struct HksParam g_hmacParams007[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_SM3
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SM3
    }
};

static struct HksParam g_genParams008[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = Unittest::Hmac::COMMON_SIZE
    }
};
static struct HksParam g_hmacParams008[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SM3
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = Unittest::Hmac::COMMON_SIZE
    }
};

static const struct GenerateKeyCaseParam g_genParamsFail[] = {
    {   0,
        HKS_ERROR_INVALID_DIGEST,
        {
            {
                .tag = HKS_TAG_ALGORITHM,
                .uint32Param = HKS_ALG_SM3
            }, {
                .tag = HKS_TAG_KEY_SIZE,
                .uint32Param = Unittest::Hmac::COMMON_SIZE
            }, {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_MAC
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SHA512
            },
        },
    },
};
static const struct GenerateKeyCaseParam g_hmacParamsFail[] = {
    {   0,
        HKS_ERROR_INVALID_DIGEST,
        {
            {
                .tag = HKS_TAG_ALGORITHM,
                .uint32Param = HKS_ALG_SM3
            }, {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_MAC
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SHA512
            },
        },
    },
};
#endif
#endif

static int32_t HksHmacTestCase(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *hmacParamSet)
{
    struct HksBlob inData = { (uint32_t)g_inData.length(), (uint8_t *)g_inData.c_str() };

    /* 1. Generate Key */
    int32_t ret = HksGenerateKeyForDe(keyAlias, genParamSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("GenerateKey failed");
        return ret;
    }

    /* 2. HMAC One Stage */
    uint8_t tmpMac[Unittest::Hmac::COMMON_SIZE] = {0};
    struct HksBlob mac = { Unittest::Hmac::COMMON_SIZE, tmpMac };
    ret = HksMacForDe(keyAlias, hmacParamSet, &inData, &mac);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksMac failed.";
    if (ret != HKS_SUCCESS) {
        HksDeleteKeyForDe(keyAlias, genParamSet);
        return ret;
    }

    /* 2. HMAC Three Stage */
    // Init
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct HksBlob handleHMAC = { sizeof(uint64_t), handle };
    ret = HksInitForDe(keyAlias, hmacParamSet, &handleHMAC, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        HksDeleteKeyForDe(keyAlias, genParamSet);
        return ret;
    }
    // Update & Finish
    uint8_t out[Unittest::Hmac::COMMON_SIZE] = {0};
    struct HksBlob outData = { Unittest::Hmac::COMMON_SIZE, out };
    ret = TestUpdateFinish(&handleHMAC, hmacParamSet, HKS_KEY_PURPOSE_MAC, &inData, &outData);
    if (ret != HKS_SUCCESS) {
        HksDeleteKeyForDe(keyAlias, genParamSet);
        return ret;
    }
    EXPECT_EQ(HksMemCmp(mac.data, outData.data, outData.size), HKS_SUCCESS);

    /* 3. Delete Key */
    ret = HksDeleteKeyForDe(keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    return ret;
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
#ifdef L2_STANDARD
/**
 * @tc.name: HksHmacTest.HksHmacTest001
 * @tc.desc: alg-HMAC pur-MAC dig-SHA1.
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacTest, HksHmacTest001, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksHMACKeyAliasTest001";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));

    struct HksParamSet *hmacParamSet = nullptr;
    ret = InitParamSet(&hmacParamSet, g_hmacParams001, sizeof(g_hmacParams001) / sizeof(HksParam));

    ret = HksHmacTestCase(&keyAlias, genParamSet, hmacParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hmacParamSet);
}

/**
 * @tc.name: HksHmacTest.HksHmacTest002
 * @tc.desc: alg-HMAC pur-MAC dig-SHA224.
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacTest, HksHmacTest002, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksHMACKeyAliasTest002";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams002, sizeof(g_genParams002) / sizeof(HksParam));

    struct HksParamSet *hmacParamSet = nullptr;
    ret = InitParamSet(&hmacParamSet, g_hmacParams002, sizeof(g_hmacParams002) / sizeof(HksParam));

    ret = HksHmacTestCase(&keyAlias, genParamSet, hmacParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hmacParamSet);
}
#endif
#endif //HKS_UNTRUSTED_RUNNING_ENV

/**
 * @tc.name: HksHmacTest.HksHmacTest003
 * @tc.desc: alg-HMAC pur-MAC dig-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacTest, HksHmacTest003, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksHMACKeyAliasTest003";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams003, sizeof(g_genParams003) / sizeof(HksParam));
    struct HksParamSet *hmacParamSet = nullptr;
    ret = InitParamSet(&hmacParamSet, g_hmacParams003, sizeof(g_hmacParams003) / sizeof(HksParam));

    ret = HksHmacTestCase(&keyAlias, genParamSet, hmacParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hmacParamSet);
}

#ifdef L2_STANDARD
/**
 * @tc.name: HksHmacTest.HksHmacTest004
 * @tc.desc: alg-HMAC pur-MAC dig-SHA384.
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacTest, HksHmacTest004, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksHMACKeyAliasTest004";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams004, sizeof(g_genParams004) / sizeof(HksParam));

    struct HksParamSet *hmacParamSet = nullptr;
    ret = InitParamSet(&hmacParamSet, g_hmacParams004, sizeof(g_hmacParams004) / sizeof(HksParam));

    ret = HksHmacTestCase(&keyAlias, genParamSet, hmacParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hmacParamSet);
}

/**
 * @tc.name: HksHmacTest.HksHmacTest005
 * @tc.desc: alg-HMAC pur-MAC dig-SHA512.
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacTest, HksHmacTest005, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksHMACKeyAliasTest005";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams005, sizeof(g_genParams005) / sizeof(HksParam));

    struct HksParamSet *hmacParamSet = nullptr;
    ret = InitParamSet(&hmacParamSet, g_hmacParams005, sizeof(g_hmacParams005) / sizeof(HksParam));

    ret = HksHmacTestCase(&keyAlias, genParamSet, hmacParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hmacParamSet);
}
#endif

/**
 * @tc.name: HksHmacTest.HksHmacTest006
 * @tc.desc: alg-HMAC pur-MAC dig-SHA512. Abort
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacTest, HksHmacTest006, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksHMACKeyAliasTest006";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksBlob inData = { (uint32_t)g_inData.length(), (uint8_t *)g_inData.c_str() };
    int32_t ret = HKS_FAILURE;

    /* 2. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *hmacParamSet = nullptr;
#ifdef L2_STANDARD
    ret = InitParamSet(&genParamSet, g_genParams005, sizeof(g_genParams005) / sizeof(HksParam));
#else
    ret = InitParamSet(&genParamSet, g_genParams003, sizeof(g_genParams003) / sizeof(HksParam));
#endif
    // Generate Key
    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. HMAC Three Stage(Abort) */
#ifdef L2_STANDARD
    ret = InitParamSet(&hmacParamSet, g_hmacParams005, sizeof(g_hmacParams005) / sizeof(HksParam));
#else
    ret = InitParamSet(&hmacParamSet, g_hmacParams003, sizeof(g_hmacParams003) / sizeof(HksParam));
#endif
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // Init
    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    ret = HksInitForDe(&keyAlias, hmacParamSet, &handle, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    // Update loop
    ret = HksTestUpdate(&handle, hmacParamSet, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Update failed.";
    // Abort
    ret = HksAbort(&handle, hmacParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Abort failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hmacParamSet);
}

/**
 * @tc.name: HksHmacTest.HksHmacTest007
 * @tc.desc: alg-HMAC pur-MAC dig-SHA512. abnormal
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacTest, HksHmacTest007, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksHMACKeyAliasTest007";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    int32_t ret = HKS_FAILURE;

    /* 2. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
#ifdef L2_STANDARD
    ret = InitParamSet(&genParamSet, g_genParams005, sizeof(g_genParams005) / sizeof(HksParam));
#else
    ret = InitParamSet(&genParamSet, g_genParams003, sizeof(g_genParams003) / sizeof(HksParam));
#endif
    // Generate Key
    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. HMAC Three Stage(Abort) */
    struct HksParamSet *hmacParamSet = nullptr;
#ifdef L2_STANDARD
    ret = InitParamSet(&hmacParamSet, g_hmacParams005, sizeof(g_hmacParams005) / sizeof(HksParam));
#else
    ret = InitParamSet(&hmacParamSet, g_hmacParams003, sizeof(g_hmacParams003) / sizeof(HksParam));
#endif
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // Init
    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    ret = HksInitForDe(NULL, hmacParamSet, &handle, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS) << "Init should failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hmacParamSet);
}

#ifdef _USE_OPENSSL_
/**
 * @tc.name: HksHmacTest.HksHmacTest008
 * @tc.desc: alg-HMAC pur-MAC dig-sm3.
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacTest, HksHmacTest008, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksHMACKeyAliasTest008";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams006, sizeof(g_genParams006) / sizeof(HksParam));

    struct HksParamSet *hmacParamSet = nullptr;
    ret = InitParamSet(&hmacParamSet, g_hmacParams006, sizeof(g_hmacParams006) / sizeof(HksParam));

    ret = HksHmacTestCase(&keyAlias, genParamSet, hmacParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hmacParamSet);
}

    /**
     * @tc.name: HksHmacTest.HksHmacTest009
     * @tc.desc: alg-SM3 pur-MAC dig-sm3.
     * @tc.type: FUNC
     */
HWTEST_F(HksHmacTest, HksHmacTest009, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksSM3KeyAliasTest009";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams007, sizeof(g_genParams007) / sizeof(HksParam));

    struct HksParamSet *hmacParamSet = nullptr;
    ret = InitParamSet(&hmacParamSet, g_hmacParams007, sizeof(g_hmacParams007) / sizeof(HksParam));

    ret = HksHmacTestCase(&keyAlias, genParamSet, hmacParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hmacParamSet);
}

    /**
     * @tc.name: HksHmacTest.HksHmacTest010
     * @tc.desc: alg-SM3 pur-MAC dig-hmac.
     * @tc.type: FUNC
     */
HWTEST_F(HksHmacTest, HksHmacTest010, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksSM3KeyAliasTest010";
    uint32_t index = 0;
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsFail[index].params,
        sizeof(g_genParamsFail[index].params) / sizeof(HksParam));

    struct HksParamSet *hmacParamSet = nullptr;
    ret = InitParamSet(&hmacParamSet, g_hmacParamsFail[index].params,
        sizeof(g_hmacParamsFail[index].params) / sizeof(HksParam));

    ret = HksHmacTestCase(&keyAlias, genParamSet, hmacParamSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_DIGEST) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hmacParamSet);
}

/**
 * @tc.name: HksHmacTest.HksHmacTest011
 * @tc.desc: alg-HMAC pur-MAC dig-sm3. and When generating the key, only the necessary parameters are passed in.
 * @tc.type: FUNC
 * @tc.require:issueI611S5
 */
HWTEST_F(HksHmacTest, HksHmacTest011, TestSize.Level0)
{
    HKS_LOG_E("Enter HksHmacTest011");
    char tmpKeyAlias[] = "HksHMACKeyAliasTest011";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams008, sizeof(g_genParams008) / sizeof(HksParam));

    struct HksParamSet *hmacParamSet = nullptr;
    ret = InitParamSet(&hmacParamSet, g_hmacParams008, sizeof(g_hmacParams008) / sizeof(HksParam));

    ret = HksHmacTestCase(&keyAlias, genParamSet, hmacParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hmacParamSet);
}
#endif
} // namespace Unittest::Hmac