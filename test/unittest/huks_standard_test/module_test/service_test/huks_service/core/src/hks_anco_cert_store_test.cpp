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
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <string>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type_inner.h"
#include "hks_anco_inject.h"
#include "hks_cert_chain_store.h"

using namespace testing::ext;

namespace Unittest::HksAncoCertStoreTest {

static constexpr uint32_t TEST_UID = 999900;
static constexpr uint32_t TEST_UID_B = 999901;

class HksAncoCertStoreTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksAncoCertStoreTest::SetUpTestCase(void) {}

void HksAncoCertStoreTest::TearDownTestCase(void) {}

void HksAncoCertStoreTest::SetUp()
{
    // 清理可能残留的测试目录
    std::string cmd = "rm -rf /data/service/el1/public/huks_service/certchain/" + std::to_string(TEST_UID);
    std::system(cmd.c_str());
    cmd = "rm -rf /data/service/el1/public/huks_service/certchain/" + std::to_string(TEST_UID_B);
    std::system(cmd.c_str());
    cmd = "rm -rf /data/service/el1/public/huks_service/attest_challenge/" + std::to_string(TEST_UID);
    std::system(cmd.c_str());
}

void HksAncoCertStoreTest::TearDown()
{
    // 测试后清理
    std::string cmd = "rm -rf /data/service/el1/public/huks_service/certchain/" + std::to_string(TEST_UID);
    std::system(cmd.c_str());
    cmd = "rm -rf /data/service/el1/public/huks_service/certchain/" + std::to_string(TEST_UID_B);
    std::system(cmd.c_str());
    cmd = "rm -rf /data/service/el1/public/huks_service/attest_challenge/" + std::to_string(TEST_UID);
    std::system(cmd.c_str());
}

// ===================== HksIsAncoBrokerCall 分支 =====================

/**
 * @tc.name: HksAncoCertStoreTest.HksIsAncoBrokerCall_NullParamSet
 * @tc.desc: paramSet 为 NULL, 返回 false
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, HksIsAncoBrokerCall_NullParamSet, TestSize.Level0)
{
    EXPECT_FALSE(HksIsAncoBrokerCall(NULL));
}

/**
 * @tc.name: HksAncoCertStoreTest.HksIsAncoBrokerCall_NoAncoUid
 * @tc.desc: paramSet 无 HKS_TAG_ANCO_APP_UID, 返回 false
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, HksIsAncoBrokerCall_NoAncoUid, TestSize.Level0)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam p = { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA };
    ret = HksAddParams(paramSet, &p, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    EXPECT_FALSE(HksIsAncoBrokerCall(paramSet));
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAncoCertStoreTest.HksIsAncoBrokerCall_HasAncoUid
 * @tc.desc: paramSet 含 HKS_TAG_ANCO_APP_UID, 返回 true
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, HksIsAncoBrokerCall_HasAncoUid, TestSize.Level0)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    uint8_t uidData[4] = {0x55, 0x15, 0x00, 0x00}; // uid = 0x1555 = 5461
    struct HksParam p = {
        .tag = HKS_TAG_ANCO_APP_UID,
        .blob = { sizeof(uint32_t), uidData }
    };
    ret = HksAddParams(paramSet, &p, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    EXPECT_TRUE(HksIsAncoBrokerCall(paramSet));
    HksFreeParamSet(&paramSet);
}

// ===================== HksInjectCertTypeForAncoBroker 分支 =====================

/**
 * @tc.name: HksAncoCertStoreTest.InjectCertType_NullNewParamSet
 * @tc.desc: newParamSet 为 NULL, 返回 HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, InjectCertType_NullNewParamSet, TestSize.Level0)
{
    struct HksParamSet *orig = NULL;
    int32_t ret = HksInitParamSet(&orig);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&orig);
    ASSERT_EQ(ret, HKS_SUCCESS);

    EXPECT_EQ(HksInjectCertTypeForAncoBroker(NULL, orig), HKS_ERROR_NULL_POINTER);
    HksFreeParamSet(&orig);
}

/**
 * @tc.name: HksAncoCertStoreTest.InjectCertType_NonBroker_Skip
 * @tc.desc: origParamSet 非 broker(无 ANCO_APP_UID), 返回 SUCCESS 不注入
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, InjectCertType_NonBroker_Skip, TestSize.Level0)
{
    struct HksParamSet *newPs = NULL;
    int32_t ret = HksInitParamSet(&newPs);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *orig = NULL;
    ret = HksInitParamSet(&orig);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&orig);
    ASSERT_EQ(ret, HKS_SUCCESS);

    // 非 broker, 返回 SUCCESS
    EXPECT_EQ(HksInjectCertTypeForAncoBroker(newPs, orig), HKS_SUCCESS);

    // build 后确认无 CERT_TYPE
    ret = HksBuildParamSet(&newPs);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam *certType = NULL;
    EXPECT_NE(HksGetParam(newPs, HKS_TAG_ATTESTATION_CERT_TYPE, &certType), HKS_SUCCESS);

    HksFreeParamSet(&newPs);
    HksFreeParamSet(&orig);
}

/**
 * @tc.name: HksAncoCertStoreTest.InjectCertType_Broker_InjectRsa
 * @tc.desc: origParamSet 是 broker(有 ANCO_APP_UID), 注入 CERT_TYPE=RSA
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, InjectCertType_Broker_InjectRsa, TestSize.Level0)
{
    struct HksParamSet *newPs = NULL;
    int32_t ret = HksInitParamSet(&newPs);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *orig = NULL;
    ret = HksInitParamSet(&orig);
    ASSERT_EQ(ret, HKS_SUCCESS);
    uint8_t uidData[4] = {0x55, 0x15, 0x00, 0x00};
    struct HksParam ancoUid = {
        .tag = HKS_TAG_ANCO_APP_UID,
        .blob = { sizeof(uint32_t), uidData }
    };
    ret = HksAddParams(orig, &ancoUid, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&orig);
    ASSERT_EQ(ret, HKS_SUCCESS);

    // broker, 注入 CERT_TYPE
    EXPECT_EQ(HksInjectCertTypeForAncoBroker(newPs, orig), HKS_SUCCESS);

    ret = HksBuildParamSet(&newPs);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam *certType = NULL;
    EXPECT_EQ(HksGetParam(newPs, HKS_TAG_ATTESTATION_CERT_TYPE, &certType), HKS_SUCCESS);
    EXPECT_EQ(certType->uint32Param, HKS_ATTESTATION_CERT_TYPE_RSA);

    HksFreeParamSet(&newPs);
    HksFreeParamSet(&orig);
}

// ===================== HksCertChainStoreSave / Load / Contains / Remove 往返 =====================

/**
 * @tc.name: HksAncoCertStoreTest.SaveLoad_RoundTrip
 * @tc.desc: Save 后 Load 读回内容一致
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, SaveLoad_RoundTrip, TestSize.Level0)
{
    const char *alias = "CERTCHAIN_roundtrip_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    uint8_t certData[] = {0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD};
    struct HksBlob certChain = { sizeof(certData), certData };

    int32_t ret = HksCertChainStoreSave(TEST_UID, &keyAlias, &certChain);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob loaded = { 0, NULL };
    ret = HksCertChainStoreLoadCertChain(TEST_UID, &keyAlias, &loaded);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(loaded.data, nullptr);
    EXPECT_EQ(loaded.size, sizeof(certData));
    EXPECT_EQ(memcmp(loaded.data, certData, sizeof(certData)), 0);
    HKS_FREE_BLOB(loaded);
}

/**
 * @tc.name: HksAncoCertStoreTest.Load_NotExist
 * @tc.desc: 未 Save 的 alias, Load 返回 HKS_ERROR_NOT_EXIST
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, Load_NotExist, TestSize.Level0)
{
    const char *alias = "CERTCHAIN_notexist_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    struct HksBlob loaded = { 0, NULL };
    int32_t ret = HksCertChainStoreLoadCertChain(TEST_UID, &keyAlias, &loaded);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST);
    EXPECT_EQ(loaded.data, nullptr);
}

/**
 * @tc.name: HksAncoCertStoreTest.Contains_NotExist
 * @tc.desc: 未 Save 的 alias, Contains 返回 false
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, Contains_NotExist, TestSize.Level0)
{
    const char *alias = "CERTCHAIN_contains_notexist";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    EXPECT_FALSE(HksCertChainStoreContains(TEST_UID, &keyAlias));
}

/**
 * @tc.name: HksAncoCertStoreTest.Save_InvalidArgs
 * @tc.desc: NULL keyAlias/certChain 或空 certChain 返回 HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, Save_InvalidArgs, TestSize.Level0)
{
    uint8_t certData[] = {0x01};
    struct HksBlob certChain = { sizeof(certData), certData };
    EXPECT_EQ(HksCertChainStoreSave(TEST_UID, NULL, &certChain), HKS_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(HksCertChainStoreSave(TEST_UID, nullptr, &certChain), HKS_ERROR_INVALID_ARGUMENT);

    const char *alias = "CERTCHAIN_invalid_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    EXPECT_EQ(HksCertChainStoreSave(TEST_UID, &keyAlias, NULL), HKS_ERROR_INVALID_ARGUMENT);

    struct HksBlob emptyChain = { 0, certData };
    EXPECT_EQ(HksCertChainStoreSave(TEST_UID, &keyAlias, &emptyChain), HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksAncoCertStoreTest.Save_Overwrite
 * @tc.desc: 同 alias 两次 Save 不同内容, Load 读回最新内容
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, Save_Overwrite, TestSize.Level0)
{
    const char *alias = "CERTCHAIN_overwrite_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    uint8_t data1[] = {0xAA, 0xBB};
    struct HksBlob chain1 = { sizeof(data1), data1 };
    EXPECT_EQ(HksCertChainStoreSave(TEST_UID, &keyAlias, &chain1), HKS_SUCCESS);

    uint8_t data2[] = {0xCC, 0xDD, 0xEE, 0xFF};
    struct HksBlob chain2 = { sizeof(data2), data2 };
    EXPECT_EQ(HksCertChainStoreSave(TEST_UID, &keyAlias, &chain2), HKS_SUCCESS);

    struct HksBlob loaded = { 0, NULL };
    EXPECT_EQ(HksCertChainStoreLoadCertChain(TEST_UID, &keyAlias, &loaded), HKS_SUCCESS);
    EXPECT_EQ(loaded.size, sizeof(data2));
    EXPECT_EQ(memcmp(loaded.data, data2, sizeof(data2)), 0);
    HKS_FREE_BLOB(loaded);
}

/**
 * @tc.name: HksAncoCertStoreTest.DifferentUid_Isolated
 * @tc.desc: 不同 uid 的证书互不干扰
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, DifferentUid_Isolated, TestSize.Level0)
{
    const char *alias = "CERTCHAIN_uid_iso_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    uint8_t dataA[] = {0x0A};
    struct HksBlob chainA = { sizeof(dataA), dataA };
    EXPECT_EQ(HksCertChainStoreSave(TEST_UID, &keyAlias, &chainA), HKS_SUCCESS);

    uint8_t dataB[] = {0x0B, 0x0B};
    struct HksBlob chainB = { sizeof(dataB), dataB };
    EXPECT_EQ(HksCertChainStoreSave(TEST_UID_B, &keyAlias, &chainB), HKS_SUCCESS);

    struct HksBlob loadedA = { 0, NULL };
    EXPECT_EQ(HksCertChainStoreLoadCertChain(TEST_UID, &keyAlias, &loadedA), HKS_SUCCESS);
    EXPECT_EQ(loadedA.size, sizeof(dataA));
    EXPECT_EQ(loadedA.data[0], dataA[0]);
    HKS_FREE_BLOB(loadedA);

    struct HksBlob loadedB = { 0, NULL };
    EXPECT_EQ(HksCertChainStoreLoadCertChain(TEST_UID_B, &keyAlias, &loadedB), HKS_SUCCESS);
    EXPECT_EQ(loadedB.size, sizeof(dataB));
    HKS_FREE_BLOB(loadedB);
}

// ===================== HksCertChainStoreOnAttestSuccess 分支 =====================

/**
 * @tc.name: HksAncoCertStoreTest.OnAttestSuccess_AnonMode_SkipStore
 * @tc.desc: 匿名 mode (ANONYMOUS), 不落盘, Contains 返回 false
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, OnAttestSuccess_AnonMode_SkipStore, TestSize.Level0)
{
    const char *alias = "CERTCHAIN_anon_skip_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam params[] = {
        { .tag = HKS_TAG_ATTESTATION_MODE, .uint32Param = HKS_ATTESTATION_MODE_ANONYMOUS }
    };
    ret = HksAddParams(paramSet, params, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t certData[] = {0x30, 0x82};
    struct HksBlob certChain = { sizeof(certData), certData };

    HksCertChainStoreOnAttestSuccess(TEST_UID, &keyAlias, paramSet, &certChain);
    // 匿名 mode 不落盘
    EXPECT_FALSE(HksCertChainStoreContains(TEST_UID, &keyAlias));

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAncoCertStoreTest.OnAttestSuccess_AnonCompatMode_SkipStore
 * @tc.desc: 匿名 compat mode (ANONYMOUS_COMPAT), 不落盘
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, OnAttestSuccess_AnonCompatMode_SkipStore, TestSize.Level0)
{
    const char *alias = "CERTCHAIN_anoncompat_skip_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam params[] = {
        { .tag = HKS_TAG_ATTESTATION_MODE, .uint32Param = HKS_ATTESTATION_MODE_ANONYMOUS_COMPAT }
    };
    ret = HksAddParams(paramSet, params, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t certData[] = {0x30, 0x82};
    struct HksBlob certChain = { sizeof(certData), certData };

    HksCertChainStoreOnAttestSuccess(TEST_UID, &keyAlias, paramSet, &certChain);
    EXPECT_FALSE(HksCertChainStoreContains(TEST_UID, &keyAlias));

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAncoCertStoreTest.OnAttestSuccess_DefaultMode_Store
 * @tc.desc: 默认 mode (DEFAULT), 落盘, Contains 返回 true
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, OnAttestSuccess_DefaultMode_Store, TestSize.Level0)
{
    const char *alias = "CERTCHAIN_default_store_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam params[] = {
        { .tag = HKS_TAG_ATTESTATION_MODE, .uint32Param = HKS_ATTESTATION_MODE_DEFAULT },
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = { 4, (uint8_t *)"abcd" } }
    };
    ret = HksAddParams(paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t certData[] = {0x30, 0x82, 0x01, 0x00, 0xAA};
    struct HksBlob certChain = { sizeof(certData), certData };

    HksCertChainStoreOnAttestSuccess(TEST_UID, &keyAlias, paramSet, &certChain);
    EXPECT_TRUE(HksCertChainStoreContains(TEST_UID, &keyAlias));

    // 验证内容一致
    struct HksBlob loaded = { 0, NULL };
    EXPECT_EQ(HksCertChainStoreLoadCertChain(TEST_UID, &keyAlias, &loaded), HKS_SUCCESS);
    EXPECT_EQ(loaded.size, sizeof(certData));
    EXPECT_EQ(memcmp(loaded.data, certData, sizeof(certData)), 0);
    HKS_FREE_BLOB(loaded);

    // challenge 也落盘了
    struct HksBlob loadedChallenge = { 0, NULL };
    EXPECT_EQ(HksCertChainStoreLoadChallenge(TEST_UID, &keyAlias, &loadedChallenge), HKS_SUCCESS);
    EXPECT_EQ(loadedChallenge.size, 4);
    HKS_FREE_BLOB(loadedChallenge);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAncoCertStoreTest.OnAttestSuccess_NoModeTag_Store
 * @tc.desc: 无 MODE tag (默认非匿名), 落盘
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, OnAttestSuccess_NoModeTag_Store, TestSize.Level0)
{
    const char *alias = "CERTCHAIN_nomode_store_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    // 只有 challenge, 无 MODE tag → IsAnonymousAttestMode 返回 false
    struct HksParam params[] = {
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = { 4, (uint8_t *)"xyzw" } }
    };
    ret = HksAddParams(paramSet, params, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t certData[] = {0x30};
    struct HksBlob certChain = { sizeof(certData), certData };

    HksCertChainStoreOnAttestSuccess(TEST_UID, &keyAlias, paramSet, &certChain);
    EXPECT_TRUE(HksCertChainStoreContains(TEST_UID, &keyAlias));

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAncoCertStoreTest.OnAttestSuccess_NoChallenge_SkipChallengeStore
 * @tc.desc: 默认 mode 但无 challenge tag, certChain 仍落盘, challenge 不落盘
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, OnAttestSuccess_NoChallenge_SkipChallengeStore, TestSize.Level0)
{
    const char *alias = "CERTCHAIN_nochallenge_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    // 无 challenge tag
    struct HksParam params[] = {
        { .tag = HKS_TAG_ATTESTATION_MODE, .uint32Param = HKS_ATTESTATION_MODE_DEFAULT }
    };
    ret = HksAddParams(paramSet, params, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t certData[] = {0x30, 0x82, 0x01};
    struct HksBlob certChain = { sizeof(certData), certData };

    HksCertChainStoreOnAttestSuccess(TEST_UID, &keyAlias, paramSet, &certChain);
    // certChain 落盘了
    EXPECT_TRUE(HksCertChainStoreContains(TEST_UID, &keyAlias));
    // challenge 未落盘
    struct HksBlob loadedChallenge = { 0, NULL };
    EXPECT_NE(HksCertChainStoreLoadChallenge(TEST_UID, &keyAlias, &loadedChallenge), HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAncoCertStoreTest.OnAttestSuccess_NullParams_Skip
 * @tc.desc: NULL 参数, 静默跳过不崩溃
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, OnAttestSuccess_NullParams_Skip, TestSize.Level0)
{
    const char *alias = "CERTCHAIN_null_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    uint8_t certData[] = {0x30};
    struct HksBlob certChain = { sizeof(certData), certData };

    // 各种 NULL 组合, 不应崩溃
    HksCertChainStoreOnAttestSuccess(TEST_UID, NULL, NULL, NULL);
    HksCertChainStoreOnAttestSuccess(TEST_UID, &keyAlias, NULL, &certChain);
    HksCertChainStoreOnAttestSuccess(TEST_UID, &keyAlias, (struct HksParamSet *)1, NULL);

    // 空 certChain 也跳过
    struct HksBlob emptyChain = { 0, certData };
    struct HksParamSet *paramSet = NULL;
    HksInitParamSet(&paramSet);
    HksBuildParamSet(&paramSet);
    HksCertChainStoreOnAttestSuccess(TEST_UID, &keyAlias, paramSet, &emptyChain);
    EXPECT_FALSE(HksCertChainStoreContains(TEST_UID, &keyAlias));
    HksFreeParamSet(&paramSet);
}

// ===================== BuildCertChainAlias 间接分支(通过 OnAttestSuccess) =====================

/**
 * @tc.name: HksAncoCertStoreTest.OnAttestSuccess_UsrCertPrefix_KeptAsIs
 * @tc.desc: USRCERT_ 前缀原样落盘, Load 时用 USRCERT_ 前缀能读到
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, OnAttestSuccess_UsrCertPrefix_KeptAsIs, TestSize.Level0)
{
    const char *alias = "USRCERT_prefix_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam params[] = {
        { .tag = HKS_TAG_ATTESTATION_MODE, .uint32Param = HKS_ATTESTATION_MODE_DEFAULT }
    };
    ret = HksAddParams(paramSet, params, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t certData[] = {0x30, 0x82};
    struct HksBlob certChain = { sizeof(certData), certData };

    HksCertChainStoreOnAttestSuccess(TEST_UID, &keyAlias, paramSet, &certChain);
    // USRCERT_ 前缀原样保留, Contains 用原 alias 能查到
    EXPECT_TRUE(HksCertChainStoreContains(TEST_UID, &keyAlias));

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAncoCertStoreTest.OnAttestSuccess_UsrPkeyPrefix_Replaced
 * @tc.desc: USRPKEY_ 前缀被替换为 CERTCHAIN_, Contains 用原 alias 查不到(需用 CERTCHAIN_ 查)
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, OnAttestSuccess_UsrPkeyPrefix_Replaced, TestSize.Level0)
{
    const char *alias = "USRPKEY_prefix_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam params[] = {
        { .tag = HKS_TAG_ATTESTATION_MODE, .uint32Param = HKS_ATTESTATION_MODE_DEFAULT }
    };
    ret = HksAddParams(paramSet, params, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t certData[] = {0x30, 0x82};
    struct HksBlob certChain = { sizeof(certData), certData };

    HksCertChainStoreOnAttestSuccess(TEST_UID, &keyAlias, paramSet, &certChain);
    // USRPKEY_ 被替换成 CERTCHAIN_, 用原 USRPKEY_ alias 查不到
    EXPECT_FALSE(HksCertChainStoreContains(TEST_UID, &keyAlias));
    // 用 CERTCHAIN_prefix_test 能查到
    const char *certAlias = "CERTCHAIN_prefix_test";
    struct HksBlob certKeyAlias = { strlen(certAlias), (uint8_t *)certAlias };
    EXPECT_TRUE(HksCertChainStoreContains(TEST_UID, &certKeyAlias));

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAncoCertStoreTest.OnAttestSuccess_CaCertPrefix_KeptAsIs
 * @tc.desc: CACERT_ 前缀原样落盘
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, OnAttestSuccess_CaCertPrefix_KeptAsIs, TestSize.Level0)
{
    const char *alias = "CACERT_prefix_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam params[] = {
        { .tag = HKS_TAG_ATTESTATION_MODE, .uint32Param = HKS_ATTESTATION_MODE_DEFAULT }
    };
    ret = HksAddParams(paramSet, params, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t certData[] = {0x30, 0x82};
    struct HksBlob certChain = { sizeof(certData), certData };

    HksCertChainStoreOnAttestSuccess(TEST_UID, &keyAlias, paramSet, &certChain);
    EXPECT_TRUE(HksCertChainStoreContains(TEST_UID, &keyAlias));

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAncoCertStoreTest.OnAttestSuccess_NoPrefix_AddCertChain
 * @tc.desc: 无前缀的裸 alias, 自动加 CERTCHAIN_ 前缀
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, OnAttestSuccess_NoPrefix_AddCertChain, TestSize.Level0)
{
    const char *alias = "plain_alias_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam params[] = {
        { .tag = HKS_TAG_ATTESTATION_MODE, .uint32Param = HKS_ATTESTATION_MODE_DEFAULT }
    };
    ret = HksAddParams(paramSet, params, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t certData[] = {0x30, 0x82};
    struct HksBlob certChain = { sizeof(certData), certData };

    HksCertChainStoreOnAttestSuccess(TEST_UID, &keyAlias, paramSet, &certChain);
    // 裸 alias 被加 CERTCHAIN_ 前缀, 用原 alias 查不到
    EXPECT_FALSE(HksCertChainStoreContains(TEST_UID, &keyAlias));
    // 用 CERTCHAIN_plain_alias_test 能查到
    const char *certAlias = "CERTCHAIN_plain_alias_test";
    struct HksBlob certKeyAlias = { strlen(certAlias), (uint8_t *)certAlias };
    EXPECT_TRUE(HksCertChainStoreContains(TEST_UID, &certKeyAlias));

    HksFreeParamSet(&paramSet);
}

// ===================== HksCertChainStoreRemove 分支 =====================

/**
 * @tc.name: HksAncoCertStoreTest.Remove_UsrPkeyPrefix_RewritesAlias
 * @tc.desc: USRPKEY_ 前缀 Remove 时先转 CERTCHAIN_ 再删
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, Remove_UsrPkeyPrefix_RewritesAlias, TestSize.Level0)
{
    // 先用 OnAttestSuccess 存一个 USRPKEY_ alias(会被转成 CERTCHAIN_)
    const char *alias = "USRPKEY_remove_test";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam params[] = {
        { .tag = HKS_TAG_ATTESTATION_MODE, .uint32Param = HKS_ATTESTATION_MODE_DEFAULT }
    };
    ret = HksAddParams(paramSet, params, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t certData[] = {0x30};
    struct HksBlob certChain = { sizeof(certData), certData };
    HksCertChainStoreOnAttestSuccess(TEST_UID, &keyAlias, paramSet, &certChain);

    // 确认 CERTCHAIN_remove_test 存在
    const char *certAlias = "CERTCHAIN_remove_test";
    struct HksBlob certKeyAlias = { strlen(certAlias), (uint8_t *)certAlias };
    EXPECT_TRUE(HksCertChainStoreContains(TEST_UID, &certKeyAlias));

    // 用 USRPKEY_ alias 删除(内部会转 CERTCHAIN_ 再删)
    HksCertChainStoreRemove(TEST_UID, &keyAlias);
    EXPECT_FALSE(HksCertChainStoreContains(TEST_UID, &certKeyAlias));

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAncoCertStoreTest.Remove_NullAlias_Noop
 * @tc.desc: NULL keyAlias, 静默不崩溃
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, Remove_NullAlias_Noop, TestSize.Level0)
{
    HksCertChainStoreRemove(TEST_UID, NULL);
    // 不崩溃即通过
    SUCCEED();
}

/**
 * @tc.name: HksAncoCertStoreTest.LoadChallenge_NotExist
 * @tc.desc: 未落盘 challenge, Load 返回 HKS_ERROR_NOT_EXIST
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoCertStoreTest, LoadChallenge_NotExist, TestSize.Level0)
{
    const char *alias = "CERTCHAIN_challenge_notexist";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    struct HksBlob challenge = { 0, NULL };
    int32_t ret = HksCertChainStoreLoadChallenge(TEST_UID, &keyAlias, &challenge);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST);
}
} // namespace Unittest::HksAncoCertStoreTest