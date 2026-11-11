/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>
#include <unistd.h>

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_mock_common.h"
#include "hks_param.h"
#include "hks_test_adapt_for_de.h"
#include "hks_type.h"
#include "native_huks_api.h"
#include "native_huks_param.h"
#include "native_huks_type.h"

using namespace testing::ext;
namespace Unittest::HksAsyncAnonAttestKeyTest {
namespace {
const char g_alias[] = "HksAsyncAnonAttestKeyAlias";
static struct HksBlob g_keyAlias = { sizeof(g_alias) - 1, (uint8_t *)g_alias };

static struct HksBlob g_secInfo = { 6, (uint8_t *)"sec_v1" };
static struct HksBlob g_challenge = { 8, (uint8_t *)"challenge" };
static struct HksBlob g_version = { 5, (uint8_t *)"ver.1" };
} // namespace

/* per-request context passed as userData; the callback may run on an IPC thread so all
 * cross-thread observations go through atomics */
struct AsyncAttestCtx {
    std::atomic<uint32_t> callCount { 0 };
    std::atomic<int32_t> lastResult { -1 };
    std::atomic<uint32_t> lastCertCount { 0 };
    /* structural validity of the last delivered chain: every cert blob must be non-empty.
     * this covers the design's "valid cert chain" requirement to the extent a unit test
     * can without pulling in an X.509 parser; full parse/verify is exercised by the
     * dedicated attestation tests. */
    std::atomic<uint32_t> lastChainValid { 0 };
    /* presentation checks: certs delivered as base64(PEM) start with the PEM header; raw
     * (InnerAPI) delivery must not contain any PEM wrapper, and a raw DER cert starts
     * with 0x30 (ASN.1 SEQUENCE) */
    std::atomic<uint32_t> lastPemCount { 0 };
    std::atomic<uint32_t> lastFirstCertByte { 0 };
};

/* observations for requests that pass userData == NULL: Test007 verifies the callback still
 * fires, so the null-context invocations are counted globally */
static std::atomic<uint32_t> g_nullCtxCallCount { 0 };

static void AsyncAnonAttestCb(void *userData, int32_t result, const struct OH_Huks_CertChain *certChain)
{
    /* certChain is only valid during this callback: observe it, do not keep it */
    uint32_t certCount = (certChain == nullptr) ? 0 : certChain->certsCount;
    uint32_t chainValid = 0;
    uint32_t pemCount = 0;
    uint32_t firstCertByte = 0;
    if (certChain != nullptr && certChain->certs != nullptr && certCount > 0) {
        chainValid = 1;
        for (uint32_t i = 0; i < certCount; ++i) {
            if (certChain->certs[i].data == nullptr || certChain->certs[i].size == 0) {
                chainValid = 0;
                break;
            }
            if (certChain->certs[i].size >= strlen("-----BEGIN CERTIFICATE-----") &&
                memcmp(certChain->certs[i].data, "-----BEGIN CERTIFICATE-----",
                    strlen("-----BEGIN CERTIFICATE-----")) == 0) {
                pemCount++;
            }
        }
        firstCertByte = certChain->certs[0].data[0];
    }
    HKS_LOG_I("async anon attest cb: user %p result %" LOG_PUBLIC "d certs %" LOG_PUBLIC "u valid %"
        LOG_PUBLIC "u pem %" LOG_PUBLIC "u", userData, result, certCount, chainValid, pemCount);
    AsyncAttestCtx *ctx = static_cast<AsyncAttestCtx *>(userData);
    if (ctx != nullptr) {
        ctx->lastResult = result;
        ctx->lastCertCount = certCount;
        ctx->lastChainValid = chainValid;
        ctx->lastPemCount = pemCount;
        ctx->lastFirstCertByte = firstCertByte;
        ctx->callCount++;
    } else {
        g_nullCtxCallCount++;
    }
}

/* InnerAPI raw-mode counterpart of AsyncAnonAttestCb: HksCertChain and OH_Huks_CertChain
 * are distinct published types with identical layout, so the observation is duplicated */
static void AsyncAnonAttestCbInner(void *userData, int32_t result, const struct HksCertChain *certChain)
{
    uint32_t certCount = (certChain == nullptr) ? 0 : certChain->certsCount;
    uint32_t chainValid = 0;
    uint32_t pemCount = 0;
    uint32_t firstCertByte = 0;
    if (certChain != nullptr && certChain->certs != nullptr && certCount > 0) {
        chainValid = 1;
        for (uint32_t i = 0; i < certCount; ++i) {
            if (certChain->certs[i].data == nullptr || certChain->certs[i].size == 0) {
                chainValid = 0;
                break;
            }
            if (certChain->certs[i].size >= strlen("-----BEGIN CERTIFICATE-----") &&
                memcmp(certChain->certs[i].data, "-----BEGIN CERTIFICATE-----",
                    strlen("-----BEGIN CERTIFICATE-----")) == 0) {
                pemCount++;
            }
        }
        firstCertByte = certChain->certs[0].data[0];
    }
    HKS_LOG_I("async anon attest cb(inner): user %p result %" LOG_PUBLIC "d certs %" LOG_PUBLIC "u valid %"
        LOG_PUBLIC "u pem %" LOG_PUBLIC "u", userData, result, certCount, chainValid, pemCount);
    AsyncAttestCtx *ctx = static_cast<AsyncAttestCtx *>(userData);
    if (ctx != nullptr) {
        ctx->lastResult = result;
        ctx->lastCertCount = certCount;
        ctx->lastChainValid = chainValid;
        ctx->lastPemCount = pemCount;
        ctx->lastFirstCertByte = firstCertByte;
        ctx->callCount++;
    } else {
        g_nullCtxCallCount++;
    }
}

/* Wait for the async callback and assert the unified delivery contract on every environment:
 * the service always delivers the chain through the stub's async reply (HKS_MSG_-
 * ATTEST_KEY_ASYNC_REPLY one-way). The software-level SA sends it while handling the
 * admission (the engine attests inline), the TEE-level SA sends it once the DCM
 * networking completes - the client no longer distinguishes the two. Either way the
 * callback must:
 *   - fire exactly once,
 *   - report success (result == 0),
 *   - carry a non-empty, structurally valid cert chain. */
static void WaitAndAssertAsyncCallback(AsyncAttestCtx &ctx, uint32_t timeoutMs)
{
    /* the callback may already have fired during admission (software) or may take seconds
     * (TEE networking): poll until it is observed or the timeout expires */
    constexpr uint32_t pollMs = 100;
    for (uint32_t waited = 0; ctx.callCount.load() == 0 && waited < timeoutMs; waited += pollMs) {
        std::this_thread::sleep_for(std::chrono::milliseconds(pollMs));
    }
    uint32_t calls = ctx.callCount.load();
    HKS_LOG_I("callback observed %" LOG_PUBLIC "u times, last result %" LOG_PUBLIC "d certs %" LOG_PUBLIC "u valid %"
        LOG_PUBLIC "u", calls, ctx.lastResult.load(), ctx.lastCertCount.load(), ctx.lastChainValid.load());
    EXPECT_GT(calls, 0u);
    EXPECT_EQ(calls, 1u);
    EXPECT_EQ(ctx.lastResult.load(), 0);
    EXPECT_GT(ctx.lastCertCount.load(), 0u);
    EXPECT_EQ(ctx.lastChainValid.load(), 1u);
}

class HksAsyncAnonAttestKeyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

static uint64_t g_shellTokenId = 0;
void HksAsyncAnonAttestKeyTest::SetUpTestCase(void)
{
    g_shellTokenId = GetSelfTokenID();
    HksMockCommon::SetTestEvironment(g_shellTokenId);
}

void HksAsyncAnonAttestKeyTest::TearDownTestCase(void)
{
    SetSelfTokenID(g_shellTokenId);
    HksMockCommon::ResetTestEvironment();
}

void HksAsyncAnonAttestKeyTest::SetUp()
{
}

void HksAsyncAnonAttestKeyTest::TearDown()
{
}

/* standard anon attest params (same tag set as the sync anon attest tests). the DE storage
 * level is required because the key is generated through the *ForDe adapter */
static int32_t GenAttestParamSet(struct HksParamSet **paramSet)
{
    struct HksParam params[] = {
        { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = g_challenge },
        { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = g_version },
        { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = g_keyAlias },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    };
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    ret = HksAddParams(*paramSet, params, sizeof(params) / sizeof(params[0]));
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(paramSet);
        return ret;
    }
    return HksBuildParamSet(paramSet);
}

static int32_t TestGenerateKey(const struct HksBlob *keyAlias){
    struct HksParam params[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    if (ret == HKS_SUCCESS) {
        ret = HksAddParams(paramSet, params, sizeof(params) / sizeof(params[0]));
    }
    if (ret == HKS_SUCCESS) {
        ret = HksBuildParamSet(&paramSet);
    }
    if (ret == HKS_SUCCESS) {
        ret = HksGenerateKeyForDe(keyAlias, paramSet, nullptr);
    }
    HksFreeParamSet(&paramSet);
    return ret;
}

static struct HksCertChain *ConstructSyncCertChain(void)
{
    uint32_t certSizes[HKS_CERT_COUNT] = {
        HKS_CERT_ROOT_SIZE, HKS_CERT_CA_SIZE, HKS_CERT_DEVICE_SIZE, HKS_CERT_APP_SIZE
    };
    struct HksCertChain *chain = static_cast<struct HksCertChain *>(HksMalloc(sizeof(struct HksCertChain)));
    if (chain == nullptr) {
        return nullptr;
    }
    chain->certsCount = HKS_CERT_COUNT;
    chain->certs = static_cast<struct HksBlob *>(HksMalloc(sizeof(struct HksBlob) * HKS_CERT_COUNT));
    if (chain->certs == nullptr) {
        HksFreeImpl(chain);
        return nullptr;
    }
    for (uint32_t i = 0; i < HKS_CERT_COUNT; ++i) {
        chain->certs[i].size = certSizes[i];
        chain->certs[i].data = static_cast<uint8_t *>(HksMalloc(certSizes[i]));
        if (chain->certs[i].data == nullptr) {
            for (uint32_t j = 0; j < i; ++j) {
                HksFreeImpl(chain->certs[j].data);
            }
            HksFreeImpl(chain->certs);
            HksFreeImpl(chain);
            return nullptr;
        }
    }
    return chain;
}

static void FreeSyncCertChain(struct HksCertChain **certChain)
{
    if (certChain == nullptr || *certChain == nullptr) {
        return;
    }
    if ((*certChain)->certs != nullptr) {
        for (uint32_t i = 0; i < (*certChain)->certsCount; ++i) {
            HksFreeImpl((*certChain)->certs[i].data);
        }
        HksFreeImpl((*certChain)->certs);
    }
    HksFreeImpl(*certChain);
    *certChain = nullptr;
}

/**
 * @tc.name: HksAsyncAnonAttestKeyTest.HksAsyncAnonAttestKeyTest001
 * @tc.desc: callback is NULL, expect OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT (401) and no crash.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncAnonAttestKeyTest, HksAsyncAnonAttestKeyTest001, TestSize.Level0)
{
    struct OH_Huks_ParamSet *paramSet = nullptr;
    ASSERT_EQ(OH_Huks_InitParamSet(&paramSet).errorCode, OH_HUKS_SUCCESS);
    struct OH_Huks_Param p = { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob =
        { g_challenge.size, g_challenge.data } };
    ASSERT_EQ(OH_Huks_AddParams(paramSet, &p, 1).errorCode, OH_HUKS_SUCCESS);
    ASSERT_EQ(OH_Huks_BuildParamSet(&paramSet).errorCode, OH_HUKS_SUCCESS);

    struct OH_Huks_Blob alias = { g_keyAlias.size, g_keyAlias.data };
    struct OH_Huks_Result ret = OH_Huks_AsyncAnonAttestKeyItem(&alias, paramSet, nullptr, nullptr);
    EXPECT_EQ(ret.errorCode, OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT);

    OH_Huks_FreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAsyncAnonAttestKeyTest.HksAsyncAnonAttestKeyTest002
 * @tc.desc: paramSet is NULL, expect OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT (401).
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncAnonAttestKeyTest, HksAsyncAnonAttestKeyTest002, TestSize.Level0)
{
    struct OH_Huks_Blob alias = { g_keyAlias.size, g_keyAlias.data };
    struct OH_Huks_Result ret = OH_Huks_AsyncAnonAttestKeyItem(&alias, nullptr, AsyncAnonAttestCb, nullptr);
    EXPECT_EQ(ret.errorCode, OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT);
}

/**
 * @tc.name: HksAsyncAnonAttestKeyTest.HksAsyncAnonAttestKeyTest003
 * @tc.desc: keyAlias is NULL, expect OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT (401).
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncAnonAttestKeyTest, HksAsyncAnonAttestKeyTest003, TestSize.Level0)
{
    struct OH_Huks_ParamSet *paramSet = nullptr;
    ASSERT_EQ(OH_Huks_InitParamSet(&paramSet).errorCode, OH_HUKS_SUCCESS);
    ASSERT_EQ(OH_Huks_BuildParamSet(&paramSet).errorCode, OH_HUKS_SUCCESS);

    struct OH_Huks_Result ret = OH_Huks_AsyncAnonAttestKeyItem(nullptr, paramSet, AsyncAnonAttestCb, nullptr);
    EXPECT_EQ(ret.errorCode, OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT);

    OH_Huks_FreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAsyncAnonAttestKeyTest.HksAsyncAnonAttestKeyTest004
 * @tc.desc: paramSet is corrupted (invalid size), expect OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT (401).
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncAnonAttestKeyTest, HksAsyncAnonAttestKeyTest004, TestSize.Level0)
{
    struct OH_Huks_ParamSet *paramSet = nullptr;
    ASSERT_EQ(OH_Huks_InitParamSet(&paramSet).errorCode, OH_HUKS_SUCCESS);
    struct OH_Huks_Param p = { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob =
        { g_challenge.size, g_challenge.data } };
    ASSERT_EQ(OH_Huks_AddParams(paramSet, &p, 1).errorCode, OH_HUKS_SUCCESS);
    ASSERT_EQ(OH_Huks_BuildParamSet(&paramSet).errorCode, OH_HUKS_SUCCESS);

    /* corrupt the size field so the inner param set check fails */
    paramSet->paramSetSize = sizeof(struct HksParamSet) - 1;
    struct OH_Huks_Blob alias = { g_keyAlias.size, g_keyAlias.data };
    struct OH_Huks_Result ret = OH_Huks_AsyncAnonAttestKeyItem(&alias, paramSet, AsyncAnonAttestCb, nullptr);
    EXPECT_EQ(ret.errorCode, OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT);

    paramSet->paramSetSize = 0; /* free with a sane header */
    OH_Huks_FreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAsyncAnonAttestKeyTest.HksAsyncAnonAttestKeyTest005
 * @tc.desc: key does not exist, admission must fail with OH_HUKS_ERR_CODE_ITEM_NOT_EXIST
 *   (12000011) and the callback must NOT be invoked (error => no callback contract).
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncAnonAttestKeyTest, HksAsyncAnonAttestKeyTest005, TestSize.Level0)
{
    HksMockNativeToken mock("asset_service");
    struct HksParamSet *paramSet = nullptr;
    ASSERT_EQ(GenAttestParamSet(&paramSet), HKS_SUCCESS);

    const char notExist[] = "HksAsyncAnonAttestNotExistKey";
    struct OH_Huks_Blob alias = { sizeof(notExist) - 1, (uint8_t *)notExist };
    AsyncAttestCtx ctx;
    struct OH_Huks_Result ret = OH_Huks_AsyncAnonAttestKeyItem(&alias,
        (const struct OH_Huks_ParamSet *)paramSet, AsyncAnonAttestCb, &ctx);
    EXPECT_EQ(ret.errorCode, OH_HUKS_ERR_CODE_ITEM_NOT_EXIST);

    /* admission failed: the callback must never fire */
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_EQ(ctx.callCount.load(), 0u);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksAsyncAnonAttestKeyTest.HksAsyncAnonAttestKeyTest006
 * @tc.desc: normal flow, admission must succeed (OH_HUKS_SUCCESS) and return quickly
 *   (the calling thread is not blocked on the attestation itself). The callback must fire
 *   once with success errcode and a valid, base64(PEM)-encoded cert chain on every
 *   environment: the delivery always arrives through the stub's async reply (the NDK entry
 *   sets the base64 tag), sent by the software SA inline with the admission or by the TEE
 *   SA after the DCM networking - identical interface behavior either way.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncAnonAttestKeyTest, HksAsyncAnonAttestKeyTest006, TestSize.Level0)
{
    HksMockNativeToken mock("asset_service");
    ASSERT_EQ(TestGenerateKey(&g_keyAlias), HKS_SUCCESS);
    struct HksParamSet *paramSet = nullptr;
    ASSERT_EQ(GenAttestParamSet(&paramSet), HKS_SUCCESS);

    AsyncAttestCtx ctx;
    struct OH_Huks_Blob alias = { g_keyAlias.size, g_keyAlias.data };
    auto begin = std::chrono::steady_clock::now();
    struct OH_Huks_Result ret = OH_Huks_AsyncAnonAttestKeyItem(&alias,
        (const struct OH_Huks_ParamSet *)paramSet, AsyncAnonAttestCb, &ctx);
    auto end = std::chrono::steady_clock::now();
    auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
    HKS_LOG_I("async anon attest admission cost %" LOG_PUBLIC "lld ms", static_cast<long long>(costMs));
    /* only the admission round trip is synchronous; it must be far below the 10s sync timeout */
    EXPECT_EQ(ret.errorCode, OH_HUKS_SUCCESS);
    EXPECT_LT(costMs, 5000);

    /* the callback must deliver the final result (success errcode + valid cert chain) on
     * both software-level and DCM-enabled devices */
    WaitAndAssertAsyncCallback(ctx, 10000);
    /* the NDK entry always attests with the base64 tag, so every delivered cert must be
     * PEM-wrapped through the real delivery path */
    EXPECT_EQ(ctx.lastPemCount.load(), ctx.lastCertCount.load());

    HksFreeParamSet(&paramSet);
    ASSERT_EQ(HksDeleteKeyForDe(&g_keyAlias, nullptr), HKS_SUCCESS);
}

/**
 * @tc.name: HksAsyncAnonAttestKeyTest.HksAsyncAnonAttestKeyTest007
 * @tc.desc: userData is NULL, admission must still succeed (userData is optional) and the
 *   callback must still be invoked once with the result and the cert chain.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncAnonAttestKeyTest, HksAsyncAnonAttestKeyTest007, TestSize.Level0)
{
    HksMockNativeToken mock("asset_service");
    ASSERT_EQ(TestGenerateKey(&g_keyAlias), HKS_SUCCESS);
    struct HksParamSet *paramSet = nullptr;
    ASSERT_EQ(GenAttestParamSet(&paramSet), HKS_SUCCESS);

    g_nullCtxCallCount = 0;
    struct OH_Huks_Blob alias = { g_keyAlias.size, g_keyAlias.data };
    struct OH_Huks_Result ret = OH_Huks_AsyncAnonAttestKeyItem(&alias,
        (const struct OH_Huks_ParamSet *)paramSet, AsyncAnonAttestCb, nullptr);
    EXPECT_EQ(ret.errorCode, OH_HUKS_SUCCESS);

    /* the callback must fire exactly once even with a NULL userData (the null-context
     * invocations are counted globally by the callback) */
    constexpr uint32_t pollMs = 100;
    for (uint32_t waited = 0; g_nullCtxCallCount.load() == 0 && waited < 10000; waited += pollMs) {
        std::this_thread::sleep_for(std::chrono::milliseconds(pollMs));
    }
    HKS_LOG_I("null ctx callback observed %" LOG_PUBLIC "u times", g_nullCtxCallCount.load());
    EXPECT_EQ(g_nullCtxCallCount.load(), 1u);

    HksFreeParamSet(&paramSet);
    ASSERT_EQ(HksDeleteKeyForDe(&g_keyAlias, nullptr), HKS_SUCCESS);
}

/**
 * @tc.name: HksAsyncAnonAttestKeyTest.HksAsyncAnonAttestKeyTest008
 * @tc.desc: two concurrent requests with distinct userData, both admitted independently;
 *   userData routing keeps the results distinguishable. Each request's callback must fire
 *   once with success errcode and a valid cert chain on every environment.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncAnonAttestKeyTest, HksAsyncAnonAttestKeyTest008, TestSize.Level0)
{
    HksMockNativeToken mock("asset_service");
    ASSERT_EQ(TestGenerateKey(&g_keyAlias), HKS_SUCCESS);
    struct HksParamSet *paramSet = nullptr;
    ASSERT_EQ(GenAttestParamSet(&paramSet), HKS_SUCCESS);

    AsyncAttestCtx ctx1;
    AsyncAttestCtx ctx2;
    struct OH_Huks_Blob alias = { g_keyAlias.size, g_keyAlias.data };
    std::thread t1([&alias, &paramSet, &ctx1]() {
        struct OH_Huks_Result ret = OH_Huks_AsyncAnonAttestKeyItem(&alias,
            (const struct OH_Huks_ParamSet *)paramSet, AsyncAnonAttestCb, &ctx1);
        EXPECT_EQ(ret.errorCode, OH_HUKS_SUCCESS);
    });
    std::thread t2([&alias, &paramSet, &ctx2]() {
        struct OH_Huks_Result ret = OH_Huks_AsyncAnonAttestKeyItem(&alias,
            (const struct OH_Huks_ParamSet *)paramSet, AsyncAnonAttestCb, &ctx2);
        EXPECT_EQ(ret.errorCode, OH_HUKS_SUCCESS);
    });
    t1.join();
    t2.join();

    /* each request must get its own callback with a valid cert chain, routed by its
     * distinct userData */
    WaitAndAssertAsyncCallback(ctx1, 10000);
    WaitAndAssertAsyncCallback(ctx2, 10000);

    HksFreeParamSet(&paramSet);
    ASSERT_EQ(HksDeleteKeyForDe(&g_keyAlias, nullptr), HKS_SUCCESS);
}

/**
 * @tc.name: HksAsyncAnonAttestKeyTest.HksAsyncAnonAttestKeyTest009
 * @tc.desc: sync anon attest still works after the unification: on software devices the
 *   chain is no longer returned in the admission reply but delivered through the same
 *   stub async reply the TEE path uses, and the client converts it with the identical
 *   wait - so the published sync interface must still return a complete, non-empty cert
 *   chain on every environment.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncAnonAttestKeyTest, HksAsyncAnonAttestKeyTest009, TestSize.Level0)
{
    HksMockNativeToken mock("asset_service");
    ASSERT_EQ(TestGenerateKey(&g_keyAlias), HKS_SUCCESS);
    /* no storage level here: HksAnonAttestKeyForDe adds the DE tag itself (duplicate tags
     * would be rejected), which is exactly how the existing sync tests call it */
    struct HksParam params[] = {
        { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = g_challenge },
        { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = g_version },
        { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = g_keyAlias },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    if (ret == HKS_SUCCESS) {
        ret = HksAddParams(paramSet, params, sizeof(params) / sizeof(params[0]));
    }
    if (ret == HKS_SUCCESS) {
        ret = HksBuildParamSet(&paramSet);
    }
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksCertChain *certChain = ConstructSyncCertChain();
    ASSERT_NE(certChain, nullptr);
    ret = HksAnonAttestKeyForDe(&g_keyAlias, paramSet, certChain);
    EXPECT_EQ(ret, HKS_SUCCESS);
    /* the unified delivery must keep the sync contract: a complete chain with every cert
     * non-empty (raw DER certs even start with the ASN.1 SEQUENCE tag) */
    ASSERT_NE(certChain->certs, nullptr);
    ASSERT_GT(certChain->certsCount, 0u);
    for (uint32_t i = 0; i < certChain->certsCount; ++i) {
        ASSERT_NE(certChain->certs[i].data, nullptr);
        ASSERT_GT(certChain->certs[i].size, 0u);
    }
    ASSERT_EQ(certChain->certs[0].data[0], 0x30);
    HKS_LOG_I("sync anon attest still returns %" LOG_PUBLIC "u certs through the uniform delivery",
        certChain->certsCount);
    FreeSyncCertChain(&certChain);

    HksFreeParamSet(&paramSet);
    ASSERT_EQ(HksDeleteKeyForDe(&g_keyAlias, nullptr), HKS_SUCCESS);
}

/**
 * @tc.name: HksAsyncAnonAttestKeyTest.HksAsyncAnonAttestKeyTest010
 * @tc.desc: the async callback must deliver the same cert chain the sync interface
 *   returns: attest the same key through the sync interface first, then through the
 *   async interface, and require the callback's cert count to equal the sync count
 *   (both interfaces now receive their chain through the same stub async reply on
 *   software-level and TEE devices alike).
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncAnonAttestKeyTest, HksAsyncAnonAttestKeyTest010, TestSize.Level0)
{
    HksMockNativeToken mock("asset_service");
    ASSERT_EQ(TestGenerateKey(&g_keyAlias), HKS_SUCCESS);

    /* 1. sync attest on the key: record the number of certs the sync interface returns.
     * no storage level in the sync param set: HksAnonAttestKeyForDe adds the DE tag itself
     * (duplicate tags would be rejected), which is exactly how Test009 calls it */
    struct HksParam syncParams[] = {
        { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = g_secInfo },
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = g_challenge },
        { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = g_version },
        { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = g_keyAlias },
    };
    struct HksParamSet *syncParamSet = nullptr;
    int32_t ret = HksInitParamSet(&syncParamSet);
    if (ret == HKS_SUCCESS) {
        ret = HksAddParams(syncParamSet, syncParams, sizeof(syncParams) / sizeof(syncParams[0]));
    }
    if (ret == HKS_SUCCESS) {
        ret = HksBuildParamSet(&syncParamSet);
    }
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksCertChain *certChain = ConstructSyncCertChain();
    ASSERT_NE(certChain, nullptr);
    ret = HksAnonAttestKeyForDe(&g_keyAlias, syncParamSet, certChain);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ASSERT_GT(certChain->certsCount, 0u);
    uint32_t syncCertCount = certChain->certsCount;
    HKS_LOG_I("sync anon attest returns %" LOG_PUBLIC "u certs", syncCertCount);
    FreeSyncCertChain(&certChain);
    HksFreeParamSet(&syncParamSet);

    /* 2. async attest the same key: the callback must deliver the same chain */
    struct HksParamSet *paramSet = nullptr;
    ASSERT_EQ(GenAttestParamSet(&paramSet), HKS_SUCCESS);
    AsyncAttestCtx ctx;
    struct OH_Huks_Blob alias = { g_keyAlias.size, g_keyAlias.data };
    struct OH_Huks_Result result = OH_Huks_AsyncAnonAttestKeyItem(&alias,
        (const struct OH_Huks_ParamSet *)paramSet, AsyncAnonAttestCb, &ctx);
    EXPECT_EQ(result.errorCode, OH_HUKS_SUCCESS);
    WaitAndAssertAsyncCallback(ctx, 10000);

    /* the chain delivered to the callback must match what the sync interface returns for
     * the same key: same environment, same key -> same cert count */
    EXPECT_EQ(ctx.lastCertCount.load(), syncCertCount);
    HKS_LOG_I("async callback delivers %" LOG_PUBLIC "u certs, sync returned %" LOG_PUBLIC "u certs",
        ctx.lastCertCount.load(), syncCertCount);

    HksFreeParamSet(&paramSet);
    ASSERT_EQ(HksDeleteKeyForDe(&g_keyAlias, nullptr), HKS_SUCCESS);
}

/**
 * @tc.name: HksAsyncAnonAttestKeyTest.HksAsyncAnonAttestKeyTest011
 * @tc.desc: InnerAPI entry (HksAsyncAnonAttestKey) without the base64 tag: the callback
 *   must deliver the raw, unencoded cert chain (first cert starts with the ASN.1 SEQUENCE
 *   tag, no PEM wrapper anywhere) - the raw presentation is preserved through the unified
 *   stub delivery, matching what the sync InnerAPI returns.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncAnonAttestKeyTest, HksAsyncAnonAttestKeyTest011, TestSize.Level0)
{
    HksMockNativeToken mock("asset_service");
    ASSERT_EQ(TestGenerateKey(&g_keyAlias), HKS_SUCCESS);
    /* GenAttestParamSet carries no HKS_TAG_ATTESTATION_BASE64, so the InnerAPI path
     * attests raw (the NDK entry would add base64) */
    struct HksParamSet *paramSet = nullptr;
    ASSERT_EQ(GenAttestParamSet(&paramSet), HKS_SUCCESS);

    AsyncAttestCtx ctx;
    int32_t ret = HksAsyncAnonAttestKey(&g_keyAlias, paramSet, AsyncAnonAttestCbInner, &ctx);
    EXPECT_EQ(ret, HKS_SUCCESS);
    WaitAndAssertAsyncCallback(ctx, 10000);

    /* raw delivery: no PEM wrapper, certs come back as DER, starting with 0x30 */
    EXPECT_EQ(ctx.lastPemCount.load(), 0u);
    EXPECT_EQ(ctx.lastFirstCertByte.load(), 0x30u);
    HKS_LOG_I("InnerAPI async anon attest delivered %" LOG_PUBLIC "u raw certs",
        ctx.lastCertCount.load());

    HksFreeParamSet(&paramSet);
    ASSERT_EQ(HksDeleteKeyForDe(&g_keyAlias, nullptr), HKS_SUCCESS);
}
} // namespace Unittest::HksAsyncAnonAttestKeyTest
