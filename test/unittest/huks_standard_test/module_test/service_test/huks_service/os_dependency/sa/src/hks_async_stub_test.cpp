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

#include <cstdint>
#include <cstring>
#include <memory>
#include <securec.h>
#include <vector>

#include "hks_async_stub.h"
#include "hks_anon_attest_stub.h"
#include "hks_dcm_callback_handler.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_type.h"
#include "huks_service_ipc_interface_code.h"
#include "message_option.h"
#include "message_parcel.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::Hks;

namespace Unittest::HksAsyncStubTest {

namespace {
/* observation buffer filled by the callback; the cert chain is only valid during the
 * callback, so everything we need to check is copied out there */
struct StubCbRecord {
    uint32_t callCount = 0;
    int32_t lastResult = -1;
    bool certChainNull = true;
    uint32_t certCount = 0;
    std::vector<std::vector<uint8_t>> certs;
};

static StubCbRecord g_cbRecord;

static void ResetCbRecord()
{
    g_cbRecord = StubCbRecord {};
}

static void StubTestCallback(void *userData, int32_t result, const struct HksCertChain *certChain)
{
    ASSERT_NE(userData, nullptr);
    StubCbRecord *record = static_cast<StubCbRecord *>(userData);
    record->callCount++;
    record->lastResult = result;
    if (certChain == nullptr || certChain->certs == nullptr) {
        record->certChainNull = true;
        record->certCount = 0;
        return;
    }
    record->certChainNull = false;
    record->certCount = certChain->certsCount;
    for (uint32_t i = 0; i < certChain->certsCount; ++i) {
        std::vector<uint8_t> cert(certChain->certs[i].data,
            certChain->certs[i].data + certChain->certs[i].size);
        record->certs.emplace_back(cert);
    }
}

static void AppendU32(std::vector<uint8_t> &out, uint32_t value)
{
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&value);
    out.insert(out.end(), p, p + sizeof(value));
}

/* mirror of the service-side PackAttestChain wire layout: [count]{[size][data][pad4]}* */
static void PackCertChain(std::vector<uint8_t> &out, const std::vector<std::vector<uint8_t>> &certs)
{
    AppendU32(out, static_cast<uint32_t>(certs.size()));
    for (const auto &cert : certs) {
        AppendU32(out, static_cast<uint32_t>(cert.size()));
        out.insert(out.end(), cert.begin(), cert.end());
        uint32_t pad = (4 - (cert.size() % 4)) % 4; /* 4: parcel alignment */
        out.insert(out.end(), pad, 0);
    }
}

static std::vector<std::vector<uint8_t>> MakeTestCerts(uint32_t count, uint32_t certSize)
{
    std::vector<std::vector<uint8_t>> certs;
    for (uint32_t i = 0; i < count; ++i) {
        std::vector<uint8_t> cert(certSize);
        for (uint32_t j = 0; j < certSize; ++j) {
            cert[j] = static_cast<uint8_t>((i + 1) * 0x11 + j);
        }
        certs.emplace_back(cert);
    }
    return certs;
}
} // namespace

class HksAsyncStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksAsyncStubTest::SetUpTestCase(void)
{
}

void HksAsyncStubTest::TearDownTestCase(void)
{
}

void HksAsyncStubTest::SetUp()
{
    ResetCbRecord();
}

void HksAsyncStubTest::TearDown()
{
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest001
 * @tc.desc: unpack a packed 4-cert chain (raw mode) and verify content, then free it.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest001, TestSize.Level0)
{
    auto testCerts = MakeTestCerts(HKS_CERT_COUNT, 100);
    std::vector<uint8_t> packed;
    PackCertChain(packed, testCerts);
    struct HksBlob srcBlob = { static_cast<uint32_t>(packed.size()), packed.data() };

    struct HksCertChain *certChain = nullptr;
    int32_t ret = HksUnpackAnonAttestCertChainToNew(&srcBlob, false, &certChain);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(certChain, nullptr);
    ASSERT_NE(certChain->certs, nullptr);
    EXPECT_EQ(certChain->certsCount, HKS_CERT_COUNT);
    for (uint32_t i = 0; i < HKS_CERT_COUNT; ++i) {
        EXPECT_EQ(certChain->certs[i].size, testCerts[i].size());
        ASSERT_NE(certChain->certs[i].data, nullptr);
        EXPECT_EQ(memcmp(certChain->certs[i].data, testCerts[i].data(), testCerts[i].size()), 0);
    }
    HksFreeAnonAttestCertChain(&certChain);
    EXPECT_EQ(certChain, nullptr);
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest002
 * @tc.desc: unpack with base64 encoding: each cert must come back PEM-wrapped.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest002, TestSize.Level0)
{
    auto testCerts = MakeTestCerts(2, 60); /* 2: partial chain is a valid packed layout */
    std::vector<uint8_t> packed;
    PackCertChain(packed, testCerts);
    struct HksBlob srcBlob = { static_cast<uint32_t>(packed.size()), packed.data() };

    struct HksCertChain *certChain = nullptr;
    int32_t ret = HksUnpackAnonAttestCertChainToNew(&srcBlob, true, &certChain);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(certChain, nullptr);
    EXPECT_EQ(certChain->certsCount, 2);
    const char *beginMark = "-----BEGIN CERTIFICATE-----";
    const char *endMark = "-----END CERTIFICATE-----";
    for (uint32_t i = 0; i < certChain->certsCount; ++i) {
        ASSERT_NE(certChain->certs[i].data, nullptr);
        EXPECT_GT(certChain->certs[i].size, strlen(beginMark) + strlen(endMark));
        EXPECT_EQ(memcmp(certChain->certs[i].data, beginMark, strlen(beginMark)), 0);
        EXPECT_EQ(memcmp(certChain->certs[i].data + certChain->certs[i].size - strlen(endMark),
            endMark, strlen(endMark)), 0);
    }
    HksFreeAnonAttestCertChain(&certChain);
    EXPECT_EQ(certChain, nullptr);
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest003
 * @tc.desc: unpack rejects invalid inputs (null args, bad count, truncated buffer).
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest003, TestSize.Level0)
{
    struct HksCertChain *certChain = nullptr;
    struct HksBlob srcBlob = { 0, nullptr };

    EXPECT_EQ(HksUnpackAnonAttestCertChainToNew(nullptr, false, &certChain), HKS_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(HksUnpackAnonAttestCertChainToNew(&srcBlob, false, nullptr), HKS_ERROR_INVALID_ARGUMENT);

    /* buffer too small to even hold the count */
    uint8_t tinyBuf[2] = { 0 };
    struct HksBlob tinyBlob = { sizeof(tinyBuf), tinyBuf };
    EXPECT_EQ(HksUnpackAnonAttestCertChainToNew(&tinyBlob, false, &certChain), HKS_ERROR_BUFFER_TOO_SMALL);

    /* count == 0 */
    std::vector<uint8_t> packed;
    AppendU32(packed, 0);
    struct HksBlob zeroCountBlob = { static_cast<uint32_t>(packed.size()), packed.data() };
    EXPECT_EQ(HksUnpackAnonAttestCertChainToNew(&zeroCountBlob, false, &certChain), HKS_ERROR_INVALID_ARGUMENT);

    /* count > HKS_CERT_COUNT */
    packed.clear();
    AppendU32(packed, HKS_CERT_COUNT + 1);
    struct HksBlob bigCountBlob = { static_cast<uint32_t>(packed.size()), packed.data() };
    EXPECT_EQ(HksUnpackAnonAttestCertChainToNew(&bigCountBlob, false, &certChain), HKS_ERROR_INVALID_ARGUMENT);

    /* truncated: count 4 but no cert data */
    packed.clear();
    AppendU32(packed, HKS_CERT_COUNT);
    struct HksBlob truncatedBlob = { static_cast<uint32_t>(packed.size()), packed.data() };
    EXPECT_NE(HksUnpackAnonAttestCertChainToNew(&truncatedBlob, false, &certChain), HKS_SUCCESS);

    /* truncated: cert size declared beyond the buffer */
    packed.clear();
    AppendU32(packed, 1);
    AppendU32(packed, 1000);
    struct HksBlob overrunBlob = { static_cast<uint32_t>(packed.size()), packed.data() };
    EXPECT_NE(HksUnpackAnonAttestCertChainToNew(&overrunBlob, false, &certChain), HKS_SUCCESS);
    EXPECT_EQ(certChain, nullptr);
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest004
 * @tc.desc: OnRemoteRequest with wrong interface token: no callback, error return.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest004, TestSize.Level0)
{
    HksAsyncStub stub(StubTestCallback, &g_cbRecord, false);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"wrong.token");

    int ret = stub.OnRemoteRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(g_cbRecord.callCount, 0u);
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest005
 * @tc.desc: OnRemoteRequest with unknown message code: no callback, error return.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest005, TestSize.Level0)
{
    HksAsyncStub stub(StubTestCallback, &g_cbRecord, false);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"ohos.security.hks.service");

    int ret = stub.OnRemoteRequest(999, data, reply, option);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(g_cbRecord.callCount, 0u);
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest006
 * @tc.desc: OnRemoteRequest with a non-zero errCode (DCM failure): callback invoked exactly
 *   once with that error and a NULL cert chain.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest006, TestSize.Level0)
{
    HksAsyncStub stub(StubTestCallback, &g_cbRecord, false);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    data.WriteUint32(DCM_ERROR_NETWORK_UNAVALIABLE);

    int ret = stub.OnRemoteRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    EXPECT_NE(ret, 0); /* reply parcel is still marked invalid */
    EXPECT_EQ(g_cbRecord.callCount, 1u);
    EXPECT_EQ(g_cbRecord.lastResult, static_cast<int32_t>(DCM_ERROR_NETWORK_UNAVALIABLE));
    EXPECT_TRUE(g_cbRecord.certChainNull);
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest007
 * @tc.desc: OnRemoteRequest with success + valid packed chain: callback invoked exactly
 *   once with result 0 and the unpacked, base64-encoded cert chain.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest007, TestSize.Level0)
{
    auto testCerts = MakeTestCerts(HKS_CERT_COUNT, 200);
    std::vector<uint8_t> packed;
    PackCertChain(packed, testCerts);

    HksAsyncStub stub(StubTestCallback, &g_cbRecord, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    data.WriteUint32(DCM_SUCCESS);
    data.WriteUint32(static_cast<uint32_t>(packed.size()));
    data.WriteBuffer(packed.data(), packed.size());

    int ret = stub.OnRemoteRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(g_cbRecord.callCount, 1u);
    EXPECT_EQ(g_cbRecord.lastResult, 0);
    ASSERT_FALSE(g_cbRecord.certChainNull);
    ASSERT_EQ(g_cbRecord.certCount, HKS_CERT_COUNT);
    const char *beginMark = "-----BEGIN CERTIFICATE-----";
    for (uint32_t i = 0; i < g_cbRecord.certCount; ++i) {
        EXPECT_GT(g_cbRecord.certs[i].size(), strlen(beginMark));
        EXPECT_EQ(memcmp(g_cbRecord.certs[i].data(), beginMark, strlen(beginMark)), 0);
    }
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest008
 * @tc.desc: OnRemoteRequest with success + broken packed data (count > 4): callback is
 *   invoked once with an error result and a NULL cert chain.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest008, TestSize.Level0)
{
    std::vector<uint8_t> broken;
    AppendU32(broken, HKS_CERT_COUNT + 1);

    HksAsyncStub stub(StubTestCallback, &g_cbRecord, false);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    data.WriteUint32(DCM_SUCCESS);
    data.WriteUint32(static_cast<uint32_t>(broken.size()));
    data.WriteBuffer(broken.data(), broken.size());

    int ret = stub.OnRemoteRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    EXPECT_EQ(ret, 0); /* parcel parsing succeeded; only the payload was invalid */
    EXPECT_EQ(g_cbRecord.callCount, 1u);
    EXPECT_NE(g_cbRecord.lastResult, 0);
    EXPECT_TRUE(g_cbRecord.certChainNull);
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest009
 * @tc.desc: OnRemoteRequest with success + zero-size chain: callback invoked once with an
 *   error result (empty payload is not a valid chain).
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest009, TestSize.Level0)
{
    HksAsyncStub stub(StubTestCallback, &g_cbRecord, false);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    data.WriteUint32(DCM_SUCCESS);
    data.WriteUint32(0);

    int ret = stub.OnRemoteRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(g_cbRecord.callCount, 1u);
    EXPECT_NE(g_cbRecord.lastResult, 0);
    EXPECT_TRUE(g_cbRecord.certChainNull);
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest010
 * @tc.desc: SendAsyncReply direct in-process dispatch with a valid chain: callback invoked
 *   exactly once with result 0 and the raw cert chain.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest010, TestSize.Level0)
{
    auto testCerts = MakeTestCerts(HKS_CERT_COUNT, 80);
    std::vector<uint8_t> packed;
    PackCertChain(packed, testCerts);

    HksAsyncStub stub(StubTestCallback, &g_cbRecord, false);
    auto buffer = std::make_unique<uint8_t[]>(packed.size());
    memcpy_s(buffer.get(), packed.size(), packed.data(), packed.size());
    stub.SendAsyncReply(DCM_SUCCESS, buffer, static_cast<uint32_t>(packed.size()));

    EXPECT_EQ(g_cbRecord.callCount, 1u);
    EXPECT_EQ(g_cbRecord.lastResult, 0);
    ASSERT_FALSE(g_cbRecord.certChainNull);
    ASSERT_EQ(g_cbRecord.certCount, HKS_CERT_COUNT);
    for (uint32_t i = 0; i < g_cbRecord.certCount; ++i) {
        EXPECT_EQ(memcmp(g_cbRecord.certs[i].data(), testCerts[i].data(), testCerts[i].size()), 0);
    }
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest011
 * @tc.desc: SendAsyncReply direct dispatch with an error code: callback invoked once with
 *   the error and a NULL chain.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest011, TestSize.Level0)
{
    HksAsyncStub stub(StubTestCallback, &g_cbRecord, false);
    std::unique_ptr<uint8_t[]> buffer = nullptr;
    stub.SendAsyncReply(DCM_ERROR_SERVICE_TIME_OUT, buffer, 0);

    EXPECT_EQ(g_cbRecord.callCount, 1u);
    EXPECT_EQ(g_cbRecord.lastResult, static_cast<int32_t>(DCM_ERROR_SERVICE_TIME_OUT));
    EXPECT_TRUE(g_cbRecord.certChainNull);
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest012
 * @tc.desc: OnRemoteRequest with success + valid packed chain in non-base64 mode (the
 *   counterpart of HksAsyncStubTest007 which covers the base64 mode): callback invoked
 *   exactly once with result 0 and the raw, unencoded cert chain.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest012, TestSize.Level0)
{
    auto testCerts = MakeTestCerts(HKS_CERT_COUNT, 120);
    std::vector<uint8_t> packed;
    PackCertChain(packed, testCerts);

    HksAsyncStub stub(StubTestCallback, &g_cbRecord, false);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"ohos.security.hks.service");
    data.WriteUint32(DCM_SUCCESS);
    data.WriteUint32(static_cast<uint32_t>(packed.size()));
    data.WriteBuffer(packed.data(), packed.size());

    int ret = stub.OnRemoteRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(g_cbRecord.callCount, 1u);
    EXPECT_EQ(g_cbRecord.lastResult, 0);
    ASSERT_FALSE(g_cbRecord.certChainNull);
    ASSERT_EQ(g_cbRecord.certCount, HKS_CERT_COUNT);
    for (uint32_t i = 0; i < g_cbRecord.certCount; ++i) {
        /* raw mode: the delivered cert bytes must equal the packed ones, no PEM wrapper */
        EXPECT_EQ(g_cbRecord.certs[i].size(), testCerts[i].size());
        EXPECT_EQ(memcmp(g_cbRecord.certs[i].data(), testCerts[i].data(), testCerts[i].size()), 0);
    }
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest013
 * @tc.desc: HksSendAnonAttestResultToCaller (the software-level service delivery) sends a
 *   success result with a packed chain to a callback stub object: the callback fires
 *   exactly once with result 0 and the exact cert content - through the local-object
 *   branch of the delivery, exactly like an in-SA stub receives it.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest013, TestSize.Level0)
{
    auto testCerts = MakeTestCerts(HKS_CERT_COUNT, 90);
    std::vector<uint8_t> packed;
    PackCertChain(packed, testCerts);
    struct HksBlob certBlob = { static_cast<uint32_t>(packed.size()), packed.data() };

    OHOS::sptr<HksAsyncStub> stub = new HksAsyncStub(StubTestCallback, &g_cbRecord, false);
    const uint8_t *stubObj = reinterpret_cast<const uint8_t *>(stub.GetRefPtr());
    int32_t ret = HksSendAnonAttestResultToCaller(stubObj, HKS_SUCCESS, &certBlob);

    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(g_cbRecord.callCount, 1u);
    EXPECT_EQ(g_cbRecord.lastResult, 0);
    ASSERT_FALSE(g_cbRecord.certChainNull);
    ASSERT_EQ(g_cbRecord.certCount, HKS_CERT_COUNT);
    for (uint32_t i = 0; i < g_cbRecord.certCount; ++i) {
        EXPECT_EQ(g_cbRecord.certs[i].size(), testCerts[i].size());
        EXPECT_EQ(memcmp(g_cbRecord.certs[i].data(), testCerts[i].data(), testCerts[i].size()), 0);
    }
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest014
 * @tc.desc: HksSendAnonAttestResultToCaller with an error result: the callback fires once
 *   with the error code and a NULL chain (the wire path the TEE DCM callback uses for
 *   failures; the software path now shares it).
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest014, TestSize.Level0)
{
    OHOS::sptr<HksAsyncStub> stub = new HksAsyncStub(StubTestCallback, &g_cbRecord, false);
    const uint8_t *stubObj = reinterpret_cast<const uint8_t *>(stub.GetRefPtr());
    int32_t ret = HksSendAnonAttestResultToCaller(stubObj, HKS_ERROR_INTERNAL_ERROR, nullptr);

    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(g_cbRecord.callCount, 1u);
    EXPECT_EQ(g_cbRecord.lastResult, HKS_ERROR_INTERNAL_ERROR);
    EXPECT_TRUE(g_cbRecord.certChainNull);
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest015
 * @tc.desc: HksSendAnonAttestResultToCaller rejects invalid inputs without touching the
 *   stub (NULL object; success result with a NULL/empty/oversized chain): no callback is
 *   dispatched, so no malformed reply is ever sent to a caller.
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest015, TestSize.Level0)
{
    uint8_t buf[4] = { 1, 2, 3, 4 };
    struct HksBlob smallBlob = { sizeof(buf), buf };
    struct HksBlob emptyBlob = { 0, buf };
    struct HksBlob oversizedBlob = { MAX_OUT_BLOB_SIZE + 1, buf };
    OHOS::sptr<HksAsyncStub> stub = new HksAsyncStub(StubTestCallback, &g_cbRecord, false);
    const uint8_t *stubObj = reinterpret_cast<const uint8_t *>(stub.GetRefPtr());

    EXPECT_EQ(HksSendAnonAttestResultToCaller(nullptr, HKS_SUCCESS, &smallBlob),
        HKS_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(HksSendAnonAttestResultToCaller(stubObj, HKS_SUCCESS, nullptr),
        HKS_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(HksSendAnonAttestResultToCaller(stubObj, HKS_SUCCESS, &emptyBlob),
        HKS_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(HksSendAnonAttestResultToCaller(stubObj, HKS_SUCCESS, &oversizedBlob),
        HKS_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(g_cbRecord.callCount, 0u);
}

/**
 * @tc.name: HksAsyncStubTest.HksAsyncStubTest016
 * @tc.desc: the in-SA broker flow end to end: HksCreateAnonAttestStub ->
 *   HksSendAnonAttestResultToCaller -> HksWaitAnonAttestReply -> HksDestroyAnonAttestStub.
 *   The chain published by the software delivery comes back byte-identical from the wait,
 *   proving the new delivery feeds the existing wait-side bridge (which the software
 *   attestation path could never satisfy before).
 * @tc.type: FUNC
 */
HWTEST_F(HksAsyncStubTest, HksAsyncStubTest016, TestSize.Level0)
{
    auto testCerts = MakeTestCerts(HKS_CERT_COUNT, 70);
    std::vector<uint8_t> packed;
    PackCertChain(packed, testCerts);
    struct HksBlob certBlob = { static_cast<uint32_t>(packed.size()), packed.data() };

    const uint8_t *stubObj = HksCreateAnonAttestStub();
    ASSERT_NE(stubObj, nullptr);
    int32_t ret = HksSendAnonAttestResultToCaller(stubObj, HKS_SUCCESS, &certBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob outCert = { 0, nullptr };
    ret = HksWaitAnonAttestReply(stubObj, 2, &outCert); /* 2: the reply is already dispatched */
    HksDestroyAnonAttestStub(stubObj);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(outCert.data, nullptr);
    EXPECT_EQ(outCert.size, packed.size());
    EXPECT_EQ(memcmp(outCert.data, packed.data(), packed.size()), 0);
    HKS_FREE_BLOB(outCert);
}
} // namespace Unittest::HksAsyncStubTest
