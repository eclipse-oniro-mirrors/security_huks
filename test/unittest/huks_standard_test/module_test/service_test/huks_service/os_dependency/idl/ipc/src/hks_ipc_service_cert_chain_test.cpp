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
#include <string.h>

#include "message_parcel.h"

#include "hks_ipc_service_cert_chain.h"
#include "hks_log.h"
#include "hks_type.h"

using namespace testing::ext;
using namespace OHOS;

namespace Unittest::HksIpcServiceCertChainTest {

static void BuildKeyAliasBlob(const char *alias, uint8_t *buf, uint32_t bufSize, uint32_t *outSize)
{
    uint32_t len = (uint32_t)strlen(alias);
    uint32_t aligned = (len + 3) & ~3u;
    *outSize = sizeof(uint32_t) + aligned;
    if (aligned > bufSize - sizeof(uint32_t)) {
        *outSize = 0;
        return;
    }
    (void)memcpy(buf, &len, sizeof(len));
    (void)memcpy(buf + sizeof(uint32_t), alias, len);
    for (uint32_t i = len; i < aligned; ++i) {
        buf[sizeof(uint32_t) + i] = 0;
    }
}

class HksIpcServiceCertChainTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksIpcServiceCertChainTest::SetUpTestCase(void)
{
}

void HksIpcServiceCertChainTest::TearDownTestCase(void)
{
}

void HksIpcServiceCertChainTest::SetUp()
{
}

void HksIpcServiceCertChainTest::TearDown()
{
}

/**
 * @tc.name: HksIpcServiceCertChainTest.GetCertChainEmpty
 * @tc.desc: tdd HksIpcServiceGetCertChain with empty srcData, expect unpack fail branch
 * @tc.type: FUNC
 */
HWTEST_F(HksIpcServiceCertChainTest, GetCertChainEmpty, TestSize.Level0)
{
    HKS_LOG_I("enter GetCertChainEmpty");
    uint8_t data[] = { 0x00 };
    struct HksBlob srcData = { .size = 0, .data = data };
    MessageParcel reply;
    uint8_t *context = reinterpret_cast<uint8_t *>(&reply);
    EXPECT_NO_FATAL_FAILURE((HksIpcServiceGetCertChain(&srcData, context)));
}

/**
 * @tc.name: HksIpcServiceCertChainTest.GetCertChainAlias
 * @tc.desc: tdd HksIpcServiceGetCertChain with keyAlias only
 * @tc.type: FUNC
 */
HWTEST_F(HksIpcServiceCertChainTest, GetCertChainAlias, TestSize.Level0)
{
    HKS_LOG_I("enter GetCertChainAlias");
    uint8_t buf[64] = { 0 };
    uint32_t size = 0;
    BuildKeyAliasBlob("CERTCHAIN_test", buf, sizeof(buf), &size);
    struct HksBlob srcData = { .size = size, .data = buf };
    MessageParcel reply;
    uint8_t *context = reinterpret_cast<uint8_t *>(&reply);
    EXPECT_NO_FATAL_FAILURE((HksIpcServiceGetCertChain(&srcData, context)));
}

/**
 * @tc.name: HksIpcServiceCertChainTest.SetStorageEmpty
 * @tc.desc: tdd HksIpcServiceSetStorage with empty srcData
 * @tc.type: FUNC
 */
HWTEST_F(HksIpcServiceCertChainTest, SetStorageEmpty, TestSize.Level0)
{
    HKS_LOG_I("enter SetStorageEmpty");
    uint8_t data[] = { 0x00 };
    struct HksBlob srcData = { .size = 0, .data = data };
    MessageParcel reply;
    uint8_t *context = reinterpret_cast<uint8_t *>(&reply);
    EXPECT_NO_FATAL_FAILURE((HksIpcServiceSetStorage(&srcData, context)));
}

/**
 * @tc.name: HksIpcServiceCertChainTest.GetStorageEmpty
 * @tc.desc: tdd HksIpcServiceGetStorage with empty srcData
 * @tc.type: FUNC
 */
HWTEST_F(HksIpcServiceCertChainTest, GetStorageEmpty, TestSize.Level0)
{
    HKS_LOG_I("enter GetStorageEmpty");
    uint8_t data[] = { 0x00 };
    struct HksBlob srcData = { .size = 0, .data = data };
    MessageParcel reply;
    uint8_t *context = reinterpret_cast<uint8_t *>(&reply);
    EXPECT_NO_FATAL_FAILURE((HksIpcServiceGetStorage(&srcData, context)));
}

/**
 * @tc.name: HksIpcServiceCertChainTest.GetStorageAlias
 * @tc.desc: tdd HksIpcServiceGetStorage with keyAlias only
 * @tc.type: FUNC
 */
HWTEST_F(HksIpcServiceCertChainTest, GetStorageAlias, TestSize.Level0)
{
    HKS_LOG_I("enter GetStorageAlias");
    uint8_t buf[64] = { 0 };
    uint32_t size = 0;
    BuildKeyAliasBlob("USRCERT_test", buf, sizeof(buf), &size);
    struct HksBlob srcData = { .size = size, .data = buf };
    MessageParcel reply;
    uint8_t *context = reinterpret_cast<uint8_t *>(&reply);
    EXPECT_NO_FATAL_FAILURE((HksIpcServiceGetStorage(&srcData, context)));
}

/**
 * @tc.name: HksIpcServiceCertChainTest.StorageExistEmpty
 * @tc.desc: tdd HksIpcServiceStorageExist with empty srcData
 * @tc.type: FUNC
 */
HWTEST_F(HksIpcServiceCertChainTest, StorageExistEmpty, TestSize.Level0)
{
    HKS_LOG_I("enter StorageExistEmpty");
    uint8_t data[] = { 0x00 };
    struct HksBlob srcData = { .size = 0, .data = data };
    MessageParcel reply;
    uint8_t *context = reinterpret_cast<uint8_t *>(&reply);
    EXPECT_NO_FATAL_FAILURE((HksIpcServiceStorageExist(&srcData, context)));
}

/**
 * @tc.name: HksIpcServiceCertChainTest.StorageExistAlias
 * @tc.desc: tdd HksIpcServiceStorageExist with keyAlias only
 * @tc.type: FUNC
 */
HWTEST_F(HksIpcServiceCertChainTest, StorageExistAlias, TestSize.Level0)
{
    HKS_LOG_I("enter StorageExistAlias");
    uint8_t buf[64] = { 0 };
    uint32_t size = 0;
    BuildKeyAliasBlob("CACERT_test", buf, sizeof(buf), &size);
    struct HksBlob srcData = { .size = size, .data = buf };
    MessageParcel reply;
    uint8_t *context = reinterpret_cast<uint8_t *>(&reply);
    EXPECT_NO_FATAL_FAILURE((HksIpcServiceStorageExist(&srcData, context)));
}

/**
 * @tc.name: HksIpcServiceCertChainTest.GetAnonCertChainEmpty
 * @tc.desc: tdd HksIpcServiceGetAnonCertChain with empty srcData
 * @tc.type: FUNC
 */
HWTEST_F(HksIpcServiceCertChainTest, GetAnonCertChainEmpty, TestSize.Level0)
{
    HKS_LOG_I("enter GetAnonCertChainEmpty");
    uint8_t data[] = { 0x00 };
    struct HksBlob srcData = { .size = 0, .data = data };
    MessageParcel reply;
    uint8_t *context = reinterpret_cast<uint8_t *>(&reply);
    EXPECT_NO_FATAL_FAILURE((HksIpcServiceGetAnonCertChain(&srcData, context)));
}

/**
 * @tc.name: HksIpcServiceCertChainTest.GetAnonCertChainAlias
 * @tc.desc: tdd HksIpcServiceGetAnonCertChain with keyAlias only
 * @tc.type: FUNC
 */
HWTEST_F(HksIpcServiceCertChainTest, GetAnonCertChainAlias, TestSize.Level0)
{
    HKS_LOG_I("enter GetAnonCertChainAlias");
    uint8_t buf[64] = { 0 };
    uint32_t size = 0;
    BuildKeyAliasBlob("CERTCHAIN_anon", buf, sizeof(buf), &size);
    struct HksBlob srcData = { .size = size, .data = buf };
    MessageParcel reply;
    uint8_t *context = reinterpret_cast<uint8_t *>(&reply);
    EXPECT_NO_FATAL_FAILURE((HksIpcServiceGetAnonCertChain(&srcData, context)));
}
} // namespace Unittest::HksIpcServiceCertChainTest