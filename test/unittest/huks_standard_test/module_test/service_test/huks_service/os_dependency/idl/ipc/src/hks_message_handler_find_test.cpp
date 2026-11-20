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

#include "hks_message_handler.h"

using namespace testing::ext;

namespace Unittest::HksMessageHandlerFindTest {
class HksMessageHandlerFindTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksMessageHandlerFindTest::SetUpTestCase(void)
{
}

void HksMessageHandlerFindTest::TearDownTestCase(void)
{
}

void HksMessageHandlerFindTest::SetUp()
{
}

void HksMessageHandlerFindTest::TearDown()
{
}

/**
 * @tc.name: HksMessageHandlerFindTest.FindMessageHandlerHit
 * @tc.desc: tdd HksFindMessageHandler hit head/middle/tail of the table
 * @tc.type: FUNC
 */
HWTEST_F(HksMessageHandlerFindTest, FindMessageHandlerHit, TestSize.Level0)
{
    EXPECT_NE(HksFindMessageHandler(HKS_MSG_GEN_KEY), nullptr);
    EXPECT_NE(HksFindMessageHandler(HKS_MSG_EXT_GET_CERT_CHAIN), nullptr);
    EXPECT_NE(HksFindMessageHandler(HKS_MSG_EXT_GET_ANON_CERT_CHAIN), nullptr);
    EXPECT_NE(HksFindMessageHandler(HKS_MSG_EXT_GET_RESOURCE_ID), nullptr);
}

/**
 * @tc.name: HksMessageHandlerFindTest.FindMessageHandlerMiss
 * @tc.desc: tdd HksFindMessageHandler miss (three-stage codes / unattested codes)
 * @tc.type: FUNC
 */
HWTEST_F(HksMessageHandlerFindTest, FindMessageHandlerMiss, TestSize.Level0)
{
    EXPECT_EQ(HksFindMessageHandler(HKS_MSG_INIT), nullptr);
    EXPECT_EQ(HksFindMessageHandler(HKS_MSG_UPDATE), nullptr);
    EXPECT_EQ(HksFindMessageHandler(HKS_MSG_FINISH), nullptr);
    EXPECT_EQ(HksFindMessageHandler(HKS_MSG_ABORT), nullptr);
    EXPECT_EQ(HksFindMessageHandler(HKS_MSG_ATTEST_KEY), nullptr);
    EXPECT_EQ(HksFindMessageHandler(HKS_MSG_MAX), nullptr);
}

/**
 * @tc.name: HksMessageHandlerFindTest.FindThreeStageHandlerHit
 * @tc.desc: tdd HksFindThreeStageHandler hit all three-stage codes
 * @tc.type: FUNC
 */
HWTEST_F(HksMessageHandlerFindTest, FindThreeStageHandlerHit, TestSize.Level0)
{
    EXPECT_NE(HksFindThreeStageHandler(HKS_MSG_INIT), nullptr);
    EXPECT_NE(HksFindThreeStageHandler(HKS_MSG_UPDATE), nullptr);
    EXPECT_NE(HksFindThreeStageHandler(HKS_MSG_FINISH), nullptr);
    EXPECT_NE(HksFindThreeStageHandler(HKS_MSG_ABORT), nullptr);
}

/**
 * @tc.name: HksMessageHandlerFindTest.FindThreeStageHandlerMiss
 * @tc.desc: tdd HksFindThreeStageHandler miss (non three-stage codes)
 * @tc.type: FUNC
 */
HWTEST_F(HksMessageHandlerFindTest, FindThreeStageHandlerMiss, TestSize.Level0)
{
    EXPECT_EQ(HksFindThreeStageHandler(HKS_MSG_GEN_KEY), nullptr);
    EXPECT_EQ(HksFindThreeStageHandler(HKS_MSG_ATTEST_KEY), nullptr);
    EXPECT_EQ(HksFindThreeStageHandler(HKS_MSG_MAX), nullptr);
}
} // namespace Unittest::HksMessageHandlerFindTest