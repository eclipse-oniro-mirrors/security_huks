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

#include "hks_response.h"
#include "hks_log.h"
#include "hks_mem.h"

using namespace testing::ext;

namespace Unittest::HksResponseTest {
class HksResponseTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksResponseTest::SetUpTestCase(void)
{
}

void HksResponseTest::TearDownTestCase(void)
{
}

void HksResponseTest::SetUp()
{
}

void HksResponseTest::TearDown()
{
}

/**
 * @tc.name: HksResponseTest.AsyncResultSlotTakeDisabled
 * @tc.desc: tdd HksAsyncResultSlotTake with the slot disabled (nothing captured)
 * @tc.type: FUNC
 */
HWTEST_F(HksResponseTest, AsyncResultSlotTakeDisabled, TestSize.Level0)
{
    HKS_LOG_I("enter AsyncResultSlotTakeDisabled");
    int32_t result = 123;
    struct HksBlob response = { 0, nullptr };
    HksAsyncResultSlotSetEnabled(false);
    HksAsyncResultSlotTake(&result, &response);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(response.data, nullptr);
    EXPECT_EQ(response.size, 0u);
}

/**
 * @tc.name: HksResponseTest.AsyncResultSlotEnableTake
 * @tc.desc: tdd HksAsyncResultSlotSetEnabled + Take round trip with empty capture
 * @tc.type: FUNC
 */
HWTEST_F(HksResponseTest, AsyncResultSlotEnableTake, TestSize.Level0)
{
    HKS_LOG_I("enter AsyncResultSlotEnableTake");
    int32_t result = 1;
    struct HksBlob response = { 0, nullptr };
    HksAsyncResultSlotSetEnabled(true);
    HksAsyncResultSlotTake(&result, &response);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(response.data, nullptr);
}

/**
 * @tc.name: HksResponseTest.ThreadIdentityOverride
 * @tc.desc: tdd HksSetThreadIdentityOverride / HksGetThreadIdentityOverride
 * @tc.type: FUNC
 */
HWTEST_F(HksResponseTest, ThreadIdentityOverride, TestSize.Level0)
{
    HKS_LOG_I("enter ThreadIdentityOverride");
    EXPECT_EQ(HksGetThreadIdentityOverride(), nullptr);

    struct HksProcessInfo info = HKS_PROCESS_INFO_INIT_VALUE;
    info.uidInt = 1000;
    HksSetThreadIdentityOverride(&info);
    const struct HksProcessInfo *got = HksGetThreadIdentityOverride();
    ASSERT_NE(got, nullptr);
    EXPECT_EQ(got->uidInt, 1000u);

    HksSetThreadIdentityOverride(nullptr);
    EXPECT_EQ(HksGetThreadIdentityOverride(), nullptr);
}

/**
 * @tc.name: HksResponseTest.ThreadFullTokenIdOverride
 * @tc.desc: tdd HksSetThreadFullTokenIdOverride / HksGetThreadFullTokenIdOverride
 * @tc.type: FUNC
 */
HWTEST_F(HksResponseTest, ThreadFullTokenIdOverride, TestSize.Level0)
{
    HKS_LOG_I("enter ThreadFullTokenIdOverride");
    EXPECT_EQ(HksGetThreadFullTokenIdOverride(), 0u);

    HksSetThreadFullTokenIdOverride(0x123456789abcdef0ULL);
    EXPECT_EQ(HksGetThreadFullTokenIdOverride(), 0x123456789abcdef0ULL);

    HksSetThreadFullTokenIdOverride(0);
    EXPECT_EQ(HksGetThreadFullTokenIdOverride(), 0u);
}

/**
 * @tc.name: HksResponseTest.ProcessInfoForIpcNull
 * @tc.desc: tdd HksGetProcessInfoForIPC with null processInfo returns success
 * @tc.type: FUNC
 */
HWTEST_F(HksResponseTest, ProcessInfoForIpcNull, TestSize.Level0)
{
    HKS_LOG_I("enter ProcessInfoForIpcNull");
    EXPECT_EQ(HksGetProcessInfoForIPC(nullptr, nullptr, nullptr), HKS_SUCCESS);
}

/**
 * @tc.name: HksResponseTest.ProcessInfoForIpcThreadSlot
 * @tc.desc: tdd HksGetProcessInfoForIPC reads identity from thread slot
 * @tc.type: FUNC
 */
HWTEST_F(HksResponseTest, ProcessInfoForIpcThreadSlot, TestSize.Level0)
{
    HKS_LOG_I("enter ProcessInfoForIpcThreadSlot");
    uint8_t uidData[] = { 0x01, 0x02, 0x03, 0x04 };
    struct HksProcessInfo info = HKS_PROCESS_INFO_INIT_VALUE;
    info.uidInt = 2000;
    info.userIdInt = 100;
    info.processName = { sizeof(uidData), uidData };

    HksSetThreadIdentityOverride(&info);
    struct HksProcessInfo out = HKS_PROCESS_INFO_INIT_VALUE;
    EXPECT_EQ(HksGetProcessInfoForIPC(nullptr, nullptr, &out), HKS_SUCCESS);
    EXPECT_EQ(out.uidInt, 2000u);
    EXPECT_EQ(out.userIdInt, 100);
    HksSetThreadIdentityOverride(nullptr);

    HKS_FREE_BLOB(out.processName);
    HKS_FREE_BLOB(out.userId);
}
// ===== coverage additions: drive HksCaptureAsyncResult via HksSendResponse(nullptr) + misc =====

/**
 * @tc.name: HksResponseTest.AsyncResultSlotFullCapture
 * @tc.desc: tdd full capture path: HksSendResponse with null context writes result/blob into the slot
 * @tc.type: FUNC
 */
HWTEST_F(HksResponseTest, AsyncResultSlotFullCapture, TestSize.Level0)
{
    HKS_LOG_I("enter AsyncResultSlotFullCapture");
    uint8_t payload[] = { 0x11, 0x22, 0x33, 0x44 };
    struct HksBlob blob = { sizeof(payload), payload };
    HksAsyncResultSlotSetEnabled(true);
    HksSendResponse(nullptr, 4321, &blob);
    int32_t result = 0;
    struct HksBlob response = { 0, nullptr };
    HksAsyncResultSlotTake(&result, &response);
    EXPECT_EQ(result, 4321);
    ASSERT_NE(response.data, nullptr);
    EXPECT_EQ(response.size, sizeof(payload));
    EXPECT_EQ(response.data[0], 0x11);
    HKS_FREE_BLOB(response);
}

/**
 * @tc.name: HksResponseTest.AsyncResultSlotNullResponse
 * @tc.desc: ttd HksSendResponse null context with null response captures result only
 * @tc.type: FUNC
 */
HWTEST_F(HksResponseTest, AsyncResultSlotNullResponse, TestSize.Level0)
{
    HKS_LOG_I("enter AsyncResultSlotNullResponse");
    HksAsyncResultSlotSetEnabled(true);
    HksSendResponse(nullptr, -555, nullptr);
    int32_t result = 0;
    struct HksBlob response = { 0, nullptr };
    HksAsyncResultSlotTake(&result, &response);
    EXPECT_EQ(result, -555);
    EXPECT_EQ(response.data, nullptr);
}

/**
 * @tc.name: HksResponseTest.IpcCallingUidAndFrontUser
 * @tc.desc: tdd HksGetIpcCallingUid and HksCheckIsFrontUser direct calls
 * @tc.type: FUNC
 */
HWTEST_F(HksResponseTest, IpcCallingUidAndFrontUser, TestSize.Level0)
{
    HKS_LOG_I("enter IpcCallingUidAndFrontUser");
    uint32_t uid = HksGetIpcCallingUid();
    EXPECT_GE(uid, 0u);

    bool isFront = true;
    int32_t ret = HksCheckIsFrontUser(100, &isFront);
    EXPECT_EQ(ret, HKS_SUCCESS);
}
} // namespace Unittest::HksResponseTest