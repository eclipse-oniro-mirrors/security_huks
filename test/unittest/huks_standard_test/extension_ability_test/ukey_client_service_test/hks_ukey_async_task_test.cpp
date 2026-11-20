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

#include "hks_ukey_async_task.h"
#include "hks_error_code.h"
#include "hks_type.h"
#include "huks_service_ipc_interface_code.h"
#include "iremote_object.h"
#include "message_parcel.h"
#include "message_option.h"

#include <vector>

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace Hks {

class MockIRemoteObject : public IRemoteObject {
public:
    MockIRemoteObject() : IRemoteObject(u"mock_async_task") {}
    int32_t GetObjectRefCount() override
    {
        return 1;
    }
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        (void)code;
        (void)data;
        (void)reply;
        (void)option;
        return 0;
    }
    bool IsProxyObject() const override
    {
        return false;
    }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        (void)recipient;
        return true;
    }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        (void)recipient;
        return true;
    }
    int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        (void)fd;
        (void)args;
        return 0;
    }
};

static void TestHandler(const struct HksBlob *msg, const uint8_t *context)
{
    (void)msg;
    (void)context;
}

static void TestThreeStageHandler(const struct HksBlob *msg, struct HksBlob *outData, const uint8_t *context)
{
    (void)msg;
    (void)context;
    if (outData != nullptr && outData->size > 0) {
        outData->data[0] = 0;
    }
}

class HksUkeyAsyncTaskTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void HksUkeyAsyncTaskTest::SetUpTestCase(void) {}
void HksUkeyAsyncTaskTest::TearDownTestCase(void) {}
void HksUkeyAsyncTaskTest::SetUp() {}
void HksUkeyAsyncTaskTest::TearDown() {}

/**
 * @tc.name: HksUkeyAsyncTaskTest.HksUkeyAsyncTaskTest001
 * @tc.desc: factory null errOut, and Run with no handler returns INVALID_ARGUMENT.
 * @tc.type: FUNC
 */
HWTEST_F(HksUkeyAsyncTaskTest, HksUkeyAsyncTaskTest001, TestSize.Level0)
{
    HksUkeyTaskParams params{};
    EXPECT_EQ(HksCreateUkeyAsyncTask(params, nullptr), nullptr);

    params.clientStub = new MockIRemoteObject();
    int32_t err = 0;
    auto *task = HksCreateUkeyAsyncTask(params, &err);
    ASSERT_NE(task, nullptr);
    EXPECT_EQ(err, HKS_SUCCESS);
    EXPECT_EQ(task->GetDeepCopyErr(), HKS_SUCCESS);
    EXPECT_EQ(task->DeadlineMs(), 0u);
    EXPECT_EQ(task->Run(), HKS_ERROR_INVALID_ARGUMENT);
    delete task;
}

/**
 * @tc.name: HksUkeyAsyncTaskTest.HksUkeyAsyncTaskTest002
 * @tc.desc: Run with single-arg handler succeeds (deep-copy path).
 * @tc.type: FUNC
 */
HWTEST_F(HksUkeyAsyncTaskTest, HksUkeyAsyncTaskTest002, TestSize.Level0)
{
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    HksUkeyTaskParams params{};
    params.handler = TestHandler;
    params.srcData = { sizeof(data), data };
    params.timeoutMs = 100;
    params.fullTokenId = 0x12345678;
    params.clientStub = new MockIRemoteObject();

    int32_t err = 0;
    auto *task = HksCreateUkeyAsyncTask(params, &err);
    ASSERT_NE(task, nullptr);
    EXPECT_EQ(err, HKS_SUCCESS);
    EXPECT_EQ(task->DeadlineMs(), 100u);
    EXPECT_EQ(task->Run(), HKS_SUCCESS);
    delete task;
}

/**
 * @tc.name: HksUkeyAsyncTaskTest.HksUkeyAsyncTaskTest003
 * @tc.desc: Run with three-stage handler and outSize > 0.
 * @tc.type: FUNC
 */
HWTEST_F(HksUkeyAsyncTaskTest, HksUkeyAsyncTaskTest003, TestSize.Level0)
{
    HksUkeyTaskParams params{};
    params.threeStageHandler = TestThreeStageHandler;
    params.outSize = 8;
    params.clientStub = new MockIRemoteObject();

    int32_t err = 0;
    auto *task = HksCreateUkeyAsyncTask(params, &err);
    ASSERT_NE(task, nullptr);
    EXPECT_EQ(task->Run(), HKS_SUCCESS);
    delete task;
}

/**
 * @tc.name: HksUkeyAsyncTaskTest.HksUkeyAsyncTaskTest004
 * @tc.desc: Run with three-stage handler and outSize == 0.
 * @tc.type: FUNC
 */
HWTEST_F(HksUkeyAsyncTaskTest, HksUkeyAsyncTaskTest004, TestSize.Level0)
{
    HksUkeyTaskParams params{};
    params.threeStageHandler = TestThreeStageHandler;
    params.outSize = 0;
    params.clientStub = new MockIRemoteObject();

    int32_t err = 0;
    auto *task = HksCreateUkeyAsyncTask(params, &err);
    ASSERT_NE(task, nullptr);
    EXPECT_EQ(task->Run(), HKS_SUCCESS);
    delete task;
}

/**
 * @tc.name: HksUkeyAsyncTaskTest.HksUkeyAsyncTaskTest005
 * @tc.desc: OnDone with plain IRemoteObject drops reply (iface_cast null).
 * @tc.type: FUNC
 */
HWTEST_F(HksUkeyAsyncTaskTest, HksUkeyAsyncTaskTest005, TestSize.Level0)
{
    HksUkeyTaskParams params{};
    params.msgCode = HKS_MSG_INIT;
    params.handler = TestHandler;
    params.clientStub = new MockIRemoteObject();
    params.routingKey = "provider";

    int32_t err = 0;
    auto *task = HksCreateUkeyAsyncTask(params, &err);
    ASSERT_NE(task, nullptr);
    task->OnDone(HKS_SUCCESS);
    delete task;
}

/**
 * @tc.name: HksUkeyAsyncTaskTest.HksUkeyAsyncTaskTest006
 * @tc.desc: OnDone with FINISH + handleAtSubmit triggers UnregisterHandleRouting.
 * @tc.type: FUNC
 */
HWTEST_F(HksUkeyAsyncTaskTest, HksUkeyAsyncTaskTest006, TestSize.Level0)
{
    HksUkeyTaskParams params{};
    params.msgCode = HKS_MSG_FINISH;
    params.handler = TestHandler;
    params.handleAtSubmit = 123;
    params.clientStub = new MockIRemoteObject();

    int32_t err = 0;
    auto *task = HksCreateUkeyAsyncTask(params, &err);
    ASSERT_NE(task, nullptr);
    task->OnDone(HKS_SUCCESS);
    delete task;
}

/**
 * @tc.name: HksUkeyAsyncTaskTest.HksUkeyAsyncTaskTest007
 * @tc.desc: OnDone with ABORT + handleAtSubmit triggers UnregisterHandleRouting.
 * @tc.type: FUNC
 */
HWTEST_F(HksUkeyAsyncTaskTest, HksUkeyAsyncTaskTest007, TestSize.Level0)
{
    HksUkeyTaskParams params{};
    params.msgCode = HKS_MSG_ABORT;
    params.handler = TestHandler;
    params.handleAtSubmit = 456;
    params.clientStub = new MockIRemoteObject();

    int32_t err = 0;
    auto *task = HksCreateUkeyAsyncTask(params, &err);
    ASSERT_NE(task, nullptr);
    task->OnDone(HKS_SUCCESS);
    delete task;
}

/**
 * @tc.name: HksUkeyAsyncTaskTest.HksUkeyAsyncTaskTest008
 * @tc.desc: deep-copies processInfo embedded blobs (userId/processName).
 * @tc.type: FUNC
 */
HWTEST_F(HksUkeyAsyncTaskTest, HksUkeyAsyncTaskTest008, TestSize.Level0)
{
    uint8_t uid[] = {0x11};
    uint8_t name[] = {0x41, 0x42};
    HksUkeyTaskParams params{};
    params.handler = TestHandler;
    params.processInfo.userId = { sizeof(uid), uid };
    params.processInfo.processName = { sizeof(name), name };
    params.processInfo.uidInt = 1000;
    params.processInfo.userIdInt = 100;
    params.processInfo.accessTokenId = 0xabcdef;
    params.processInfo.pid = 999;
    params.clientStub = new MockIRemoteObject();

    int32_t err = 0;
    auto *task = HksCreateUkeyAsyncTask(params, &err);
    ASSERT_NE(task, nullptr);
    EXPECT_EQ(err, HKS_SUCCESS);
    EXPECT_EQ(task->Run(), HKS_SUCCESS);
    delete task;
}

} // namespace Hks
} // namespace Security
} // namespace OHOS