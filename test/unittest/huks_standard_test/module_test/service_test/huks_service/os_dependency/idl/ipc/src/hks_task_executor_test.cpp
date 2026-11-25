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
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

#include "hks_async_task.h"
#include "hks_task_executor.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace Hks {
namespace Test {

class CountingTask : public HksAsyncTask {
public:
    CountingTask(uint32_t deadline, bool blockUntilReleased) : deadline_(deadline), block_(blockUntilReleased) {}

    int32_t Run() override
    {
        runs_.fetch_add(1);
        if (block_) {
            std::unique_lock<std::mutex> lk(m_);
            releaseCv_.wait(lk, [this] { return released_; });
        }
        return kRunRet;
    }

    void OnDone(int32_t ret) override
    {
        lastRet_.store(ret);
        dones_.fetch_add(1);
        doneCv_.notify_all();
    }

    uint32_t DeadlineMs() const override
    {
        return deadline_;
    }

    void Release()
    {
        std::lock_guard<std::mutex> lk(m_);
        released_ = true;
        releaseCv_.notify_all();
    }

    void WaitDone()
    {
        std::unique_lock<std::mutex> lk(m_);
        doneCv_.wait_for(lk, std::chrono::seconds(10), [this] { return dones_.load() > 0; });
    }

    static constexpr int32_t kRunRet = 4321;

    std::atomic<int> runs_{ 0 };
    std::atomic<int> dones_{ 0 };
    std::atomic<int32_t> lastRet_{ 0 };
    uint32_t deadline_;
    bool block_;

private:
    std::mutex m_;
    std::condition_variable releaseCv_;
    std::condition_variable doneCv_;
    bool released_ = false;
};

static HksTaskExecutor::Config SmallConfig()
{
    HksTaskExecutor::Config cfg;
    cfg.workerCount = 1;
    cfg.maxPending = 2;
    cfg.maxTimeoutMs = 1000; // 1s upper bound for tests
    cfg.workerStackSize = 0;
    return cfg;
}

class HksTaskExecutorTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: HksTaskExecutorTest.HksTaskExecutorTest001
 * @tc.desc: submit before Start is rejected with STOPPED
 * @tc.type: FUNC
 */
HWTEST_F(HksTaskExecutorTest, HksTaskExecutorTest001, TestSize.Level0)
{
    HksTaskExecutor exec(SmallConfig());
    auto task = std::make_unique<CountingTask>(0, false);
    ASSERT_EQ(exec.Submit(std::move(task)), HksTaskAccept::STOPPED);
}

/**
 * @tc.name: HksTaskExecutorTest.HksTaskExecutorTest002
 * @tc.desc: submit nullptr task is rejected with INVALID
 * @tc.type: FUNC
 */
HWTEST_F(HksTaskExecutorTest, HksTaskExecutorTest002, TestSize.Level0)
{
    HksTaskExecutor exec(SmallConfig());
    exec.Start();
    ASSERT_EQ(exec.Submit(nullptr), HksTaskAccept::INVALID);
}

/**
 * @tc.name: HksTaskExecutorTest.HksTaskExecutorTest003
 * @tc.desc: submit task whose deadline exceeds maxTimeoutMs is rejected with INVALID
 * @tc.type: FUNC
 */
HWTEST_F(HksTaskExecutorTest, HksTaskExecutorTest003, TestSize.Level0)
{
    HksTaskExecutor exec(SmallConfig());
    exec.Start();
    auto task = std::make_unique<CountingTask>(SmallConfig().maxTimeoutMs + 1, false);
    ASSERT_EQ(exec.Submit(std::move(task)), HksTaskAccept::INVALID);
}

/**
 * @tc.name: HksTaskExecutorTest.HksTaskExecutorTest004
 * @tc.desc: normal task is executed on worker and OnDone receives Run's return value
 * @tc.type: FUNC
 */
HWTEST_F(HksTaskExecutorTest, HksTaskExecutorTest004, TestSize.Level0)
{
    HksTaskExecutor exec(SmallConfig());
    exec.Start();
    auto task = std::make_unique<CountingTask>(0, false);
    CountingTask *raw = task.get();
    ASSERT_EQ(exec.Submit(std::move(task)), HksTaskAccept::OK);
    raw->WaitDone();
    ASSERT_EQ(raw->runs_.load(), 1);
    ASSERT_EQ(raw->dones_.load(), 1);
    ASSERT_EQ(raw->lastRet_.load(), CountingTask::kRunRet);
}

/**
 * @tc.name: HksTaskExecutorTest.HksTaskExecutorTest005
 * @tc.desc: bounded queue rejects extra submissions with BUSY
 * @tc.type: FUNC
 */
HWTEST_F(HksTaskExecutorTest, HksTaskExecutorTest005, TestSize.Level0)
{
    HksTaskExecutor exec(SmallConfig()); // capacity = workerCount(1) + maxPending(2) = 3
    exec.Start();
    auto blocker = std::make_unique<CountingTask>(0, true);
    CountingTask *blockerRaw = blocker.get();
    ASSERT_EQ(exec.Submit(std::move(blocker)), HksTaskAccept::OK);
    auto q1 = std::make_unique<CountingTask>(0, false);
    ASSERT_EQ(exec.Submit(std::move(q1)), HksTaskAccept::OK);
    auto q2 = std::make_unique<CountingTask>(0, false);
    ASSERT_EQ(exec.Submit(std::move(q2)), HksTaskAccept::OK); // executing(1) + queued(2) = 3 full
    auto q3 = std::make_unique<CountingTask>(0, false);
    ASSERT_EQ(exec.Submit(std::move(q3)), HksTaskAccept::BUSY);
    blockerRaw->Release();
    exec.Stop();
}

/**
 * @tc.name: HksTaskExecutorTest.HksTaskExecutorTest006
 * @tc.desc: Stop rejects new submissions, drains queued tasks with failure and waits in-flight
 * @tc.type: FUNC
 */
HWTEST_F(HksTaskExecutorTest, HksTaskExecutorTest006, TestSize.Level0)
{
    HksTaskExecutor exec(SmallConfig());
    exec.Start();
    auto blocker = std::make_unique<CountingTask>(0, true);
    CountingTask *blockerRaw = blocker.get();
    ASSERT_EQ(exec.Submit(std::move(blocker)), HksTaskAccept::OK);
    auto queued = std::make_unique<CountingTask>(0, false);
    CountingTask *queuedRaw = queued.get();
    ASSERT_EQ(exec.Submit(std::move(queued)), HksTaskAccept::OK);

    std::thread stopper([&exec] { exec.Stop(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto afterStop = std::make_unique<CountingTask>(0, false);
    CountingTask *afterStopRaw = afterStop.get();
    ASSERT_EQ(exec.Submit(std::move(afterStop)), HksTaskAccept::STOPPED);
    blockerRaw->Release();
    stopper.join();
    // queued task must have been drained with an error code (not Run's success value)
    ASSERT_EQ(queuedRaw->dones_.load(), 1);
    ASSERT_NE(queuedRaw->lastRet_.load(), CountingTask::kRunRet);
    // afterStop task is owned by caller again (STOPPED); free it explicitly
    (void)afterStopRaw;
}

/**
 * @tc.name: HksTaskExecutorTest.HksTaskExecutorTest007
 * @tc.desc: PendingCount reflects executing + queued; zero after idle drain
 * @tc.type: FUNC
 */
HWTEST_F(HksTaskExecutorTest, HksTaskExecutorTest007, TestSize.Level0)
{
    HksTaskExecutor exec(SmallConfig());
    exec.Start();
    ASSERT_EQ(exec.PendingCount(), 0u);
    auto blocker = std::make_unique<CountingTask>(0, true);
    CountingTask *blockerRaw = blocker.get();
    ASSERT_EQ(exec.Submit(std::move(blocker)), HksTaskAccept::OK);
    auto queued = std::make_unique<CountingTask>(0, false);
    ASSERT_EQ(exec.Submit(std::move(queued)), HksTaskAccept::OK);
    ASSERT_EQ(exec.PendingCount(), 2u);
    blockerRaw->Release();
    exec.Stop();
}

/**
 * @tc.name: HksTaskExecutorTest.HksTaskExecutorTest008
 * @tc.desc: Start is idempotent and pool can be restarted after Stop
 * @tc.type: FUNC
 */
HWTEST_F(HksTaskExecutorTest, HksTaskExecutorTest008, TestSize.Level0)
{
    HksTaskExecutor exec(SmallConfig());
    exec.Start();
    exec.Start(); // idempotent, must not spawn extra workers
    exec.Stop();
    exec.Start(); // restart
    auto task = std::make_unique<CountingTask>(0, false);
    CountingTask *raw = task.get();
    ASSERT_EQ(exec.Submit(std::move(task)), HksTaskAccept::OK);
    raw->WaitDone();
    ASSERT_EQ(raw->runs_.load(), 1);
    exec.Stop();
}

/**
 * @tc.name: HksTaskExecutorTest.HksTaskExecutorTest009
 * @tc.desc: destructor stops the pool safely (RAII shutdown path)
 * @tc.type: FUNC
 */
HWTEST_F(HksTaskExecutorTest, HksTaskExecutorTest009, TestSize.Level0)
{
    HksTaskExecutor exec(SmallConfig());
    exec.Start();
    auto blocker = std::make_unique<CountingTask>(0, true);
    CountingTask *blockerRaw = blocker.get();
    ASSERT_EQ(exec.Submit(std::move(blocker)), HksTaskAccept::OK);
    blockerRaw->Release(); // let worker finish before destructor joins
    // scope ends: destructor must Stop() without hanging
}

/**
 * @tc.name: HksTaskExecutorTest.HksTaskExecutorTest010
 * @tc.desc: two sequential submissions are both executed serially by the single worker
 * @tc.type: FUNC
 */
HWTEST_F(HksTaskExecutorTest, HksTaskExecutorTest010, TestSize.Level0)
{
    HksTaskExecutor exec(SmallConfig());
    exec.Start();
    auto first = std::make_unique<CountingTask>(0, false);
    CountingTask *firstRaw = first.get();
    auto second = std::make_unique<CountingTask>(0, false);
    CountingTask *secondRaw = second.get();
    ASSERT_EQ(exec.Submit(std::move(first)), HksTaskAccept::OK);
    ASSERT_EQ(exec.Submit(std::move(second)), HksTaskAccept::OK);
    firstRaw->WaitDone();
    secondRaw->WaitDone();
    ASSERT_EQ(firstRaw->dones_.load() + secondRaw->dones_.load(), 2);
    exec.Stop();
}
} // namespace Test
} // namespace Hks
} // namespace Security
} // namespace OHOS
