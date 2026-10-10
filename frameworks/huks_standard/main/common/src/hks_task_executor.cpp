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

#include "hks_task_executor.h"

#include <utility>

#include "hks_log.h"
#include "hks_template.h"

namespace OHOS {
namespace Security {
namespace Hks {

namespace {
// Error code delivered via OnDone when Stop drops queued tasks (service-stopped class error;
// clients get an explicit failure instead of waiting for a full timeout)
constexpr int32_t HKS_TASK_DISCARDED_ERR = -59; // Same family as HKS_ERROR_COMMUNICATION_ERROR

// Joins each worker and clears the container. clear after join is mandatory: the executor
// supports Stopped->Running restart (when a delayed unload is cancelled by a new registration);
// if stale joined tids remained in the container, the next Stop would pthread_join them again,
// which POSIX defines as undefined behavior (and pthread_t may be reused by the kernel, so
// joining a live thread would hang). Caller guarantees this is not invoked while holding the lock.
void JoinAllWorkers(std::vector<pthread_t> &workers)
{
    for (auto &w : workers) {
        if (w != 0) {
            (void)pthread_join(w, nullptr);
        }
    }
    workers.clear();
}
} // namespace

// pthread_create callback (static member so it can reach the private WorkerLoop; std::thread
// cannot configure the stack size, so a configurable stack requires a raw function pointer
// plus pthread_attr_setstacksize)
void *HksTaskExecutor::WorkerEntry(void *arg)
{
    static_cast<HksTaskExecutor *>(arg)->WorkerLoop();
    return nullptr;
}

HksTaskExecutor::HksTaskExecutor(Config cfg) : cfg_(cfg)
{
    // LoadedIdle: workers are not created until Start() (see the lifetime notes in the header)
}

HksTaskExecutor::~HksTaskExecutor()
{
    Stop();
}

void HksTaskExecutor::Start()
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (state_ == State::Running) {
        return; // idempotent: already started
    }
    if (state_ == State::Stopped) {
        // Restart: restore service when a delayed unload is cancelled by a new registration
        // (dlclose did not happen). The previous Stop already joined all workers; recreate
        // them here and reset stop_.
        stop_ = false;
    }
    pthread_attr_t attr;
    (void)pthread_attr_init(&attr);
    if (cfg_.workerStackSize > 0) {
        // Stack size is configurable (0 = system default)
        (void)pthread_attr_setstacksize(&attr, cfg_.workerStackSize);
    }
    for (size_t i = 0; i < cfg_.workerCount; ++i) {
        pthread_t tid = 0;
        int rc = pthread_create(&tid, &attr, &HksTaskExecutor::WorkerEntry, this);
        if (rc != 0) {
            // Worker creation failed (resource-exhaustion level): mark unavailable so Submit
            // always returns STOPPED; notify already-created workers to exit and join them.
            HKS_LOG_E("HksTaskExecutor create worker fail rc=%{public}d", rc);
            (void)pthread_attr_destroy(&attr);
            stop_ = true;
            state_ = State::Stopped;
            lock.unlock();
            cv_.notify_all();
            JoinAllWorkers(workers_);
            lock.lock();
            workersDone_ = true; // all workers joined; subsequent Stop() will not block
            lock.unlock();
            drainedCv_.notify_all();
            return;
        }
        workers_.push_back(tid);
    }
    (void)pthread_attr_destroy(&attr);
    state_ = State::Running;
    HKS_LOG_I("HksTaskExecutor started, workers=%{public}zu stack=%{public}zu",
        cfg_.workerCount, cfg_.workerStackSize);
}

HksTaskAccept HksTaskExecutor::Submit(std::unique_ptr<HksAsyncTask> task)
{
    if (task == nullptr) {
        return HksTaskAccept::INVALID;
    }
    std::unique_lock<std::mutex> lock(mutex_);
    if (state_ != State::Running || stop_) {
        // Not started (LoadedIdle) or already stopped -> STOPPED (also covers the unload race window)
        return HksTaskAccept::STOPPED;
    }
    // (1) Capacity backpressure: in-flight (executing + queued) >= workerCount + maxPending -> BUSY
    //     (no blocking, no unbounded queueing).
    if (pending_ >= cfg_.workerCount + cfg_.maxPending) {
        return HksTaskAccept::BUSY;
    }
    // (2) Wait-window cap: task deadline over the limit (DeadlineMs > maxTimeoutMs) -> INVALID.
    //     Client/server validation normally intercepts this; this is the last line of defense
    //     (defense in depth against outlier values).
    if (task->DeadlineMs() > cfg_.maxTimeoutMs) {
        return HksTaskAccept::INVALID;
    }
    queue_.push_back(std::move(task));
    ++pending_;
    lock.unlock();
    cv_.notify_one();
    return HksTaskAccept::OK;
}

void HksTaskExecutor::WorkerLoop()
{
    bool keepRunning = true;
    while (keepRunning) {
        std::unique_ptr<HksAsyncTask> task;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return stop_ || !queue_.empty(); });
            if (!stop_) {
                task = std::move(queue_.front());
                queue_.pop_front();
            } else {
                keepRunning = false;
            }
        }
        if (task == nullptr) {
            // Stopped: the in-flight task has finished; queued tasks were drained by Stop
            // (OnDone called on each), so the worker exits here.
            break;
        }
        ExecuteTask(std::move(task));
        {
            std::lock_guard<std::mutex> lock(mutex_);
            --pending_;
        }
    }
}

void HksTaskExecutor::ExecuteTask(std::unique_ptr<HksAsyncTask> task)
{
    // Exceptions are disabled at compile time (-fno-exceptions): Run/OnDone must not throw;
    // business errors propagate via return values (adapter contract). The task object
    // (including deep-copied data) is destroyed when the scope ends (sensitive-data wiping is
    // the task destructor's responsibility).
    int32_t ret = task->Run();
    task->OnDone(ret);
}

void HksTaskExecutor::DrainQueuedTasks(std::unique_lock<std::mutex> &lock)
{
    // Deliver OnDone to each queued task before dropping it (otherwise clients wait for a full timeout)
    while (!queue_.empty()) {
        auto task = std::move(queue_.front());
        queue_.pop_front();
        --pending_;
        lock.unlock();
        task->OnDone(HKS_TASK_DISCARDED_ERR); // -fno-exceptions: must not throw (adapter contract)
        lock.lock();
    }
}

void HksTaskExecutor::Stop()
{
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (stop_) {
            // Re-entry wait: the second caller waits until the first Stop has finished draining
            // before returning (it must not return early, otherwise the caller could trigger
            // dlclose while workers are still running, causing an unload race).
            drainedCv_.wait(lock, [this] { return workersDone_; });
            return;
        }
        stop_ = true;
        state_ = State::Stopped;
        DrainQueuedTasks(lock);
    }
    cv_.notify_all();
    JoinAllWorkers(workers_);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        workersDone_ = true;
    }
    drainedCv_.notify_all();
    HKS_LOG_I("HksTaskExecutor stopped, all workers joined");
}

uint32_t HksTaskExecutor::PendingCount() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_;
}

} // namespace Hks
} // namespace Security
} // namespace OHOS
