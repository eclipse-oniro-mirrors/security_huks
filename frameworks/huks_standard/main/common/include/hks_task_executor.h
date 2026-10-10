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

#ifndef HKS_TASK_EXECUTOR_H
#define HKS_TASK_EXECUTOR_H

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <vector>

#include "hks_async_task.h"

namespace OHOS {
namespace Security {
namespace Hks {

// Submission result (admission decision)
enum class HksTaskAccept {
    OK,       // Accepted (queued; a worker will execute it)
    BUSY,     // Capacity full (in-flight >= workerCount + maxPending); rejected without blocking the caller
    STOPPED,  // Not started or already stopped
    INVALID,  // Invalid input (nullptr task, or task deadline exceeds the limit)
};

/*
 * Generic thread pool: moves long-running binder client synchronous calls (which cannot
 * run on the binder server thread) off the IPC thread.
 *
 * Lifetime (owned by the ukey plugin SO, tied to SO load/unload):
 *   - Construction leaves the pool in LoadedIdle state; no threads are created (avoids
 *     the timing risk of a static initializer spawning threads during dlopen).
 *   - Start() is idempotent and spawns workerCount workers (called at the end of the
 *     successful registration path in the SO). A Stopped pool can be restarted (when a
 *     delayed unload is cancelled by a new registration and dlclose does not happen).
 *   - Stop() is only for the unload sequence (in the delayed dlclose thread, before
 *     dlclose) and is not reachable on the normal request path:
 *       1. Rejects new submissions (Submit -> STOPPED).
 *       2. Drains queued tasks, calling OnDone(error) on each before dropping them
 *          (so clients get an explicit failure instead of waiting for a full timeout).
 *       3. Waits for in-flight tasks to finish (the nested synchronous call cannot be
 *          interrupted, at most 60s) and then joins the workers.
 *     Re-entry means "wait": a second caller waits until the first Stop has drained
 *     everything before returning (it must not return early, otherwise the caller could
 *     trigger dlclose while workers are still running, causing an unload race).
 *   Caller constraint: Stop must be invoked after releasing the host SO reference lock
 *   (the worker dispatch path's reference RAII needs the same lock; joining while holding
 *   it would deadlock with in-flight workers).
 *
 * Threading model: submission never blocks (the Submit lock critical section is O(1));
 * idle workers block on a condition variable and consume no CPU.
 */
class HksTaskExecutor {
public:
    struct Config {
        // Worker count: fixed at 1. The ukey business orchestration (session/handle tables,
        // provider proxies, etc.) is not concurrency-safe; parallel workers would introduce
        // races. Serial execution with bounded queuing (BUSY backpressure) guarantees safety.
        // Also, each worker's resident stack pages are the main contributor to the new static
        // RSS (4->1 further reduces the peak memory regression).
        size_t workerCount = 1;
        size_t maxPending = 8;           // Bounded queue capacity (total = workerCount + maxPending = 9)
        // Task deadline upper bound (ms, 15 min); bounds the client wait window,
        // last line of defense for outliers.
        uint32_t maxTimeoutMs = 900000;
        // Worker thread stack size (bytes; 0 = system default). The ukey nested call stack is
        // deep; tune down (e.g. 512KB) by measured stack depth on the target device to lower peak
        // memory. Too small a value will overflow the worker stack.
        size_t workerStackSize = 0;
    };

    explicit HksTaskExecutor(Config cfg);
    ~HksTaskExecutor(); // RAII: Stop() (only reachable on the process exit path; normal shutdown goes through Stop())

    HksTaskExecutor(const HksTaskExecutor &) = delete;
    HksTaskExecutor &operator=(const HksTaskExecutor &) = delete;

    // Explicit start (idempotent): spawns workerCount workers. On failure the pool is marked
    // unavailable; Submit always returns STOPPED.
    void Start();

    // Task submission (called by the IPC thread via the SO-exported handle); never blocks the
    // calling thread.
    HksTaskAccept Submit(std::unique_ptr<HksAsyncTask> task);

    // Stops and waits for all workers to exit. Constraint: only callable from the SA-side
    // delayed dlclose thread (never from a worker thread or inside an SO-exported function).
    void Stop();

    // Number of in-flight tasks (executing + queued), lock-protected.
    uint32_t PendingCount() const;

private:
    static void *WorkerEntry(void *arg); // pthread_create callback (entry point into the private WorkerLoop)
    void WorkerLoop();
    void ExecuteTask(std::unique_ptr<HksAsyncTask> task);
    // Called by Stop: delivers OnDone to each queued task before dropping it.
    void DrainQueuedTasks(std::unique_lock<std::mutex> &lock);

    enum class State { LoadedIdle, Running, Stopped };

    Config cfg_;
    State state_ = State::LoadedIdle;   // lock-protected
    std::vector<pthread_t> workers_;    // created via pthread_create (std::thread cannot set the stack size)
    std::deque<std::unique_ptr<HksAsyncTask>> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;         // Worker waits for a non-empty queue / stop
    std::condition_variable drainedCv_;  // Stop re-entry wait (waits for the first Stop to finish)
    bool stop_ = false;                  // lock-protected
    bool workersDone_ = false;           // lock-protected; Stop completion flag
    uint32_t pending_ = 0;               // lock-protected (executing + queued)
};

} // namespace Hks
} // namespace Security
} // namespace OHOS

#endif // HKS_TASK_EXECUTOR_H
