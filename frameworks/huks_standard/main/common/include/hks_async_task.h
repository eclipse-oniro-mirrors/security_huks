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

#ifndef HKS_ASYNC_TASK_H
#define HKS_ASYNC_TASK_H

#include <cstdint>

namespace OHOS {
namespace Security {
namespace Hks {

/*
 * Generic asynchronous task abstraction.
 * The thread pool is agnostic to the business type; adapters implement three hooks:
 *   Run()        Executes the actual call on a worker thread (may block, e.g. a nested
 *                binder synchronous call), returns the result code.
 *   OnDone(ret)  Called by the thread pool on the worker thread after Run() returns,
 *                used to deliver the result back. After OnDone() returns, the thread pool
 *                releases the task object, so the deep-copied data and callback references
 *                held by the task remain valid until then (deterministic lifetime).
 *   DeadlineMs() Expected execution duration in milliseconds; used only for the outlier
 *                check in Submit (rejected when > maxTimeoutMs) and for DFX monitoring,
 *                not as a queue admission criterion. 0 = no limit.
 */
class HksAsyncTask {
public:
    virtual ~HksAsyncTask() = default;

    virtual int32_t Run() = 0;

    virtual void OnDone(int32_t ret) = 0;

    virtual uint32_t DeadlineMs() const
    {
        return 0;
    }
};

} // namespace Hks
} // namespace Security
} // namespace OHOS

#endif // HKS_ASYNC_TASK_H
