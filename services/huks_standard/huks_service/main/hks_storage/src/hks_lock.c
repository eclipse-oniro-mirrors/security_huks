/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "hks_lock.h"

#include <stddef.h>

#include "hks_mem.h"
#include "hks_rwlock.h"
#include "hks_template.h"

struct HksLock {
    HksRwlock *lock;
};

HksLock *HksLockCreate(void)
{
    HksLock *lock = (HksLock *)HksMalloc(sizeof(HksLock));
    if (lock != NULL) {
        lock->lock = HksRwlockCreate();
        if (lock->lock == NULL) {
            HKS_FREE(lock);
            lock = NULL;
        }
    }
    return lock;
}

int32_t HksLockLockRead(HksLock *lock)
{
    HKS_IF_NULL_RETURN(lock, -1)

    return HksRwlockLockRead(lock->lock);
}

int32_t HksLockUnlockRead(HksLock *lock)
{
    HKS_IF_NULL_RETURN(lock, -1)

    return HksRwlockUnlockRead(lock->lock);
}

int32_t HksLockLockWrite(HksLock *lock)
{
    HKS_IF_NULL_RETURN(lock, -1)

    return HksRwlockLockWrite(lock->lock);
}

int32_t HksLockUnlockWrite(HksLock *lock)
{
    HKS_IF_NULL_RETURN(lock, -1)

    return HksRwlockUnlockWrite(lock->lock);
}

void HksLockClose(HksLock *lock)
{
    HKS_IF_NULL_RETURN_VOID(lock)
    HksRwlockClose(lock->lock);
    HKS_FREE(lock);
}
