/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef HKS_SESSION_MANAGER_H
#define HKS_SESSION_MANAGER_H

#include <stdbool.h>
#include <stdint.h>

#include "hks_double_list.h"
#include "hks_event_info.h"
#include "hks_type_inner.h"

struct HksOperation {
    struct DoubleList listHead;
    struct HksProcessInfo processInfo;
    HksEventInfo eventInfo;
    uint64_t handle;
    bool abortable;
    uint64_t accessTokenId;
    bool isInUse;
    uint64_t batchOperationTimestamp;
    bool isBatchOperation;
    bool isUserIdPassedDuringInit;
    int userIdPassedDuringInit;
    int32_t pid;
    struct HksBlob errMsgBlob;
    uint64_t startTime;
};

#ifdef __cplusplus
extern "C" {
#endif

int32_t CreateOperation(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *operationHandle, bool abortable);

struct HksOperation *QueryOperationAndMarkInUse(const struct HksProcessInfo *processInfo,
    const struct HksBlob *operationHandle);

struct HksOperation *QueryOperationByPidAndMarkInUse(int32_t pid);

void MarkOperationUnUse(struct HksOperation *operation);

void DeleteOperation(const struct HksBlob *operationHandle);

void DeleteSessionByProcessInfo(const struct HksProcessInfo *processInfo);

#ifdef __cplusplus
}
#endif

#endif
