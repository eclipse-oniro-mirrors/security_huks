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

#include "hks_session_manager.h"
#include "hks_client_service_util.h"

#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <securec.h>
#include <stdio.h>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"
#include "huks_access.h"
#include "securec.h"
#include "hks_util.h"

#define MAX_OPERATIONS_COUNT 96

#ifdef HKS_SUPPORT_ACCESS_TOKEN
#define MAX_OPERATIONS_EACH_TOKEN_ID 32
#else
#define MAX_OPERATIONS_EACH_TOKEN_ID MAX_OPERATIONS_COUNT
#endif

#define S_TO_MS 1000

static struct DoubleList g_operationList = { &g_operationList, &g_operationList };
static uint32_t g_operationCount = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static void DeleteKeyNode(uint64_t operationHandle)
{
    uint8_t *handle = (uint8_t *)HksMalloc(sizeof(uint64_t));
    HKS_IF_NULL_LOGE_RETURN_VOID(handle, "malloc failed")
    (void)memcpy_s(handle, sizeof(uint64_t), &operationHandle, sizeof(uint64_t));
    struct HksBlob handleBlob = { sizeof(uint64_t), handle };

    struct HksParamSet *paramSet = NULL;
    if (HksInitParamSet(&paramSet) != HKS_SUCCESS) {
        HKS_FREE(handle);
        return;
    }

    (void)HuksAccessAbort(&handleBlob, paramSet);

    HksFreeParamSet(&paramSet);
    HKS_FREE(handle);
}

/* Need to lock before calling FreeOperation */
static void FreeOperation(struct HksOperation **operation)
{
    if (operation == NULL || *operation == NULL) {
        return;
    }
    RemoveDoubleListNode(&(*operation)->listHead);
    HKS_FREE_BLOB((*operation)->processInfo.userId);
    HKS_FREE_BLOB((*operation)->processInfo.processName);
    HKS_FREE(*operation);
}

/* Need to lock before calling DeleteKeyNodeAndDecreaseGlobalCount */
static void DeleteKeyNodeAndDecreaseGlobalCount(struct HksOperation *operation)
{
    DeleteKeyNode(operation->handle);
    FreeOperation(&operation);
    --g_operationCount;
    HKS_LOG_I("delete operation count:%" LOG_PUBLIC "u", g_operationCount);
}

/* Need to lock before calling DeleteFirstAbortableOperation */
static bool DeleteFirstAbortableOperation(void)
{
    struct HksOperation *operation = NULL;

    HKS_DLIST_ITER(operation, &g_operationList) {
        if (operation == NULL) {
            continue;
        }
        if (operation->isInUse) {
            HKS_LOG_W("DeleteFirstAbortableOperation can not delete using session! userIdInt %" LOG_PUBLIC "d",
                operation->processInfo.userIdInt);
            continue;
        }
        HKS_LOG_E("DeleteFirstAbortableOperation delete old not using session! userIdInt %"
            LOG_PUBLIC "d", operation->processInfo.userIdInt);
        DeleteKeyNodeAndDecreaseGlobalCount(operation);
        return true;
    }
    return false;
}

/* Need to lock before calling DeleteFirstTimeOutBatchOperation */
static void DeleteFirstTimeOutBatchOperation(void)
{
    if (g_operationCount < MAX_OPERATIONS_COUNT) {
        return;
    }
    HKS_LOG_I("maximum number of sessions reached: delete timeout session.");
    struct HksOperation *operation = NULL;

    HKS_DLIST_ITER(operation, &g_operationList) {
        if (operation == NULL || !operation->isBatchOperation) {
            continue;
        }
        uint64_t curTime = 0;
        int32_t ret = HksElapsedRealTime(&curTime);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksElapsedRealTime failed %" LOG_PUBLIC "d, err %" LOG_PUBLIC "s", ret, strerror(errno));
            continue; // find next and try again
        }
        if (operation->batchOperationTimestamp >= curTime) {
            continue;
        }
        if (operation->isInUse) {
            HKS_LOG_W("Batch operation timeout but is in use, not delete, userIdInt %" LOG_PUBLIC "d",
                operation->processInfo.userIdInt);
            continue;
        }
        HKS_LOG_E("Batch operation timeout! delete operation! userIdInt %" LOG_PUBLIC "d",
            operation->processInfo.userIdInt);
        // IAR iccarm can not compile `return DeleteKeyNodeAndDecreaseGlobalCount(operation)`
        // IAR iccarm will report `a void function may not return a value`
        DeleteKeyNodeAndDecreaseGlobalCount(operation);
        return;
    }
}

/* Need to lock before calling DeleteFirstAbortableOperationForTokenId */
static bool DeleteFirstAbortableOperationForTokenId(uint32_t tokenId)
{
    struct HksOperation *operation = NULL;
    HKS_DLIST_ITER(operation, &g_operationList) {
        if (operation == NULL || operation->accessTokenId != tokenId) {
            continue;
        }
        if (operation->isInUse) {
            HKS_LOG_W("DeleteFirstAbortableOperationForTokenId can not delete using session! userIdInt %"
                LOG_PUBLIC "d", operation->processInfo.userIdInt);
            continue;
        }
        HKS_LOG_E("DeleteFirstAbortableOperationForTokenId delete old not using session! userIdInt %"
            LOG_PUBLIC "d", operation->processInfo.userIdInt);
        DeleteKeyNodeAndDecreaseGlobalCount(operation);
        return true;
    }
    return false;
}

/* Need to lock before calling DeleteForTokenIdIfExceedLimit */
static int32_t DeleteForTokenIdIfExceedLimit(uint32_t tokenId)
{
    if (g_operationCount < MAX_OPERATIONS_EACH_TOKEN_ID) {
        return HKS_SUCCESS;
    }
    uint32_t ownedSessionCount = 0;
    struct HksOperation *operation = NULL;
    HKS_DLIST_ITER(operation, &g_operationList) {
        if (operation != NULL && operation->accessTokenId == tokenId) {
            ++ownedSessionCount;
        }
    }
    if (ownedSessionCount >= MAX_OPERATIONS_EACH_TOKEN_ID) {
        HKS_LOG_E("current tokenId have owned too many %" LOG_PUBLIC "u sessions", ownedSessionCount);
        if (DeleteFirstAbortableOperationForTokenId(tokenId)) {
            return HKS_SUCCESS;
        }
        return HKS_ERROR_SESSION_REACHED_LIMIT;
    }
    return HKS_SUCCESS;
}

static int32_t AddOperation(struct HksOperation *operation)
{
    pthread_mutex_lock(&g_lock);

    int32_t ret = HKS_ERROR_SESSION_REACHED_LIMIT;
    do {
        DeleteFirstTimeOutBatchOperation();

        ret = DeleteForTokenIdIfExceedLimit(operation->accessTokenId);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "DeleteForTokenIdIfExceedLimit fail %" LOG_PUBLIC "d", ret)

        if (g_operationCount >= MAX_OPERATIONS_COUNT) {
            HKS_LOG_I("maximum number of sessions reached: delete oldest session.");
            if (!DeleteFirstAbortableOperation()) {
                HKS_LOG_E("DeleteFirstAbortableOperation fail!");
                ret = HKS_ERROR_SESSION_REACHED_LIMIT;
                break;
            }
        }

        AddNodeAtDoubleListTail(&g_operationList, &operation->listHead);
        ++g_operationCount;
        HKS_LOG_I("add operation count:%" LOG_PUBLIC "u", g_operationCount);
    } while (false);
    pthread_mutex_unlock(&g_lock);
    return ret;
}

static int32_t ConstructOperationProcessInfo(const struct HksProcessInfo *processInfo, struct HksOperation *operation)
{
    /* userIdLen and processNameLen have been checked by calling function */
    uint32_t userIdLen = processInfo->userId.size;
    uint32_t processNameLen = processInfo->processName.size;

    uint8_t *userId = (uint8_t *)HksMalloc(userIdLen);
    HKS_IF_NULL_LOGE_RETURN(userId, HKS_ERROR_MALLOC_FAIL, "malloc operation userId failed")

    uint8_t *processName = (uint8_t *)HksMalloc(processNameLen);
    if (processName == NULL) {
        HKS_LOG_E("malloc operation process name failed");
        HKS_FREE(userId);
        return HKS_ERROR_MALLOC_FAIL;
    }

    (void)memcpy_s(userId, userIdLen, processInfo->userId.data, userIdLen);
    (void)memcpy_s(processName, processNameLen, processInfo->processName.data, processNameLen);

    operation->processInfo.userId.size = userIdLen;
    operation->processInfo.userId.data = userId;
    operation->processInfo.processName.size = processNameLen;
    operation->processInfo.processName.data = processName;
    operation->accessTokenId = processInfo->accessTokenId;
    return HKS_SUCCESS;
}

static int32_t ConstructOperationHandle(const struct HksBlob *operationHandle, uint64_t *handle)
{
    HKS_IF_TRUE_LOGE_RETURN(operationHandle->size < sizeof(*handle), HKS_ERROR_INVALID_ARGUMENT, "invalid handle size")
    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(handle, sizeof(*handle), operationHandle->data, operationHandle->size),
        HKS_ERROR_INSUFFICIENT_MEMORY, "copy handle failed")

    return HKS_SUCCESS;
}

static int32_t HksAddBatchTimeToOperation(const struct HksParamSet *paramSet, struct HksOperation *operation)
{
    if (paramSet == NULL || operation == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    uint64_t curTime = 0;
    int32_t ret = HksElapsedRealTime(&curTime);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksElapsedRealTime failed")
    bool findOperation = false;
    bool findTimeout = false;
    operation->isBatchOperation = false;
    operation->batchOperationTimestamp = curTime + DEFAULT_BATCH_TIME_OUT * S_TO_MS;
    for (uint32_t i = 0; i < paramSet->paramsCnt; i++) {
        if (paramSet->params[i].tag == HKS_TAG_IS_BATCH_OPERATION) {
            operation->isBatchOperation = paramSet->params[i].boolParam;
            findOperation = true;
            continue;
        }
        if (paramSet->params[i].tag == HKS_TAG_BATCH_OPERATION_TIMEOUT) {
            HKS_IF_TRUE_LOGE_RETURN((uint64_t)paramSet->params[i].uint32Param > MAX_BATCH_TIME_OUT,
                HKS_ERROR_NOT_SUPPORTED, "Batch time is too big.")
            operation->batchOperationTimestamp = curTime + (uint64_t)paramSet->params[i].uint32Param * S_TO_MS;
            findTimeout = true;
            continue;
        }
        HKS_IF_TRUE_BREAK(findOperation && findTimeout)
    }
    if (!findOperation) {
        operation->batchOperationTimestamp = 0;
    }
    return HKS_SUCCESS;
}

int32_t CreateOperation(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *operationHandle, bool abortable)
{
    struct HksOperation *operation = (struct HksOperation *)HksMalloc(sizeof(struct HksOperation));
    HKS_IF_NULL_LOGE_RETURN(operation, HKS_ERROR_MALLOC_FAIL, "malloc hks operation failed")

    int32_t ret = ConstructOperationProcessInfo(processInfo, operation);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("constrtct operation process info failed");
        HKS_FREE(operation);
        return ret;
    }
    do {
        ret = ConstructOperationHandle(operationHandle, &(operation->handle));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "constrtct operation handle failed")

        operation->abortable = abortable;
        operation->isInUse = false;

        ret = HksAddBatchTimeToOperation(paramSet, operation);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add batchtime to operation failed")

        struct HksParam *specificUserIdParam = NULL;
        if (HksGetParam(paramSet, HKS_TAG_SPECIFIC_USER_ID, &specificUserIdParam) == HKS_SUCCESS) {
            operation->isUserIdPassedDuringInit = true;
            operation->userIdPassedDuringInit = specificUserIdParam->int32Param;
        }

        ret = AddOperation(operation);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add operation failed")
        return HKS_SUCCESS;
    } while (0);

    HKS_FREE_BLOB(operation->processInfo.processName);
    HKS_FREE_BLOB(operation->processInfo.userId);
    HKS_FREE(operation);
    return ret;
}

static bool IsSameProcessName(const struct HksProcessInfo *processInfo, const struct HksOperation *operation)
{
    uint32_t processNameLen = operation->processInfo.processName.size;
    return ((processNameLen == processInfo->processName.size) &&
        (memcmp(operation->processInfo.processName.data, processInfo->processName.data, processNameLen) == 0));
}

static bool IsSameUserId(const struct HksProcessInfo *processInfo, const struct HksOperation *operation)
{
    uint32_t userIdLen = operation->processInfo.userId.size;
    return ((userIdLen == processInfo->userId.size) &&
        (memcmp(operation->processInfo.userId.data, processInfo->userId.data, userIdLen) == 0));
}

struct HksOperation *QueryOperationAndMarkInUse(const struct HksProcessInfo *processInfo,
    const struct HksBlob *operationHandle)
{
    uint64_t handle;
    int32_t ret = ConstructOperationHandle(operationHandle, &handle);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, NULL, "construct handle failed when query operation")

    struct HksOperation *operation = NULL;
    pthread_mutex_lock(&g_lock);
    HKS_DLIST_ITER(operation, &g_operationList) {
        if ((operation != NULL) && (operation->handle == handle) && IsSameProcessName(processInfo, operation) &&
            IsSameUserId(processInfo, operation)) {
            if (operation->isInUse) {
                HKS_LOG_E("operation is in use!");
                pthread_mutex_unlock(&g_lock);
                return NULL;
            }
            operation->isInUse = true;
            pthread_mutex_unlock(&g_lock);
            return operation;
        }
    }
    pthread_mutex_unlock(&g_lock);

    return NULL;
}

void MarkOperationUnUse(struct HksOperation *operation)
{
    HKS_IF_NULL_RETURN_VOID(operation)
    operation->isInUse = false;
}

void DeleteOperation(const struct HksBlob *operationHandle)
{
    uint64_t handle;
    int32_t ret = ConstructOperationHandle(operationHandle, &handle);
    HKS_IF_NOT_SUCC_LOGE_RETURN_VOID(ret, "construct handle failed when delete operation")

    struct HksOperation *operation = NULL;
    pthread_mutex_lock(&g_lock);
    HKS_DLIST_ITER(operation, &g_operationList) {
        if (operation != NULL && operation->handle == handle) {
            HKS_IF_TRUE_LOGI_BREAK(operation->isInUse, "operation is in use, do not delete")
            FreeOperation(&operation);
            --g_operationCount;
            HKS_LOG_D("delete operation count:%" LOG_PUBLIC "u", g_operationCount);
            pthread_mutex_unlock(&g_lock);
            return;
        }
    }
    pthread_mutex_unlock(&g_lock);
}

static void DeleteSession(const struct HksProcessInfo *processInfo, struct HksOperation *operation)
{
    if (operation->isInUse) {
        HKS_LOG_E("operation is in use, do not delete");
        return;
    }
    bool isNeedDelete = false;
    if (processInfo->processName.size == 0) { /* delete by user id */
        isNeedDelete = IsSameUserId(processInfo, operation);
    } else { /* delete by process name */
        isNeedDelete = IsSameUserId(processInfo, operation) && IsSameProcessName(processInfo, operation);
    }

    if (isNeedDelete) {
        DeleteKeyNodeAndDecreaseGlobalCount(operation);
    }
}

void DeleteSessionByProcessInfo(const struct HksProcessInfo *processInfo)
{
    struct HksOperation *operation = NULL;

    pthread_mutex_lock(&g_lock);
    HKS_DLIST_SAFT_ITER(operation, &g_operationList) {
        if (operation != NULL) {
            DeleteSession(processInfo, operation);
        }
    }
    pthread_mutex_unlock(&g_lock);
}
