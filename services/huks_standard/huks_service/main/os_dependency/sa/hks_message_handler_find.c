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

#include "hks_message_handler.h"

#include <stddef.h>

// ukey async refactor: unified handler table lookup (single source of truth; the legacy path
// and task dispatch share the same table)

HksIpcHandlerFuncProc HksFindMessageHandler(enum HksIpcInterfaceCode msgId)
{
    size_t size = sizeof(HKS_IPC_MESSAGE_HANDLER) / sizeof(HKS_IPC_MESSAGE_HANDLER[0]);
    for (size_t i = 0; i < size; ++i) {
        if (msgId == HKS_IPC_MESSAGE_HANDLER[i].msgId) {
            return HKS_IPC_MESSAGE_HANDLER[i].handler;
        }
    }
    return NULL;
}

HksIpcThreeStageHandlerFuncProc HksFindThreeStageHandler(enum HksIpcInterfaceCode msgId)
{
    size_t size = sizeof(HKS_IPC_THREE_STAGE_HANDLER) / sizeof(HKS_IPC_THREE_STAGE_HANDLER[0]);
    for (size_t i = 0; i < size; ++i) {
        if (msgId == HKS_IPC_THREE_STAGE_HANDLER[i].msgId) {
            return HKS_IPC_THREE_STAGE_HANDLER[i].handler;
        }
    }
    return NULL;
}
