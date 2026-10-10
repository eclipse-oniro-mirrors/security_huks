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

#ifndef HKS_UKEY_ASYNC_SUBMIT_H
#define HKS_UKEY_ASYNC_SUBMIT_H

#include <cstdint>

#include "hks_type.h"
#include "iremote_object.h"
#include "message_parcel.h"

namespace OHOS {
namespace Security {
namespace Hks {

// ukey decision for reused standard codes (GEN_KEY/EXPORT_PUBLIC_KEY/IMPORT_WRAPPED_KEY/
// INIT/UPDATE/FINISH/ABORT): properly unpacks the embedded paramSet from srcData; the operation
// is a ukey operation only when KEY_CLASS == EXTENSION.
bool HksIsUkeyStandardMsgCode(uint32_t code, const struct HksBlob &srcData);

// Two-mode decision + async submission (ukey async refactor).
// Returns true = the async path was taken (the caller returns the admission receipt directly);
// false = no callback object present (legacy client, the caller continues the legacy sync path).
// Call only for codes in the ukey coverage set, and only before the legacy INIT block.
// context = IPC-thread context (for identity resolution, passed in by the caller).
bool HksTrySubmitUkeyAsyncMsg(uint32_t code, MessageParcel &data, uint32_t outSize,
    const struct HksBlob &srcData, const uint8_t *context);

} // namespace Hks
} // namespace Security
} // namespace OHOS

#endif // HKS_UKEY_ASYNC_SUBMIT_H
