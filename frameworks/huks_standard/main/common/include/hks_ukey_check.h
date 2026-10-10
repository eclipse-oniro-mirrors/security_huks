/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#ifndef HKS_UKEY_CHECK_H
#define HKS_UKEY_CHECK_H

#include <stdint.h>
#include <stdbool.h>
#include "hks_type.h"
#include "hks_plugin_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksCheckIsUkeyOperation(const struct HksParamSet *paramSet, int32_t *outRet);

// ukey timeout tag selection (shared by client and server, single source of truth):
// reused standard codes -> HKS_TAG_TIME_OUT(529); ukey native codes -> HKS_EXT_CRYPTO_TAG_TIMEOUT(200006)
enum HksTag HksUkeyTimeoutTagByMsgCode(uint32_t msgCode);

#ifdef __cplusplus
}
#endif

#endif