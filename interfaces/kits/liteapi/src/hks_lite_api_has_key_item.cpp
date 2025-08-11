/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define HUKS_DISABLE_LOG_AT_FILE_TO_REDUCE_ROM_SIZE

#include "hks_lite_api.h"
#include "jsi.h"
#include "jsi_types.h"

#include "hks_api.h"
#include "hks_param.h"
#include "hks_lite_api_common.h"
#include "hks_log.h"

namespace OHOS {
namespace ACELite {

JSIValue HksLiteModule::hasKeyItem(const JSIValue thisVal, const JSIValue* args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;

    JSIValue undefValue = JSI::CreateUndefined();
    uint32_t minNumArgs = 3;
    if (argsNum < minNumArgs || args == nullptr) {
        HKS_LOG_E("hasKeyItem args invalid, args num(%{public}d).", argsNum);
        return undefValue;
    }

    HksCallbackResultFailure(thisVal, args[ARGS_INDEX_2], HKS_ERROR_API_NOT_SUPPORTED);
    return undefValue;
}
}
}