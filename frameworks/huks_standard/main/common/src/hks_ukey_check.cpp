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

#include "hks_ukey_check.h"
#include "hilog/log_c.h"
#include "hks_cpp_paramset.h"
#include "hks_error_code.h"
#include "hks_log.h"
#include "securec.h"
#include "hks_template.h"
#include "hks_mem.h"
#include <string>
#include <vector>
#include "hks_common_check.h"
#include "huks_service_ipc_interface_code.h"

int32_t HksCheckIsUkeyOperation(const struct HksParamSet *paramSet, int32_t *outRet)
{
    int32_t ret = HksCheckParamSetValidity(paramSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksCheckParamSetValidity fail. ret: %" LOG_PUBLIC "d", ret);
    CppParamSet paramSetCpp(paramSet);
    auto keyClass = paramSetCpp.GetParam<HKS_TAG_KEY_CLASS>();
    if (keyClass.first == HKS_SUCCESS) {
        if (keyClass.second != HKS_KEY_CLASS_EXTENSION && keyClass.second != HKS_KEY_CLASS_DEFAULT) {
            HKS_LOG_E("Invalid HKS_TAG_KEY_CLASS");
            *outRet = HKS_ERROR_INVALID_ARGUMENT;
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        if (keyClass.second == HKS_KEY_CLASS_EXTENSION) {
            HKS_LOG_I("is ukey operation");
            return HKS_SUCCESS;
        }
    }
    return HKS_ERROR_INVALID_ARGUMENT;
}

// Coverage set = 10 ukey-native extension codes + 7 reused standard codes; standard codes read
// HKS_TAG_TIME_OUT(529), extension codes always read HKS_EXT_CRYPTO_TAG_TIMEOUT(200006). Called
// only for the ukey async coverage set; other message codes fall back to 200006 (defensive; the
// caller has already done the ukey check).
enum HksTag HksUkeyTimeoutTagByMsgCode(uint32_t msgCode)
{
    switch (msgCode) {
        case HKS_MSG_GEN_KEY:
        case HKS_MSG_EXPORT_PUBLIC_KEY:
        case HKS_MSG_IMPORT_WRAPPED_KEY:
        case HKS_MSG_INIT:
        case HKS_MSG_UPDATE:
        case HKS_MSG_FINISH:
        case HKS_MSG_ABORT:
            return HKS_TAG_TIME_OUT;
        default:
            return HKS_EXT_CRYPTO_TAG_TIMEOUT;
    }
}
