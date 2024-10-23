/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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


#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_core_get_main_key.h"
#include "hks_ability.h"
#include "securec.h"

#ifndef _HARDWARE_ROOT_KEY_
#include "hks_rkc.h"

#ifdef L2_STANDARD
static int32_t L2CoreGetMainKey(struct HksBlob *mainKey)
{
#ifdef HKS_USE_RKC_IN_STANDARD
    return HksRkcGetMainKey(mainKey);
#else
    (void)mainKey;
    return HKS_ERROR_NOT_SUPPORTED;
#endif
}
#endif
#endif

int32_t HksCoreGetMainKey(const struct HksBlob *message, struct HksBlob *mainKey)
{
    (void)message;

#ifndef _HARDWARE_ROOT_KEY_

#ifdef L2_STANDARD
    return L2CoreGetMainKey(mainKey)
#else
   return HksRkcGetMainKey(mainKey);
#endif

#else
    /*
     * Currently, root key is implemented using stubs.
     * Product adaptation needs to be performed based on hardware capabilities.
     */
    uint8_t stubBuf[] = {
        0x0c, 0xb4, 0x29, 0x39, 0xb7, 0x46, 0xa6, 0x4b,
        0xdd, 0xf3, 0x75, 0x4c, 0xe0, 0x73, 0x91, 0x51,
        0xc4, 0x88, 0xbe, 0xa4, 0xe1, 0x87, 0xb5, 0x42,
        0x06, 0x27, 0x08, 0x21, 0xe2, 0x8f, 0x9b, 0xc1,
    };

    if (memcpy_s(mainKey->data, mainKey->size, stubBuf, sizeof(stubBuf)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    return HKS_SUCCESS;
#endif
}

void RegisterAbilityGetMainKey(void)
{
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GET_MAIN_KEY, (void *)HksCoreGetMainKey);
}