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

#include "hks_plugin_adapter.h"
#include "hks_log.h"
#include "hks_type.h"

void HksInitPluginProxyMutex(void)
{
    HKS_LOG_I("Unsupport extension plugin!");
}

int32_t HksCreatePluginProxy(void)
{
    HKS_LOG_I("Unsupport extension plugin!");
    return HKS_SUCCESS;
}

void HksDestoryPluginProxy(void)
{
    HKS_LOG_I("Unsupport extension plugin!");
}

struct HksPluginProxy *HksGetPluginProxy(void)
{
    HKS_LOG_I("Unsupport extension plugin!");
    return NULL;
}