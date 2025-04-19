/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef HKS_CLIENT_SERVICE_UTIL_H
#define HKS_CLIENT_SERVICE_UTIL_H

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_type.h"
#include "hks_session_manager.h"
#include "hks_storage_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t GetKeyParamSet(const struct HksBlob *key, struct HksParamSet *paramSet);

#ifndef _STORAGE_LITE_
int32_t GetKeyFileData(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, struct HksBlob *key, enum HksStorageType mode);

#ifdef HKS_ENABLE_UPGRADE_KEY
int32_t ConstructUpgradeKeyParamSet(const struct HksProcessInfo *processInfo, const struct HksParamSet *srcParamSet,
    struct HksParamSet **outParamSet);
#endif /* HKS_ENABLE_UPGRADE_KEY */

#endif /* _STORAGE_LITE_ */

int32_t AppendStorageLevelIfNotExistInner(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksParamSet **outParamSet);

bool CheckProcessNameTagExist(const struct HksParamSet *paramSet);

int32_t AppendProcessInfoAndDefaultStrategy(const struct HksParamSet *paramSet,
    const struct HksProcessInfo *processInfo, const struct HksOperation *operation, struct HksParamSet **outParamSet);

// callback
int32_t AppendNewInfoForGenKeyInService(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksParamSet **outParamSet);

int32_t AppendNewInfoForUseKeyInService(const struct HksParamSet *paramSet,
    const struct HksProcessInfo *processInfo, struct HksParamSet **outParamSet);

int32_t AppendStorageLevelIfNotExist(const struct HksParamSet *paramSet, struct HksParamSet **outParamSet);

#ifdef __cplusplus
}
#endif

#endif
