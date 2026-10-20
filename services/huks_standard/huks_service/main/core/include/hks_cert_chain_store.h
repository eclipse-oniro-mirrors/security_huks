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

#ifndef HKS_CERT_CHAIN_STORE_H
#define HKS_CERT_CHAIN_STORE_H

#include <stdbool.h>
#include <stdint.h>
#include "hks_param.h"
#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

void HksCertChainStoreOnAttestSuccess(uint32_t uid, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *certChain);

int32_t HksCertChainStoreLoadChallenge(uint32_t uid, const struct HksBlob *keyAlias, struct HksBlob *challenge);

int32_t HksCertChainStoreLoadCertChain(uint32_t uid, const struct HksBlob *keyAlias, struct HksBlob *certChain);

void HksCertChainStoreRemove(uint32_t uid, const struct HksBlob *keyAlias);

bool HksCertChainStoreContains(uint32_t uid, const struct HksBlob *keyAlias);

int32_t HksCertChainStoreSave(uint32_t uid, const struct HksBlob *keyAlias, const struct HksBlob *certChain);

#ifdef __cplusplus
}
#endif

#endif /* HKS_CERT_CHAIN_STORE_H */