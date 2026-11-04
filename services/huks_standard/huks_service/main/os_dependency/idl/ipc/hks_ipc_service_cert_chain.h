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

#ifndef HKS_IPC_SERVICE_CERT_CHAIN_H
#define HKS_IPC_SERVICE_CERT_CHAIN_H

#include "hks_type_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

/* IPC handlers for ANCO broker cert-chain and storage operations. */

void HksIpcServiceGetAnonCertChain(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceGetCertChain(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceSetStorage(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceGetStorage(const struct HksBlob *srcData, const uint8_t *context);

void HksIpcServiceStorageExist(const struct HksBlob *srcData, const uint8_t *context);

#ifdef __cplusplus
}
#endif

#endif /* HKS_IPC_SERVICE_CERT_CHAIN_H */