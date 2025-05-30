/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef HKS_IPC_SERIALIZATION_H
#define HKS_IPC_SERIALIZATION_H

#include <stdbool.h>
#include <stdint.h>

#include "hks_type_inner.h"

#define MAX_IPC_BUF_SIZE    0x10000   /* Maximun IPC message buffer size. */
#define MAX_IPC_RSV_SIZE    0x400     /* Reserve IPC message buffer size */
#define MAX_PROCESS_SIZE    (MAX_IPC_BUF_SIZE - MAX_IPC_RSV_SIZE)

#ifdef __cplusplus
extern "C" {
#endif

int32_t CopyUint32ToBuffer(uint32_t value, const struct HksBlob *destBlob, uint32_t *destOffset);

int32_t HksGenerateKeyPack(struct HksBlob *destData, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, const struct HksBlob *keyOut);

int32_t HksImportKeyPack(struct HksBlob *destData, const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *key);

int32_t HksImportWrappedKeyPack(struct HksBlob *destData, const struct HksBlob *keyAlias,
    const struct HksBlob *wrappingKeyAlias, const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData);

int32_t HksDeleteKeyPack(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet, struct HksBlob *destData);

int32_t HksExportPublicKeyPack(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *key, struct HksBlob *destData);

int32_t HksGetKeyParamSetPack(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *keyOut, struct HksBlob *destData);

int32_t HksKeyExistPack(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet, struct HksBlob *destData);

int32_t HksOnceParamPack(struct HksBlob *destData, const struct HksBlob *key, const struct HksParamSet *paramSet,
    uint32_t *offset);

int32_t HksOnceDataPack(struct HksBlob *destData, const struct HksBlob *inputData, const struct HksBlob *rsvData,
    const struct HksBlob *outputData, uint32_t *offset);

int32_t HksAgreeKeyPack(struct HksBlob *destData, const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, const struct HksBlob *agreedKey);

int32_t HksDeriveKeyPack(struct HksBlob *destData, const struct HksParamSet *paramSet, const struct HksBlob *kdfKey,
    const struct HksBlob *derivedKey);

int32_t HksGetKeyInfoListPack(const struct HksParamSet *paramSet, const struct HksKeyInfo *keyInfoList,
    struct HksBlob *destData, uint32_t listCount);

int32_t HksGetKeyInfoListUnpackFromService(const struct HksBlob *srcData, uint32_t *listCount,
    struct HksKeyInfo *keyInfoList);

int32_t HksCertificateChainPack(struct HksBlob *destData, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *certChainBlob);

int32_t HksCertificateChainUnpackFromService(const struct HksBlob *srcData, bool needEncode,
    struct HksCertChain *certChain);

int32_t HksParamsToParamSet(struct HksParam *params, uint32_t cnt, struct HksParamSet **outParamSet);

int32_t EncodeCertChain(const struct HksBlob *inBlob, struct HksBlob *outBlob);

int32_t HksListAliasesPack(const struct HksParamSet *srcParamSet, struct HksBlob *destData);

int32_t HksListAliasesUnpackFromService(const struct HksBlob *srcData, struct HksKeyAliasSet **destData);

int32_t HksRenameKeyAliasPack(const struct HksBlob *oldKeyAlias, const struct HksBlob *newKeyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *destData);

int32_t HksChangeStorageLevelPack(struct HksBlob *destData, const struct HksBlob *keyAlias,
    const struct HksParamSet *srcParamSet, const struct HksParamSet *destParamSet);

int32_t HksWrapKeyPack(struct HksBlob *inBlob, const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksBlob *wrappedKey);

int32_t HksUnwrapKeyPack(struct HksBlob *inBlob, const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *wrappedKey);

#ifdef __cplusplus
}
#endif

#endif /* HKS_IPC_SERIALIZATION_H */