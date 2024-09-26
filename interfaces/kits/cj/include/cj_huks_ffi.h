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

#ifndef CJ_HUKS_FFI_H
#define CJ_HUKS_FFI_H

#include "hks_param.h"
#include "hks_errcode_adapter.h"

#define FFI_EXPORT __attribute__((visibility("default")))

FFI_EXPORT int32_t FfiOHOSGetSdkVersion(struct HksBlob *sdkVersion);

FFI_EXPORT int32_t FfiOHOSInitSession(const char *keyAlias, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token);

FFI_EXPORT int32_t FfiOHOSUpdateSession(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData);

FFI_EXPORT int32_t FfiOHOSFinishSession(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData);

FFI_EXPORT int32_t FfiOHOSAbortSession(const struct HksBlob *handle, const struct HksParamSet *paramSet);

FFI_EXPORT int32_t FfiOHOSIsKeyExist(const char *keyAlias, const struct HksParamSet *paramSet);

FFI_EXPORT int32_t FfiOHOSGetKeyItemProperties(const char *keyAlias,
    const struct HksParamSet *paramSetIn, struct HksParamSet *paramSetOut);

FFI_EXPORT int32_t FfiOHOSHAttestKey(const char *keyAlias, const struct HksParamSet *paramSet,
    struct HksCertChain *certChain);

FFI_EXPORT int32_t FfiOHOSHAnonAttestKey(const char *keyAlias, const struct HksParamSet *paramSet,
    struct HksCertChain *certChain);

FFI_EXPORT int32_t FfiOHOSExportKey(const char *keyAlias, const struct HksParamSet *paramSet, struct HksBlob *key);

FFI_EXPORT int32_t FfiOHOSImportWrappedKey(const char *keyAlias, const char *wrappingKeyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData);

FFI_EXPORT int32_t FfiOHOSGenerateKey(const char *keyAlias, const struct HksParamSet *paramSetIn,
    struct HksParamSet *paramSetOut);

FFI_EXPORT int32_t FfiOHOSDeleteKey(const char *keyAlias, const struct HksParamSet *paramSet);

FFI_EXPORT int32_t FfiOHOSImportKey(const char *keyAlias, const struct HksParamSet *paramSet, struct HksBlob *key);

FFI_EXPORT int32_t FfiOHOSListAliases(const struct HksParamSet *paramSet, uint32_t *retAliasesCnt,
    struct HksBlob **retAliases);

FFI_EXPORT void FfiOHOSConvertErrCode(int32_t hksCode, struct HksResult *ret);

#endif