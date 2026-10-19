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

#include "hks_cert_chain_store.h"

#include <securec.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "hks_file_operator.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"

/* Root directories for persisted certificate data. */
#define HKS_CERT_CHAIN_STORE_ROOT       "/data/service/el1/public/huks_service/certchain"
#define HKS_ATTEST_CHALLENGE_STORE_ROOT "/data/service/el1/public/huks_service/attest_challenge"
#define HKS_CERT_MAX_PATH_LEN           512

/* ---- prefix conventions ---- */
#define HKS_PREFIX_CERTCHAIN   "CERTCHAIN_"
#define HKS_PREFIX_USRPKEY     "USRPKEY_"
#define HKS_PREFIX_USRPKEY_S   "USRPKEY_S_"
#define HKS_PREFIX_USRPKEY_EP  "USRPKEY_EP_"
#define HKS_PREFIX_USRCERT     "USRCERT_"
#define HKS_PREFIX_CACERT      "CACERT_"

static bool IsAliasSafe(const struct HksBlob *keyAlias)
{
    if (keyAlias == NULL || keyAlias->data == NULL || keyAlias->size == 0) {
        return false;
    }
    for (uint32_t i = 0; i < keyAlias->size; i++) {
        if (keyAlias->data[i] == '/') {
            return false;
        }
    }
    for (uint32_t i = 0; i + 1 < keyAlias->size; i++) {
        if (keyAlias->data[i] == '.' && keyAlias->data[i + 1] == '.') {
            return false;
        }
    }
    return true;
}

static bool BlobHasPrefix(const struct HksBlob *alias, const char *prefix)
{
    size_t plen = strlen(prefix);
    if (alias == NULL || alias->size < plen) {
        return false;
    }
    return memcmp(alias->data, prefix, plen) == 0;
}

static struct HksBlob BuildCertChainAlias(const struct HksBlob *keyAlias)
{
    struct HksBlob result = { 0, NULL };
    if (keyAlias == NULL || keyAlias->data == NULL || keyAlias->size == 0) {
        return result;
    }

    if (BlobHasPrefix(keyAlias, HKS_PREFIX_CERTCHAIN) ||
        BlobHasPrefix(keyAlias, HKS_PREFIX_USRCERT) ||
        BlobHasPrefix(keyAlias, HKS_PREFIX_CACERT)) {
        result.data = (uint8_t *)HksMalloc(keyAlias->size);
        HKS_IF_NULL_RETURN(result.data, result)
        if (memcpy_s(result.data, keyAlias->size, keyAlias->data, keyAlias->size) != EOK) {
            HKS_LOG_E("BuildCertChainAlias: copy cert alias failed");
            HKS_FREE_BLOB(result);
            return result;
        }
        result.size = keyAlias->size;
        return result;
    }

    const char *keyPrefixes[] = { HKS_PREFIX_USRPKEY_EP, HKS_PREFIX_USRPKEY_S, HKS_PREFIX_USRPKEY };
    const char *matched = NULL;
    for (size_t i = 0; i < sizeof(keyPrefixes) / sizeof(keyPrefixes[0]); i++) {
        if (BlobHasPrefix(keyAlias, keyPrefixes[i])) {
            matched = keyPrefixes[i];
            break;
        }
    }
    HKS_IF_TRUE_EXCU(matched == NULL, matched = "");

    size_t plen = strlen(matched);
    size_t certPrefixLen = strlen(HKS_PREFIX_CERTCHAIN);
    uint32_t bodyLen = keyAlias->size - plen;
    uint32_t totalLen = certPrefixLen + bodyLen;

    result.data = (uint8_t *)HksMalloc(totalLen);
    HKS_IF_NULL_RETURN(result.data, result)
    if (memcpy_s(result.data, totalLen, HKS_PREFIX_CERTCHAIN, certPrefixLen) != EOK) {
        HKS_LOG_E("BuildCertChainAlias: copy cert chain prefix failed");
        HKS_FREE_BLOB(result);
        return result;
    }
    if (memcpy_s(result.data + certPrefixLen, bodyLen, keyAlias->data + plen, bodyLen) != EOK) {
        HKS_LOG_E("BuildCertChainAlias: copy key alias body failed");
        HKS_FREE_BLOB(result);
        return result;
    }
    result.size = totalLen;
    return result;
}

static int32_t BuildUidDirPath(char *path, uint32_t pathLen, const char *root, uint32_t uid)
{
    int32_t ret = snprintf_s(path, pathLen, pathLen - 1, "%s/%u", root, uid);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret < 0, HKS_ERROR_INTERNAL_ERROR, "snprintf_s uid dir failed")
    return HKS_SUCCESS;
}

static int32_t EnsureUidDir(const char *root, uint32_t uid)
{
    (void)HksMakeDir(root);
    char dirPath[HKS_CERT_MAX_PATH_LEN] = {0};
    int32_t ret = BuildUidDirPath(dirPath, sizeof(dirPath), root, uid);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    (void)HksMakeDir(dirPath);
    return HKS_SUCCESS;
}

static int32_t BuildFileName(char *fileName, uint32_t bufLen, uint32_t uid, const struct HksBlob *keyAlias)
{
    int32_t ret = snprintf_s(fileName, bufLen, bufLen - 1, "%u/", uid);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret < 0, HKS_ERROR_INTERNAL_ERROR, "snprintf_s fileName uid failed")
    uint32_t usedLen = (uint32_t)ret;
    if (usedLen + keyAlias->size + 1 > bufLen) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(fileName + usedLen, bufLen - usedLen, keyAlias->data, keyAlias->size),
        HKS_ERROR_INTERNAL_ERROR, "copy keyAlias to fileName failed")
    fileName[usedLen + keyAlias->size] = '\0';
    return HKS_SUCCESS;
}

static int32_t StoreWriteFile(const char *root, uint32_t uid, const struct HksBlob *keyAlias,
    const uint8_t *data, uint32_t len)
{
    if (data == NULL || len == 0 || !IsAliasSafe(keyAlias)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    int32_t ret = EnsureUidDir(root, uid);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    char fileName[HKS_CERT_MAX_PATH_LEN] = {0};
    ret = BuildFileName(fileName, sizeof(fileName), uid, keyAlias);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    HKS_LOG_I("CertChainStore write: root=%" LOG_PUBLIC "s fileName=%" LOG_PUBLIC "s uid=%" LOG_PUBLIC "u",
        root, fileName, uid);
    ret = HksFileWrite(root, fileName, 0, data, len);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksFileWrite failed, ret = %" LOG_PUBLIC "d", ret)
    return HKS_SUCCESS;
}

static int32_t StoreReadFile(const char *root, uint32_t uid, const struct HksBlob *keyAlias,
    struct HksBlob *outData)
{
    if (outData == NULL || !IsAliasSafe(keyAlias)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    char fileName[HKS_CERT_MAX_PATH_LEN] = {0};
    int32_t ret = BuildFileName(fileName, sizeof(fileName), uid, keyAlias);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    HKS_LOG_I("CertChainStore read: root=%" LOG_PUBLIC "s fileName=%" LOG_PUBLIC "s uid=%" LOG_PUBLIC "u",
        root, fileName, uid);

    uint32_t fileLen = HksFileSize(root, fileName);
    if (fileLen == 0) {
        HKS_LOG_E("CertChainStore read: file not exist, root=%" LOG_PUBLIC "s fileName=%" LOG_PUBLIC "s",
            root, fileName);
        return HKS_ERROR_NOT_EXIST;
    }
    outData->data = (uint8_t *)HksMalloc(fileLen);
    HKS_IF_NULL_RETURN(outData->data, HKS_ERROR_MALLOC_FAIL)
    outData->size = fileLen;
    uint32_t readLen = 0;
    ret = HksFileRead(root, fileName, 0, outData, &readLen);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(outData->data);
        outData->size = 0;
        return ret;
    }
    outData->size = readLen;
    return HKS_SUCCESS;
}

static int32_t StoreRemoveFile(const char *root, uint32_t uid, const struct HksBlob *keyAlias)
{
    if (!IsAliasSafe(keyAlias)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    char fileName[HKS_CERT_MAX_PATH_LEN] = {0};
    int32_t ret = BuildFileName(fileName, sizeof(fileName), uid, keyAlias);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    (void)HksFileRemove(root, fileName);
    return HKS_SUCCESS;
}

static int32_t StoreFileExist(const char *root, uint32_t uid, const struct HksBlob *keyAlias)
{
    if (!IsAliasSafe(keyAlias)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    char fileName[HKS_CERT_MAX_PATH_LEN] = {0};
    int32_t ret = BuildFileName(fileName, sizeof(fileName), uid, keyAlias);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    return HksIsFileExist(root, fileName);
}

void HksCertChainStoreOnAttestSuccess(uint32_t uid, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *certChain)
{
    if (keyAlias == NULL || paramSet == NULL || certChain == NULL || certChain->data == NULL || certChain->size == 0) {
        HKS_LOG_I("CertChainStore OnAttestSuccess: invalid params, skip");
        return;
    }

    struct HksParam *attestModeParam = NULL;
    if (HksGetParam(paramSet, HKS_TAG_ATTESTATION_MODE, &attestModeParam) == HKS_SUCCESS) {
        if (attestModeParam->uint32Param == HKS_ATTESTATION_MODE_ANONYMOUS ||
            attestModeParam->uint32Param == HKS_ATTESTATION_MODE_ANONYMOUS_COMPAT) {
            HKS_LOG_I("CertChainStore OnAttestSuccess: anonymous mode, skip store");
            return;
        }
    }

    struct HksBlob certAlias = BuildCertChainAlias(keyAlias);
    if (certAlias.data == NULL) {
        HKS_LOG_E("CertChainStore OnAttestSuccess: BuildCertChainAlias failed");
        return;
    }

    int32_t ret = StoreWriteFile(HKS_CERT_CHAIN_STORE_ROOT, uid, &certAlias, certChain->data, certChain->size);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("CertChainStore save certChain failed, ret = %" LOG_PUBLIC "d", ret);
    } else {
        HKS_LOG_I("CertChainStore save certChain ok, uid=%" LOG_PUBLIC "u size=%" LOG_PUBLIC "u",
            uid, certChain->size);
    }

    struct HksParam *challengeParam = NULL;
    if (HksGetParam(paramSet, HKS_TAG_ATTESTATION_CHALLENGE, &challengeParam) != HKS_SUCCESS) {
        HKS_LOG_I("CertChainStore OnAttestSuccess: no challenge tag, skip challenge store");
        HKS_FREE_BLOB(certAlias);
        return;
    }
    if (challengeParam->blob.data == NULL || challengeParam->blob.size == 0) {
        HKS_LOG_I("CertChainStore OnAttestSuccess: empty challenge, skip challenge store");
        HKS_FREE_BLOB(certAlias);
        return;
    }
    ret = StoreWriteFile(HKS_ATTEST_CHALLENGE_STORE_ROOT, uid, &certAlias,
        challengeParam->blob.data, challengeParam->blob.size);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("CertChainStore save challenge failed, ret = %" LOG_PUBLIC "d", ret);
    } else {
        HKS_LOG_I("CertChainStore save challenge ok, uid=%" LOG_PUBLIC "u size=%" LOG_PUBLIC "u",
            uid, challengeParam->blob.size);
    }
    HKS_FREE_BLOB(certAlias);
}

int32_t HksCertChainStoreLoadChallenge(uint32_t uid, const struct HksBlob *keyAlias, struct HksBlob *challenge)
{
    if (keyAlias == NULL || challenge == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return StoreReadFile(HKS_ATTEST_CHALLENGE_STORE_ROOT, uid, keyAlias, challenge);
}

int32_t HksCertChainStoreLoadCertChain(uint32_t uid, const struct HksBlob *keyAlias, struct HksBlob *certChain)
{
    if (keyAlias == NULL || certChain == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return StoreReadFile(HKS_CERT_CHAIN_STORE_ROOT, uid, keyAlias, certChain);
}

void HksCertChainStoreRemove(uint32_t uid, const struct HksBlob *keyAlias)
{
    if (keyAlias == NULL) {
        return;
    }

    bool needsRewrite = BlobHasPrefix(keyAlias, HKS_PREFIX_USRPKEY) ||
                        BlobHasPrefix(keyAlias, HKS_PREFIX_USRPKEY_S) ||
                        BlobHasPrefix(keyAlias, HKS_PREFIX_USRPKEY_EP);
    if (!needsRewrite) {
        (void)StoreRemoveFile(HKS_CERT_CHAIN_STORE_ROOT, uid, keyAlias);
        (void)StoreRemoveFile(HKS_ATTEST_CHALLENGE_STORE_ROOT, uid, keyAlias);
        HKS_LOG_I("CertChainStore remove ok, uid=%" LOG_PUBLIC "u", uid);
        return;
    }

    struct HksBlob certAlias = BuildCertChainAlias(keyAlias);
    if (certAlias.data == NULL) {
        HKS_LOG_E("CertChainStore remove: BuildCertChainAlias failed");
        return;
    }
    (void)StoreRemoveFile(HKS_CERT_CHAIN_STORE_ROOT, uid, &certAlias);
    (void)StoreRemoveFile(HKS_ATTEST_CHALLENGE_STORE_ROOT, uid, &certAlias);
    HKS_LOG_I("CertChainStore remove ok (rewritten), uid=%" LOG_PUBLIC "u", uid);
    HKS_FREE_BLOB(certAlias);
}

bool HksCertChainStoreContains(uint32_t uid, const struct HksBlob *keyAlias)
{
    if (keyAlias == NULL) {
        return false;
    }
    int32_t ret = StoreFileExist(HKS_CERT_CHAIN_STORE_ROOT, uid, keyAlias);
    return ret == HKS_SUCCESS;
}

int32_t HksCertChainStoreSave(uint32_t uid, const struct HksBlob *keyAlias, const struct HksBlob *certChain)
{
    if (keyAlias == NULL || certChain == NULL || certChain->data == NULL || certChain->size == 0) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return StoreWriteFile(HKS_CERT_CHAIN_STORE_ROOT, uid, keyAlias, certChain->data, certChain->size);
}