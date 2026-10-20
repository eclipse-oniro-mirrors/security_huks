/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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


#include "hks_anon_attest_stub.h"
#include "hks_ipc_service.h"
#include "hks_cert_chain_store.h"
#include "hks_client_service.h"
#include "hks_cmd_id.h"
#include "hks_ipc_serialization.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_response.h"
#include "hks_service_ipc_serialization.h"
#include "hks_template.h"
#include <securec.h>
#include <stdint.h>

#define HKS_ANON_CERT_CHAIN_BUF_SIZE 8192
#define HKS_ANON_ATTEST_TIMEOUT_SEC 30
#define HKS_PREFIX_CERTCHAIN "CERTCHAIN_"
#define HKS_PREFIX_USRPKEY   "USRPKEY_"

#ifdef L2_STANDARD
static struct HksBlob BuildKeyAliasFromCertChain(const struct HksBlob *certAlias)
{
    struct HksBlob result = { 0, NULL };
    if (certAlias == NULL || certAlias->data == NULL || certAlias->size == 0) {
        return result;
    }
    size_t certPrefixLen = strlen(HKS_PREFIX_CERTCHAIN);
    size_t keyPrefixLen = strlen(HKS_PREFIX_USRPKEY);
    if (certAlias->size < certPrefixLen ||
        memcmp(certAlias->data, HKS_PREFIX_CERTCHAIN, certPrefixLen) != 0) {
        return result; /* not a CERTCHAIN_ alias */
    }
    uint32_t bodyLen = certAlias->size - certPrefixLen;
    uint32_t totalLen = keyPrefixLen + bodyLen;
    result.data = (uint8_t *)HksMalloc(totalLen);
    if (result.data == NULL) {
        return result;
    }
    if (memcpy_s(result.data, totalLen, HKS_PREFIX_USRPKEY, keyPrefixLen) != EOK) {
        HKS_LOG_E("BuildKeyAliasFromCertChain: copy key prefix failed");
        HKS_FREE_BLOB(result);
        return result;
    }
    if (memcpy_s(result.data + keyPrefixLen, bodyLen, certAlias->data + certPrefixLen, bodyLen) != EOK) {
        HKS_LOG_E("BuildKeyAliasFromCertChain: copy alias body failed");
        HKS_FREE_BLOB(result);
        return result;
    }
    result.size = totalLen;
    return result;
}

// build anonymous attest paramSet
static int32_t BuildAnonAttestParamSet(const struct HksBlob *challenge,
    const struct HksParamSet *origParamSet, struct HksParamSet **outAnonParamSet)
{
    struct HksParam anonParams[4];
    (void)memset_s(anonParams, sizeof(anonParams), 0, sizeof(anonParams));
    anonParams[0].tag = HKS_TAG_ATTESTATION_CHALLENGE;
    anonParams[0].blob = *challenge;
    anonParams[1].tag = HKS_TAG_ATTESTATION_MODE;
    anonParams[1].uint32Param = HKS_ATTESTATION_MODE_ANONYMOUS_COMPAT;
    uint32_t paramCnt = 2;

    struct HksParam *ancoUidParam = NULL;
    struct HksParam *ancoUserParam = NULL;
    bool hasAncoUid = (HksGetParam(origParamSet, HKS_TAG_ANCO_APP_UID, &ancoUidParam) == HKS_SUCCESS);
    bool hasAncoUser = (HksGetParam(origParamSet, HKS_TAG_ANCO_USER_ID, &ancoUserParam) == HKS_SUCCESS);
    if (hasAncoUid) {
        anonParams[paramCnt].tag = HKS_TAG_ANCO_APP_UID;
        anonParams[paramCnt].blob = ancoUidParam->blob;
        paramCnt++;
    }
    if (hasAncoUser) {
        anonParams[paramCnt].tag = HKS_TAG_ANCO_USER_ID;
        anonParams[paramCnt].uint32Param = ancoUserParam->uint32Param;
        paramCnt++;
    }

    struct HksParamSet *anonParamSet = NULL;
    int32_t ret = HksInitParamSet(&anonParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksInitParamSet fail, ret = %" LOG_PUBLIC "d", ret)

    do {
        ret = HksAddParams(anonParamSet, anonParams, paramCnt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAddParams fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksBuildParamSet(&anonParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksBuildParamSet fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&anonParamSet);
        return ret;
    }
    *outAnonParamSet = anonParamSet;
    return HKS_SUCCESS;
}

static int32_t DoAnonAttestAndGetCert(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *anonParamSet, struct HksBlob *outCert)
{
    const uint8_t *stubObj = HksCreateAnonAttestStub();
    HKS_IF_NULL_LOGE_RETURN(stubObj, HKS_ERROR_NULL_POINTER, "HksCreateAnonAttestStub fail")

    struct HksBlob tmpCert = { 0, NULL };
    tmpCert.data = (uint8_t *)HksMalloc(HKS_ANON_CERT_CHAIN_BUF_SIZE);
    if (tmpCert.data == NULL) {
        HksDestroyAnonAttestStub(stubObj);
        return HKS_ERROR_MALLOC_FAIL;
    }
    tmpCert.size = HKS_ANON_CERT_CHAIN_BUF_SIZE;

    int32_t ret = HksServiceAttestKey(processInfo, keyAlias, anonParamSet, &tmpCert, stubObj);
    HKS_FREE_BLOB(tmpCert);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("anon HksServiceAttestKey fail, ret = %" LOG_PUBLIC "d", ret);
        HksDestroyAnonAttestStub(stubObj);
        return ret;
    }

    ret = HksWaitAnonAttestReply(stubObj, HKS_ANON_ATTEST_TIMEOUT_SEC, outCert);
    HksDestroyAnonAttestStub(stubObj);
    return ret;
}

// get cert chain (anonymous)
void HksIpcServiceGetAnonCertChain(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksParamSet *anonParamSet = NULL;
    struct HksBlob challenge = { 0, NULL };
    struct HksBlob certChain = { 0, NULL };
    struct HksBlob attestKeyAlias = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;
    do {
        ret = HksKeyExistUnpack(srcData, &keyAlias, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksKeyExistUnpack fail, ret = %" LOG_PUBLIC "d", ret)
        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)
 
        ret = HksCertChainStoreLoadChallenge(processInfo.uidInt, &keyAlias, &challenge);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "load challenge fail, ret = %" LOG_PUBLIC "d", ret)

        ret = BuildAnonAttestParamSet(&challenge, paramSet, &anonParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build anon paramSet fail, ret = %" LOG_PUBLIC "d", ret)

        /* keyAlias from broker is CERTCHAIN_ prefixed (cert-chain alias); attest needs the
         * key alias (USRPKEY_ prefixed). Rewrite before calling HksServiceAttestKey. */
        attestKeyAlias = BuildKeyAliasFromCertChain(&keyAlias);
        if (attestKeyAlias.data == NULL) {
            HKS_LOG_E("BuildKeyAliasFromCertChain fail, alias is not CERTCHAIN_ prefixed");
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }
        ret = DoAnonAttestAndGetCert(&processInfo, &attestKeyAlias, anonParamSet, &certChain);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "anon attest fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);
    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &certChain : NULL);
    HksFreeParamSet(&anonParamSet);
    HKS_FREE_BLOB(challenge);
    HKS_FREE_BLOB(certChain);
    HKS_FREE_BLOB(attestKeyAlias);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

#else
void HksIpcServiceGetAnonCertChain(const struct HksBlob *srcData, const uint8_t *context)
{
    /* the anonymous attest broker stub only exists on the standard system */
    (void)srcData;
    HksSendResponse(context, HKS_ERROR_NOT_SUPPORTED, NULL);
}
#endif

// get cert chain (non-anonymous, read from persisted storage)
void HksIpcServiceGetCertChain(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksBlob certChain = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;
    do {
        ret = HksKeyExistUnpack(srcData, &keyAlias, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksKeyExistUnpack fail, ret = %" LOG_PUBLIC "d", ret)
        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)
        ret = HksCertChainStoreLoadCertChain(processInfo.uidInt, &keyAlias, &certChain);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "load persisted cert chain fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);
    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &certChain : NULL);
    HKS_FREE_BLOB(certChain);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

// set storage: persist certificate data (CERTCHAIN_ / USRCERT_ / CACERT_ prefixed)
void HksIpcServiceSetStorage(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksBlob data = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;
    do {
        ret = HksSetStorageUnpack(srcData, &keyAlias, &paramSet, &data);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSetStorageUnpack fail, ret = %" LOG_PUBLIC "d", ret)
        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)
        ret = HksCertChainStoreSave(processInfo.uidInt, &keyAlias, &data);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCertChainStoreSave fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);
    HksSendResponse(context, ret, NULL);
    /* keyAlias, paramSet and data point into srcData buffer (no independent malloc);
     * they are released by the IPC framework, so we must NOT free them here. */
    (void)keyAlias;
    (void)paramSet;
    (void)data;
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

// get storage: read certificate data (CERTCHAIN_ / USRCERT_ / CACERT_ prefixed)
void HksIpcServiceGetStorage(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksBlob data = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;
    do {
        ret = HksKeyExistUnpack(srcData, &keyAlias, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksKeyExistUnpack fail, ret = %" LOG_PUBLIC "d", ret)
        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)
        ret = HksCertChainStoreLoadCertChain(processInfo.uidInt, &keyAlias, &data);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCertChainStoreLoadCertChain fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);
    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &data : NULL);
    /* keyAlias and paramSet point into srcData buffer (no independent malloc);
     * they are released by the IPC framework, so we must NOT free them here.
     * data is allocated by HksCertChainStoreLoadCertChain and must be freed. */
    (void)keyAlias;
    (void)paramSet;
    HKS_FREE_BLOB(data);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

// storage exist: check existence of certificate data (CERTCHAIN_ / USRCERT_ / CACERT_ prefixed)
void HksIpcServiceStorageExist(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;
    do {
        ret = HksKeyExistUnpack(srcData, &keyAlias, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksKeyExistUnpack fail, ret = %" LOG_PUBLIC "d", ret)
        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)
        bool exist = HksCertChainStoreContains(processInfo.uidInt, &keyAlias);
        ret = exist ? HKS_SUCCESS : HKS_ERROR_NOT_EXIST;
    } while (0);
    HksSendResponse(context, ret, NULL);
    /* keyAlias and paramSet point into srcData buffer (no independent malloc);
     * they are released by the IPC framework, so we must NOT free them here. */
    (void)keyAlias;
    (void)paramSet;
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}