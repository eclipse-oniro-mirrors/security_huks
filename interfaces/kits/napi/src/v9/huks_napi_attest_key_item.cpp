/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "huks_napi_attest_key_item.h"

#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_template.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_common_item.h"

namespace HuksNapiItem {
constexpr int HUKS_NAPI_ATTEST_KEY_MIN_ARGS = 2;
constexpr int HUKS_NAPI_ATTEST_KEY_MAX_ARGS = 3;

constexpr int INDEX_0 = 0;
constexpr int INDEX_1 = 1;
constexpr int INDEX_2 = 2;
constexpr int INDEX_3 = 3;

AttestKeyAsyncContext CreateAttestKeyAsyncContext(bool isAnon)
{
    AttestKeyAsyncContext context = static_cast<AttestKeyAsyncContext>(HksMalloc(sizeof(AttestKeyAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(AttestKeyAsyncContextT), 0, sizeof(AttestKeyAsyncContextT));
        context->isAnon = isAnon;
    }
    return context;
}

void DeleteAttestKeyAsyncContext(napi_env env, AttestKeyAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }
    DeleteCommonAsyncContext(env, context->asyncWork, context->callback, context->keyAlias, context->paramSet);
    FreeHksCertChain(context->certChain, context->certChainCapacity);
    HKS_FREE(context);
    context = nullptr;
}

static napi_value AttestKeyParseParams(napi_env env, napi_callback_info info, AttestKeyAsyncContext context)
{
    size_t argc = HUKS_NAPI_ATTEST_KEY_MAX_ARGS;
    napi_value argv[HUKS_NAPI_ATTEST_KEY_MAX_ARGS] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < HUKS_NAPI_ATTEST_KEY_MIN_ARGS) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseKeyAlias(env, argv[index], context->keyAlias);
    if (result == nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get key alias");
        HKS_LOG_E("could not get alias");
        return nullptr;
    }

    index++;
    napi_value property = GetPropertyFromOptions(env, argv[index], HKS_OPTIONS_PROPERTY_PROPERTIES);
    if (property == nullptr) {
        HKS_LOG_E("attestKey get property failed");
        return nullptr;
    }
    result = ParseHksParamSetAndAddParam(env, property, context->paramSet,
        {{ .tag = HKS_TAG_ATTESTATION_BASE64, .boolParam = true }});
    if (result == nullptr) {
        HKS_LOG_E("could not get paramset");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
    }

    return GetInt32(env, 0);
}

static int32_t InitCertChain(struct HksCertChain *certChain, uint32_t *certChainCapacity)
{
    certChain->certsCount = HKS_CERT_COUNT;
    certChain->certs = static_cast<struct HksBlob *>(HksMalloc(certChain->certsCount * sizeof(struct HksBlob)));
    HKS_IF_NULL_LOGE_RETURN(certChain->certs, HKS_ERROR_MALLOC_FAIL, "malloc certChain->certs error!");
    do {
        *certChainCapacity = certChain->certsCount;
        certChain->certs[INDEX_0].size = HKS_CERT_APP_SIZE;
        certChain->certs[INDEX_0].data = static_cast<uint8_t *>(HksMalloc(certChain->certs[INDEX_0].size));
        HKS_IF_NULL_LOGE_BREAK(certChain->certs[INDEX_0].data, "malloc certChain->certs[INDEX_0].data error!");
        
        certChain->certs[INDEX_1].size = HKS_CERT_DEVICE_SIZE;
        certChain->certs[INDEX_1].data = static_cast<uint8_t *>(HksMalloc(certChain->certs[INDEX_1].size));
        HKS_IF_NULL_LOGE_BREAK(certChain->certs[INDEX_1].data, "malloc certChain->certs[INDEX_1].data error!");

        certChain->certs[INDEX_2].size = HKS_CERT_CA_SIZE;
        certChain->certs[INDEX_2].data = static_cast<uint8_t *>(HksMalloc(certChain->certs[INDEX_2].size));
        HKS_IF_NULL_LOGE_BREAK(certChain->certs[INDEX_2].data, "malloc certChain->certs[INDEX_2].data error!");

        certChain->certs[INDEX_3].size = HKS_CERT_ROOT_SIZE;
        certChain->certs[INDEX_3].data = static_cast<uint8_t *>(HksMalloc(certChain->certs[INDEX_3].size));
        HKS_IF_NULL_LOGE_BREAK(certChain->certs[INDEX_3].data, "malloc certChain->certs[INDEX_3].data error!");
        
        return HKS_SUCCESS;
    } while (0);

    HKS_FREE(certChain->certs[INDEX_2].data);
    HKS_FREE(certChain->certs[INDEX_1].data);
    HKS_FREE(certChain->certs[INDEX_0].data);
    HKS_FREE(certChain->certs);

    return HKS_ERROR_MALLOC_FAIL;
}

napi_value AttestKeyAsyncWork(napi_env env, AttestKeyAsyncContext &context)
{
    napi_value promise = nullptr;
    if (context->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    }

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "attestKeyAsyncWork", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            AttestKeyAsyncContext napiContext = static_cast<AttestKeyAsyncContext>(data);

            napiContext->certChain = static_cast<struct HksCertChain *>(HksMalloc(sizeof(struct HksCertChain)));
            if (napiContext->certChain != nullptr) {
                napiContext->result = InitCertChain(napiContext->certChain, &napiContext->certChainCapacity);
                if (napiContext->result != HKS_SUCCESS) {
                    return;
                }
            }

            if (napiContext->isAnon) {
                napiContext->result = HksAnonAttestKey(
                    napiContext->keyAlias, napiContext->paramSet, napiContext->certChain);
            } else {
                napiContext->result = HksAttestKey(
                    napiContext->keyAlias, napiContext->paramSet, napiContext->certChain);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            AttestKeyAsyncContext napiContext = static_cast<AttestKeyAsyncContext>(data);
            HksSuccessReturnResult resultData;
            SuccessReturnResultInit(resultData);
            resultData.certChain = napiContext->certChain;
            HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result, resultData);
            DeleteAttestKeyAsyncContext(env, napiContext);
        },
        static_cast<void *>(context),
        &context->asyncWork);

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        DeleteAttestKeyAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }

    if (context->callback == nullptr) {
        return promise;
    } else {
        return GetNull(env);
    }
}

napi_value HuksNapiAttestKeyItem(napi_env env, napi_callback_info info, bool isAnon)
{
    AttestKeyAsyncContext context = CreateAttestKeyAsyncContext(isAnon);
    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = AttestKeyParseParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteAttestKeyAsyncContext(env, context);
        return nullptr;
    }
    result = AttestKeyAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteAttestKeyAsyncContext(env, context);
        return nullptr;
    }
    return result;
}

napi_value HuksNapiAttestKeyItem(napi_env env, napi_callback_info info)
{
    return HuksNapiAttestKeyItem(env, info, false);
}

napi_value HuksNapiAnonAttestKeyItem(napi_env env, napi_callback_info info)
{
    return HuksNapiAttestKeyItem(env, info, true);
}
}  // namespace HuksNapiItem