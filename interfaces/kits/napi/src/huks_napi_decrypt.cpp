/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "huks_napi_decrypt.h"

#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_common.h"

namespace HuksNapi {
namespace {
constexpr int HUKS_NAPI_DECRYPT_MIN_ARGS = 2;
constexpr int HUKS_NAPI_DECRYPT_MAX_ARGS = 3;
}  // namespace

struct DecryptAsyncContext_t {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct HksBlob *keyAlias = nullptr;
    struct HksParamSet *paramSet = nullptr;
    struct HksBlob *cipherText = nullptr;
    struct HksBlob *plainText = nullptr;
};
using DecryptAsyncContext = DecryptAsyncContext_t *;

static DecryptAsyncContext CreateDecryptAsyncContext()
{
    DecryptAsyncContext context = (DecryptAsyncContext)HksMalloc(sizeof(DecryptAsyncContext_t));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(DecryptAsyncContext_t), 0, sizeof(DecryptAsyncContext_t));
    }
    return context;
}

static void DeleteDecryptAsyncContext(napi_env env, DecryptAsyncContext context)
{
    if (context == nullptr) {
        return;
    }

    if (context->asyncWork != nullptr) {
        napi_delete_async_work(env, context->asyncWork);
        context->asyncWork = nullptr;
    }

    if (context->callback != nullptr) {
        napi_delete_reference(env, context->callback);
        context->callback = nullptr;
    }

    if (context->keyAlias != nullptr) {
        FreeHksBlob(context->keyAlias);
    }

    if (context->paramSet != nullptr) {
        HksFreeParamSet(&context->paramSet);
    }

    if (context->cipherText != nullptr) {
        if (context->cipherText->data != nullptr && context->cipherText->size != 0) {
            (void)memset_s(context->cipherText->data, context->cipherText->size, 0, context->cipherText->size);
        }
        FreeHksBlob(context->cipherText);
    }

    if (context->plainText != nullptr) {
        if (context->plainText->data != nullptr && context->plainText->size != 0) {
            (void)memset_s(context->plainText->data, context->plainText->size, 0, context->plainText->size);
        }
        FreeHksBlob(context->plainText);
    }

    HksFree(context);
}

static napi_value DecryptParseParams(napi_env env, napi_callback_info info, DecryptAsyncContext context)
{
    size_t argc = HUKS_NAPI_DECRYPT_MAX_ARGS;
    napi_value argv[HUKS_NAPI_DECRYPT_MAX_ARGS] = {0};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < HUKS_NAPI_DECRYPT_MIN_ARGS) {
        napi_throw_error(env, NULL, "invalid arguments");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseKeyAlias(env, argv[index], context->keyAlias);
    if (result == nullptr) {
        HKS_LOG_E("could not get alias");
        return nullptr;
    }

    index++;
    napi_value properties = nullptr;
    napi_status status =
        napi_get_named_property(env, argv[index], HKS_OPTIONS_PROPERTY_PROPERTIES.c_str(), &properties);
    if (status != napi_ok || properties == nullptr) {
        GET_AND_THROW_LAST_ERROR((env));
        HKS_LOG_E("could not get property %s", HKS_OPTIONS_PROPERTY_PROPERTIES.c_str());
        return nullptr;
    }
    result = ParseHksParamSet(env, properties, context->paramSet);
    if (result == nullptr) {
        HKS_LOG_E("could not get paramset");
        return nullptr;
    }
    napi_value inData = nullptr;
    status = napi_get_named_property(env, argv[index], HKS_OPTIONS_PROPERTY_INDATA.c_str(), &inData);
    if (status != napi_ok || inData == nullptr) {
        GET_AND_THROW_LAST_ERROR((env));
        HKS_LOG_E("could not get property %s", HKS_OPTIONS_PROPERTY_INDATA.c_str());
        return nullptr;
    }
    context->cipherText = (HksBlob *)HksMalloc(sizeof(HksBlob));
    if (context->cipherText == nullptr) {
        HKS_LOG_E("could not alloc memory");
        return nullptr;
    }
    result = GetUint8Array(env, inData, *context->cipherText);
    if (result == nullptr) {
        HKS_LOG_E("could not get indata");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
    }

    return GetInt32(env, 0);
}

static napi_value DecryptKeyWriteResult(napi_env env, DecryptAsyncContext context)
{
    return GenerateHksResult(env,
        context->result,
        ((context->result == HKS_SUCCESS && context->plainText != nullptr) ? context->plainText->data : nullptr),
        (context->result == HKS_SUCCESS && context->plainText != nullptr) ? context->plainText->size : 0);
}

static napi_value DecryptAsyncWork(napi_env env, DecryptAsyncContext context)
{
    napi_value promise = nullptr;
    if (context->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    }

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "decryptAsyncWork", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            DecryptAsyncContext context = static_cast<DecryptAsyncContext>(data);

            context->plainText = (HksBlob *)HksMalloc(sizeof(HksBlob));
            if (context->plainText != NULL) {
                context->plainText->data = (uint8_t *)HksMalloc(context->cipherText->size);
                context->plainText->size = context->cipherText->size;
            }

            context->result = HksDecrypt(context->keyAlias, context->paramSet, context->cipherText, context->plainText);
        },
        [](napi_env env, napi_status status, void *data) {
            DecryptAsyncContext context = static_cast<DecryptAsyncContext>(data);
            napi_value result = DecryptKeyWriteResult(env, context);
            if (result == nullptr) {
                return;
            }
            if (context->callback != nullptr) {
                CallAsyncCallback(env, context->callback, context->result, result);
            } else {
                napi_resolve_deferred(env, context->deferred, result);
            }
            DeleteDecryptAsyncContext(env, context);
        },
        (void *)context,
        &context->asyncWork);

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteDecryptAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }

    if (context->callback == nullptr) {
        return promise;
    } else {
        return GetNull(env);
    }
    return nullptr;
}

napi_value HuksNapiDecrypt(napi_env env, napi_callback_info info)
{
    DecryptAsyncContext context = CreateDecryptAsyncContext();
    if (context == nullptr) {
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = DecryptParseParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteDecryptAsyncContext(env, context);
        return nullptr;
    }

    result = DecryptAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteDecryptAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace HuksNapi