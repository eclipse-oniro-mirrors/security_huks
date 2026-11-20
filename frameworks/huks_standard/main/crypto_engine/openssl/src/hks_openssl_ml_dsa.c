/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#ifdef HKS_SUPPORT_ML_DSA_C
#include "securec.h"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include "hks_error_code.h"
#include "hks_common_check.h"
#include "hks_openssl_engine.h"
#include "hks_openssl_ml_dsa.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"

#define ML_DSA_KEY_NUM 3

typedef struct MlDsaParam {
    uint32_t paramSetId;
    uint32_t alg;
    uint32_t pubKeySize;
    uint32_t priKeySize;
} MlDsaParam;

static MlDsaParam g_validMlDsaParam[] = {
    {
        HKS_ML_DSA_KEY_PARAM_SET_44, EVP_PKEY_ML_DSA_44, HKS_ML_DSA_PUB_KEY_SIZE_1312,
        HKS_ML_DSA_PRI_KEY_SIZE_2560
    }, {
        HKS_ML_DSA_KEY_PARAM_SET_65, EVP_PKEY_ML_DSA_65, HKS_ML_DSA_PUB_KEY_SIZE_1952,
        HKS_ML_DSA_PRI_KEY_SIZE_4032
    }, {
        HKS_ML_DSA_KEY_PARAM_SET_87, EVP_PKEY_ML_DSA_87, HKS_ML_DSA_PUB_KEY_SIZE_2592,
        HKS_ML_DSA_PRI_KEY_SIZE_4896
    }
};

#ifdef HKS_SUPPORT_ML_DSA_GENERATE_KEY
static int32_t MlDsaGetKeyMaterial(EVP_PKEY *pkey, uint32_t paramSetId, struct HksBlob *key)
{
    uint32_t pubKeySize = 0;
    uint32_t priKeySize = 0;
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_validMlDsaParam); i++) {
        if (g_validMlDsaParam[i].paramSetId == paramSetId) {
            pubKeySize = g_validMlDsaParam[i].pubKeySize;
            priKeySize = g_validMlDsaParam[i].priKeySize;
        }
    }
    HKS_IF_TRUE_LOGE_RETURN(pubKeySize == 0, HKS_ERROR_INVALID_KEY_SIZE, "get ml-dsa key len failed");

    const uint32_t rawMaterialLen = sizeof(struct HksKeyMaterialMlDsa) + pubKeySize + priKeySize;
    uint8_t *rawMaterial = (uint8_t *)HksMalloc(rawMaterialLen);
    HKS_IF_NULL_LOGE_RETURN(rawMaterial, HKS_ERROR_MALLOC_FAIL, "ml-dsa key malloc failed")

    struct HksKeyMaterialMlDsa *keyMaterial = (struct HksKeyMaterialMlDsa *)rawMaterial;
    keyMaterial->keyAlg = HKS_ALG_ML_DSA;
    keyMaterial->keyParamSet = paramSetId;
    keyMaterial->pubKeySize = pubKeySize;
    keyMaterial->priKeySize = priKeySize;

    uint32_t offset = sizeof(*keyMaterial);
    int32_t ret = HKS_OPENSSL_SUCCESS;
    do {
        size_t pubSize = pubKeySize;
        ret = EVP_PKEY_get_raw_public_key(pkey, rawMaterial + offset, &pubSize);
        if (ret != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("get ml-dsa pub key failed, ret = 0x%x", ret);
            HksLogOpensslError();
            break;
        }

        size_t priSize = priKeySize;
        offset += keyMaterial->pubKeySize;
        ret = EVP_PKEY_get_raw_private_key(pkey, rawMaterial + offset, &priSize);
        if (ret != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("get ml-dsa pri key failed, ret = 0x%x", ret);
            HksLogOpensslError();
            break;
        }
    } while (0);

    if (ret != HKS_OPENSSL_SUCCESS) {
        (void)memset_s(rawMaterial, rawMaterialLen, 0, rawMaterialLen);
        HKS_FREE(rawMaterial);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    key->data = rawMaterial;
    key->size = sizeof(struct HksKeyMaterialMlDsa) + keyMaterial->pubKeySize + keyMaterial->priKeySize;

    return HKS_SUCCESS;
}

int32_t HksOpensslMlDsaGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    uint32_t alg = 0;
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_validMlDsaParam); i++) {
        if (g_validMlDsaParam[i].paramSetId == spec->keyLen) {
            alg = g_validMlDsaParam[i].alg;
        }
    }
    HKS_IF_TRUE_LOGE_RETURN(alg == 0, HKS_ERROR_INVALID_KEY_SIZE, "get ml-dsa alg failed");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(alg, NULL);
    if (ctx == NULL) {
        HKS_LOG_E("failed to create context");
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    int32_t ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    EVP_PKEY *pkey = NULL;
    do {
        if (EVP_PKEY_keygen_init(ctx) != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("failed to initialize context");
            HksLogOpensslError();
            break;
        }

        if (EVP_PKEY_keygen(ctx, &pkey) != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("failed to generate evp key");
            HksLogOpensslError();
            break;
        }

        ret = MlDsaGetKeyMaterial(pkey, spec->keyLen, key);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("ml-dsa generate key: MlDsaGetKeyMaterial failed ret = %d", ret);
        }
    } while (0);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return ret;
}
#endif

#ifdef HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY
int32_t HksOpensslMlDsaGetPubKey(const struct HksBlob *keyIn, struct HksBlob *keyOut)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckAsyKeyMaterialSize(HKS_ALG_ML_DSA, keyIn, keyOut),
        HKS_ERROR_INVALID_ARGUMENT, "invalid ml-dsa key material!")

    struct HksKeyMaterialMlDsa *keyMaterial = (struct HksKeyMaterialMlDsa *)keyIn->data;
    HKS_IF_TRUE_LOGE_RETURN(keyMaterial->pubKeySize == 0, HKS_ERROR_INVALID_ALGORITHM,
        "get ml-dsa public key size invalid")

    uint32_t pubKeySize = sizeof(struct HksKeyMaterialMlDsa) + keyMaterial->pubKeySize;

    struct HksKeyMaterialMlDsa *publickeyMaterial = (struct HksKeyMaterialMlDsa *)keyOut->data;
    publickeyMaterial->keyAlg = keyMaterial->keyAlg;
    publickeyMaterial->keyParamSet = keyMaterial->keyParamSet;
    publickeyMaterial->pubKeySize = keyMaterial->pubKeySize;
    publickeyMaterial->priKeySize = 0;
    publickeyMaterial->reserved = 0;

    if (memcpy_s(keyOut->data + sizeof(struct HksKeyMaterialMlDsa), keyOut->size - sizeof(struct HksKeyMaterialMlDsa),
        keyIn->data + sizeof(struct HksKeyMaterialMlDsa), keyMaterial->pubKeySize) != EOK) {
        HKS_LOG_E("copy ml-dsa public key fail");
        return HKS_ERROR_INVALID_OPERATION;
    }

    keyOut->size = pubKeySize;
    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_ML_DSA_SIGN_VERIFY
#define ML_DSA_CONTEXT_STRING       "context-string"
#define ML_DSA_MESSAGE_ENCODING     "message-encoding"
#define ML_DSA_MU                   "mu"
#define ML_DSA_MSG_ENCODE_RAW       0
#define ML_DSA_PREHASH_DOMAIN_SEP   1

typedef struct MlDsaPreHashParam {
    uint32_t digest;
    uint32_t digestLen;
    const uint8_t *oid;
    uint32_t oidLen;
} MlDsaPreHashParam;

/*
 * The DER encoding of the object identifier of the pre-hash function, see FIPS 204 section 5.4.
 * HashML-DSA signs 0x01 || len(ctx) || ctx || OID(PH) || PH(M).
 */
static const uint8_t g_mlDsaSha256Oid[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
static const uint8_t g_mlDsaSha384Oid[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
static const uint8_t g_mlDsaSha512Oid[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
static const uint8_t g_mlDsaShake128Oid[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B };
static const uint8_t g_mlDsaShake256Oid[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C };

static const MlDsaPreHashParam g_mlDsaPreHashParam[] = {
    { HKS_DIGEST_SHA256, HKS_DIGEST_SHA256_LEN, g_mlDsaSha256Oid, sizeof(g_mlDsaSha256Oid) },
    { HKS_DIGEST_SHA384, HKS_DIGEST_SHA384_LEN, g_mlDsaSha384Oid, sizeof(g_mlDsaSha384Oid) },
    { HKS_DIGEST_SHA512, HKS_DIGEST_SHA512_LEN, g_mlDsaSha512Oid, sizeof(g_mlDsaSha512Oid) },
#ifndef HKS_CHIPSET_API
    { HKS_DIGEST_SHAKE128, HKS_DIGEST_SHAKE128_LEN, g_mlDsaShake128Oid, sizeof(g_mlDsaShake128Oid) },
    { HKS_DIGEST_SHAKE256, HKS_DIGEST_SHAKE256_LEN, g_mlDsaShake256Oid, sizeof(g_mlDsaShake256Oid) },
#endif
};

static const MlDsaPreHashParam *MlDsaGetPreHashParam(uint32_t digest)
{
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_mlDsaPreHashParam); i++) {
        if (g_mlDsaPreHashParam[i].digest == digest) {
            return &g_mlDsaPreHashParam[i];
        }
    }
    return NULL;
}

/*
 * Builds the HashML-DSA formatted message M' = 0x01 || len(ctx) || ctx || OID(PH) || PH(M).
 * message is the digest PH(M) computed by the caller, its length must match the selected hash.
 * The resulting buffer is owned by the caller and must be freed with HKS_FREE_BLOB.
 */
static int32_t MlDsaBuildPreHashMessage(const struct HksBlob *message, const struct HksBlob *context,
    const MlDsaPreHashParam *preHashParam, struct HksBlob *encodedMessage)
{
    HKS_IF_TRUE_LOGE_RETURN(message->size != preHashParam->digestLen, HKS_ERROR_INVALID_ARGUMENT,
        "invalid ml-dsa prehash size %" LOG_PUBLIC "u, expect %" LOG_PUBLIC "u",
        message->size, preHashParam->digestLen)

    uint32_t ctxLen = (context == NULL) ? 0 : context->size;
    uint32_t totalLen = 2 + ctxLen + preHashParam->oidLen + preHashParam->digestLen;
    uint8_t *buffer = (uint8_t *)HksMalloc(totalLen);
    HKS_IF_NULL_LOGE_RETURN(buffer, HKS_ERROR_MALLOC_FAIL, "ml-dsa prehash message malloc failed")

    uint32_t offset = 0;
    buffer[offset++] = ML_DSA_PREHASH_DOMAIN_SEP;
    buffer[offset++] = (uint8_t)ctxLen;
    if ((ctxLen != 0) && (context->data != NULL)) {
        if (memcpy_s(buffer + offset, totalLen - offset, context->data, ctxLen) != EOK) {
            HKS_LOG_E("copy ml-dsa context failed");
            (void)memset_s(buffer, totalLen, 0, totalLen);
            HKS_FREE(buffer);
            return HKS_ERROR_INVALID_OPERATION;
        }
        offset += ctxLen;
    }
    if (memcpy_s(buffer + offset, totalLen - offset, preHashParam->oid, preHashParam->oidLen) != EOK) {
        HKS_LOG_E("copy ml-dsa prehash oid failed");
        (void)memset_s(buffer, totalLen, 0, totalLen);
        HKS_FREE(buffer);
        return HKS_ERROR_INVALID_OPERATION;
    }
    offset += preHashParam->oidLen;
    if (memcpy_s(buffer + offset, totalLen - offset, message->data, message->size) != EOK) {
        HKS_LOG_E("copy ml-dsa prehash digest failed");
        (void)memset_s(buffer, totalLen, 0, totalLen);
        HKS_FREE(buffer);
        return HKS_ERROR_INVALID_OPERATION;
    }

    encodedMessage->data = buffer;
    encodedMessage->size = totalLen;
    return HKS_SUCCESS;
}

/*
 * For pre-hash mode the caller supplied digest is formatted into M', which OpenSSL must sign as a
 * raw message (message-encoding = 0). Pure mode and external mu mode use the message as is,
 * OpenSSL applies the pure encoding or starts from mu according to the parameters.
 */
static int32_t MlDsaPrepareMessage(const struct HksUsageSpec *usageSpec, const struct HksBlob *message,
    struct HksBlob *encodedMessage)
{
    encodedMessage->data = NULL;
    encodedMessage->size = 0;

    switch (usageSpec->pqcSigMode) {
        case HKS_PQC_SIG_MODE_PURE:
            return HKS_SUCCESS;
        case HKS_PQC_SIG_MODE_EXTERNAL_MU:
            HKS_IF_TRUE_LOGE_RETURN((message->data == NULL) || (message->size != ML_DSA_MU_SIZE),
                HKS_ERROR_INVALID_ARGUMENT, "invalid ml-dsa external mu size %" LOG_PUBLIC "u", message->size)
            return HKS_SUCCESS;
        case HKS_PQC_SIG_MODE_PREHASH: {
            struct HksBlob *context = (struct HksBlob *)usageSpec->algParam;
            HKS_IF_TRUE_LOGE_RETURN((context != NULL) && (context->size > HKS_ML_DSA_MAX_CONTEXT_SIZE),
                HKS_ERROR_INVALID_ARGUMENT, "invalid ml-dsa context size %" LOG_PUBLIC "u", context->size)
            const MlDsaPreHashParam *preHashParam = MlDsaGetPreHashParam(usageSpec->digest);
            HKS_IF_NULL_LOGE_RETURN(preHashParam, HKS_ERROR_INVALID_DIGEST,
                "unsupported ml-dsa prehash digest %" LOG_PUBLIC "u", usageSpec->digest)
            return MlDsaBuildPreHashMessage(message, context, preHashParam, encodedMessage);
        }
        default:
            HKS_LOG_E("invalid pqc sig mode %" LOG_PUBLIC "u", usageSpec->pqcSigMode);
            return HKS_ERROR_INVALID_MODE;
    }
}

static int32_t MlDsaSetSignVerifyParam(EVP_PKEY_CTX *ctx, const struct HksUsageSpec *usageSpec)
{
    struct HksBlob *context = (struct HksBlob *)usageSpec->algParam;
    int32_t muFlag = 0;
    int32_t msgEncoding = ML_DSA_MSG_ENCODE_RAW;
    OSSL_PARAM params[ML_DSA_KEY_NUM];
    uint32_t index = 0;

    if (usageSpec->pqcSigMode == HKS_PQC_SIG_MODE_EXTERNAL_MU) {
        /* mu already contains the context and the message, the context string must not be applied again */
        muFlag = 1;
        params[index++] = OSSL_PARAM_construct_int(ML_DSA_MU, &muFlag);
    } else {
        if (usageSpec->pqcSigMode == HKS_PQC_SIG_MODE_PREHASH) {
            params[index++] = OSSL_PARAM_construct_int(ML_DSA_MESSAGE_ENCODING, &msgEncoding);
        }
        if ((context != NULL) && (context->data != NULL) && (context->size != 0)) {
            params[index++] = OSSL_PARAM_construct_octet_string(ML_DSA_CONTEXT_STRING, context->data, context->size);
        }
    }

    if (index == 0) {
        return HKS_SUCCESS;
    }
    params[index] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(ctx, params) != HKS_OPENSSL_SUCCESS) {
        HKS_LOG_E("evp ml-dsa set params failed");
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return HKS_SUCCESS;
}

static int32_t MlDsaSignVerifyInitCtx(const struct HksBlob *key, EVP_PKEY **pkey)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckAsyKeyMaterialSize(HKS_ALG_ML_DSA, key, NULL),
        HKS_ERROR_INVALID_ARGUMENT, "invalid ml-dsa key material!")

    struct HksKeyMaterialMlDsa *keyMaterial = (struct HksKeyMaterialMlDsa *)key->data;
    int32_t ret;
    uint32_t alg = 0;
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_validMlDsaParam); i++) {
        if (g_validMlDsaParam[i].paramSetId == keyMaterial->keyParamSet) {
            alg = g_validMlDsaParam[i].alg;
        }
    }
    HKS_IF_TRUE_LOGE_RETURN(alg == 0, HKS_ERROR_INVALID_KEY_SIZE, "get ml-dsa alg failed");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(alg, NULL);
    if (ctx == NULL) {
        HKS_LOG_E("failed to create ml-dsa ctx");
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = EVP_PKEY_fromdata_init(ctx);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HKS_LOG_E("failed to initialize ml-dsa ctx");
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    uint32_t offset = sizeof(struct HksKeyMaterialMlDsa);
    OSSL_PARAM params[ML_DSA_KEY_NUM];
    uint32_t index = 0;
    params[index++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
        key->data + offset, keyMaterial->pubKeySize);
    offset += keyMaterial->pubKeySize;
    if (keyMaterial->priKeySize != 0) {
        params[index++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
            key->data + offset, keyMaterial->priKeySize);
    }
    params[index++] = OSSL_PARAM_construct_end();

    ret = EVP_PKEY_fromdata(ctx, pkey, (keyMaterial->priKeySize == 0) ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR, params);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HKS_LOG_E("failed to create key from data");
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    EVP_PKEY_CTX_free(ctx);
    return HKS_SUCCESS;
}

static int32_t MlDsaPrepareMessageToUse(const struct HksUsageSpec *usageSpec, const struct HksBlob *message,
    struct HksBlob *encodedMessage, const struct HksBlob **messageToUse)
{
    *messageToUse = message;
    int32_t ret = MlDsaPrepareMessage(usageSpec, message, encodedMessage);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "prepare ml-dsa message failed, ret = %" LOG_PUBLIC "d", ret)
    if (encodedMessage->data != NULL) {
        *messageToUse = encodedMessage;
    }
    return HKS_SUCCESS;
}

static int32_t MlDsaInitSignVerifyOpCtx(const struct HksBlob *key, bool isSign,
    EVP_PKEY **pkey, EVP_MD_CTX **mdCtx, EVP_PKEY_CTX **opCtx)
{
    int32_t ret = MlDsaSignVerifyInitCtx(key, pkey);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "failed to init ml-dsa key ctx");

    *mdCtx = EVP_MD_CTX_new();
    HKS_IF_NULL_LOGE_RETURN(*mdCtx, HKS_ERROR_CRYPTO_ENGINE_ERROR, "failed to create ml-dsa md ctx");

    int32_t initRet = isSign ? EVP_DigestSignInit(*mdCtx, opCtx, NULL, NULL, *pkey) :
        EVP_DigestVerifyInit(*mdCtx, opCtx, NULL, NULL, *pkey);
    if (initRet != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return HKS_SUCCESS;
}

static int32_t MlDsaDoSign(EVP_MD_CTX *mdCtx, const struct HksBlob *message, struct HksBlob *signature)
{
    size_t outSize = signature->size;
    if (EVP_DigestSign(mdCtx, signature->data, &outSize, message->data, message->size) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    signature->size = (uint32_t)outSize;
    return HKS_SUCCESS;
}

int32_t HksOpensslMlDsaSign(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *signature)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdCtx = NULL;
    EVP_PKEY_CTX *signCtx = NULL;
    struct HksBlob encodedMessage = { 0, NULL };
    const struct HksBlob *messageToSign = NULL;

    int32_t ret = MlDsaPrepareMessageToUse(usageSpec, message, &encodedMessage, &messageToSign);
    if (ret == HKS_SUCCESS) {
        ret = MlDsaInitSignVerifyOpCtx(key, true, &pkey, &mdCtx, &signCtx);
    }
    if (ret == HKS_SUCCESS) {
        ret = MlDsaSetSignVerifyParam(signCtx, usageSpec);
    }
    if (ret == HKS_SUCCESS) {
        ret = MlDsaDoSign(mdCtx, messageToSign, signature);
    }

    HKS_MEMSET_FREE_BLOB(encodedMessage);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdCtx);
    return ret;
}

static int32_t MlDsaDoVerify(EVP_MD_CTX *mdCtx, const struct HksBlob *message,
    const struct HksBlob *signature)
{
    if (EVP_DigestVerify(mdCtx, signature->data, signature->size, message->data, message->size) !=
        HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return HKS_SUCCESS;
}

int32_t HksOpensslMlDsaVerify(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdCtx = NULL;
    EVP_PKEY_CTX *verifyCtx = NULL;
    struct HksBlob encodedMessage = { 0, NULL };
    const struct HksBlob *messageToVerify = NULL;

    int32_t ret = MlDsaPrepareMessageToUse(usageSpec, message, &encodedMessage, &messageToVerify);
    if (ret == HKS_SUCCESS) {
        ret = MlDsaInitSignVerifyOpCtx(key, false, &pkey, &mdCtx, &verifyCtx);
    }
    if (ret == HKS_SUCCESS) {
        ret = MlDsaSetSignVerifyParam(verifyCtx, usageSpec);
    }
    if (ret == HKS_SUCCESS) {
        ret = MlDsaDoVerify(mdCtx, messageToVerify, signature);
    }

    HKS_MEMSET_FREE_BLOB(encodedMessage);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdCtx);
    return ret;
}
#endif //HKS_SUPPORT_ML_DSA_SIGN_VERIFY

#endif // HKS_SUPPORT_ML_DSA_C
