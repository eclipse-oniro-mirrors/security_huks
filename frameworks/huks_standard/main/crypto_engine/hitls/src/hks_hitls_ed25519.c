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
#define HUKS_DISABLE_LOG_AT_FILE_TO_REDUCE_ROM_SIZE

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#ifdef _CUT_AUTHENTICATE_
#undef HKS_SUPPORT_ED25519_C
#endif

/*
 * ED25519 provider of the mini system, backed by OpenHiTLS.
 * mbedtls does not support EdDSA and the openssl based implementation
 * (hks_crypto_ed25519.c) is exclusive to small/standard systems.
 * Both implementations share the ability-table contract declared in
 * hks_crypto_ed25519.h and are selected exclusively by gn at build time.
 */
#ifdef HKS_SUPPORT_ED25519_C

#include "hks_crypto_ed25519.h"

#include <securec.h>

#include "crypt_algid.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "trng.h"

#include "hks_common_check.h"
#include "hks_crypto_hal.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_pthread_util.h"

static pthread_mutex_t g_hitlsEd25519Lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef HKS_SUPPORT_ED25519_GENERATE_KEY
static int32_t SaveEd25519KeyMaterial(const struct HksBlob *pubKey, const struct HksBlob *priKey,
    struct HksBlob *keyOut)
{
    uint32_t totalSize = sizeof(struct KeyMaterial25519) + pubKey->size + priKey->size;
    keyOut->data = (uint8_t *)HksMalloc(totalSize);
    HKS_IF_NULL_LOGE_RETURN(keyOut->data, HKS_ERROR_MALLOC_FAIL, "malloc ed25519 key material failed")
    keyOut->size = totalSize;

    struct KeyMaterial25519 *keyMaterial = (struct KeyMaterial25519 *)keyOut->data;
    keyMaterial->keyAlg = HKS_ALG_ED25519;
    keyMaterial->keySize = HKS_CURVE25519_KEY_SIZE_256;
    keyMaterial->pubKeySize = pubKey->size;
    keyMaterial->priKeySize = priKey->size;
    keyMaterial->reserved = 0;

    uint32_t offset = sizeof(struct KeyMaterial25519);
    if (memcpy_s(keyOut->data + offset, totalSize - offset, pubKey->data, pubKey->size) != EOK) {
        HKS_LOG_E("copy ed25519 public key failed");
        HKS_MEMSET_FREE_BLOB(*keyOut);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    offset += pubKey->size;
    if (memcpy_s(keyOut->data + offset, totalSize - offset, priKey->data, priKey->size) != EOK) {
        HKS_LOG_E("copy ed25519 private key failed");
        HKS_MEMSET_FREE_BLOB(*keyOut);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    return HKS_SUCCESS;
}

static bool IsBlobZero(const struct HksBlob *key)
{
    volatile uint8_t diff = 0;
    for (uint32_t i = 0; i < key->size; ++i) {
        diff |= key->data[i];
    }
    return diff == 0;
}

static void HksCleanEntropy(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    if (entropy != NULL && entropy->data != NULL) {
        (void)memset_s(entropy->data, entropy->len, 0, entropy->len);
        free(entropy->data);
        entropy->data = NULL;
        entropy->len = 0;
    }
}

static int32_t HksGetEntropy(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    if (entropy == NULL || lenRange == NULL) {
        return CRYPT_NULL_INPUT;
    }

    uint32_t entropyLen = (strength + 7U) / 8U;
    if (entropyLen < lenRange->min) {
        entropyLen = lenRange->min;
    }
    if (entropyLen > lenRange->max) {
        entropyLen = lenRange->max;
    }
    if (entropyLen == 0) {
        return CRYPT_NULL_INPUT;
    }

    entropy->data = (uint8_t *)calloc(1U, entropyLen);
    if (entropy->data == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    entropy->len = entropyLen;

    errcode_t ret = uapi_drv_cipher_trng_get_random_bytes(entropy->data, entropy->len);
    if (ret != ERRCODE_SUCC) {
        HKS_LOG_E("get entropy failed, ret = %" LOG_PUBLIC "d", ret);
        HksCleanEntropy(ctx, entropy);
        return CRYPT_DRBG_FAIL_GET_ENTROPY;
    }
    return CRYPT_SUCCESS;
}

static CRYPT_RandSeedMethod g_hitlsRandSeedMeth = {
    .getEntropy = HksGetEntropy,
    .cleanEntropy = HksCleanEntropy,
};

/* CRYPT_EAL_RandInit is not thread safe, ensure initialize the random number generator once */
static int32_t HitlsRandInitOnce(void)
{
    static volatile bool randInited = false;
    if (randInited) {
        return HKS_SUCCESS;
    }

    HKS_IF_NOT_SUCC_LOGE_RETURN(HKS_LOCK_OR_FAIL(g_hitlsEd25519Lock), HKS_ERROR_PTHREAD_MUTEX_LOCK_FAIL, "lock fail");
    if (randInited) {
        HKS_UNLOCK_OR_FAIL(g_hitlsEd25519Lock);
        return HKS_SUCCESS;
    }

    int32_t ret = CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, &g_hitlsRandSeedMeth, NULL, NULL, 0);
    if (ret == CRYPT_SUCCESS || ret == CRYPT_EAL_ERR_DRBG_REPEAT_INIT) {
        randInited = true;
    } else {
        HKS_LOG_E("hitls rand init failed, ret = %" LOG_PUBLIC "d", ret);
        ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    HKS_UNLOCK_OR_FAIL(g_hitlsEd25519Lock);

    return randInited ? HKS_SUCCESS : ret;
}

/* Generate an ed25519 key pair with OpenHiTLS and export the raw pub/pri key. */
static int32_t HitlsEd25519GenKeyPair(struct HksBlob *pubKeyBlob, struct HksBlob *priKeyBlob)
{
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED25519);
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_CRYPTO_ENGINE_ERROR, "hitls ed25519 new ctx failed")

    int32_t ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    do {
        int32_t hret = CRYPT_EAL_PkeyGen(ctx);
        HKS_IF_TRUE_LOGE_BREAK(hret != CRYPT_SUCCESS, "ed25519 generate key failed, ret = %" LOG_PUBLIC "d", hret)

        CRYPT_EAL_PkeyPub pub = {0};
        pub.id = CRYPT_PKEY_ED25519;
        pub.key.curve25519Pub.data = pubKeyBlob->data;
        pub.key.curve25519Pub.len = pubKeyBlob->size;
        hret = CRYPT_EAL_PkeyGetPub(ctx, &pub);
        HKS_IF_TRUE_LOGE_BREAK(hret != CRYPT_SUCCESS, "ed25519 get public key failed, ret = %" LOG_PUBLIC "d", hret)
        HKS_IF_TRUE_LOGE_BREAK(pub.key.curve25519Pub.len != pubKeyBlob->size, "ed25519 public key size mismatch")

        CRYPT_EAL_PkeyPrv prv = {0};
        prv.id = CRYPT_PKEY_ED25519;
        prv.key.curve25519Prv.data = priKeyBlob->data;
        prv.key.curve25519Prv.len = priKeyBlob->size;
        hret = CRYPT_EAL_PkeyGetPrv(ctx, &prv);
        HKS_IF_TRUE_LOGE_BREAK(hret != CRYPT_SUCCESS, "ed25519 get private key failed, ret = %" LOG_PUBLIC "d", hret)
        HKS_IF_TRUE_LOGE_BREAK(prv.key.curve25519Prv.len != priKeyBlob->size, "ed25519 private key size mismatch")
        ret = HKS_SUCCESS;
    } while (0);

    if (ret != HKS_SUCCESS) {
        (void)memset_s(pubKeyBlob->data, pubKeyBlob->size, 0, pubKeyBlob->size);
        (void)memset_s(priKeyBlob->data, priKeyBlob->size, 0, priKeyBlob->size);
    }
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
}

int32_t HksEd25519GenerateKey(const struct HksKeySpec *spec, struct HksBlob *keyOut)
{
    (void)spec;
    uint8_t pubKey[ED25519_PUBLIC_KEY_LEN] = {0};
    uint8_t priKey[ED25519_PRIVATE_KEY_LEN] = {0};
    struct HksBlob pubKeyBlob = { ED25519_PUBLIC_KEY_LEN, pubKey };
    struct HksBlob priKeyBlob = { ED25519_PRIVATE_KEY_LEN, priKey };

    if (HitlsRandInitOnce() != HKS_SUCCESS) {
        HKS_LOG_E("hitls rand init failed");
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    int32_t ret = HitlsEd25519GenKeyPair(&pubKeyBlob, &priKeyBlob);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    if (IsBlobZero(&pubKeyBlob) || IsBlobZero(&priKeyBlob)) {
        HKS_LOG_E("hitls ed25519 generate key failed");
        (void)memset_s(priKeyBlob.data, ED25519_PRIVATE_KEY_LEN, 0, ED25519_PRIVATE_KEY_LEN);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = SaveEd25519KeyMaterial(&pubKeyBlob, &priKeyBlob, keyOut);
    (void)memset_s(priKeyBlob.data, ED25519_PRIVATE_KEY_LEN, 0, ED25519_PRIVATE_KEY_LEN);
    return ret;
}
#endif /* HKS_SUPPORT_ED25519_GENERATE_KEY */

#ifdef HKS_SUPPORT_ED25519_GET_PUBLIC_KEY
int32_t HksGetEd25519PubKey(const struct HksBlob *input, struct HksBlob *output)
{
    int32_t ret = CheckAsyKeyMaterialSize(HKS_ALG_ED25519, input, output);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    struct KeyMaterial25519 *key = (struct KeyMaterial25519 *)input->data;
    uint32_t outLen = sizeof(struct KeyMaterial25519) + key->pubKeySize;
    if (memcpy_s(output->data, output->size, key, outLen) != EOK) {
        HKS_LOG_E("memcpy_s ed25519 pub key failed");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    ((struct KeyMaterial25519 *)output->data)->priKeySize = 0;
    ((struct KeyMaterial25519 *)output->data)->reserved = 0;
    output->size = outLen;
    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_ED25519_SIGN_VERIFY
int32_t HksEd25519Sign(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *signature)
{
    (void)usageSpec;
    int32_t ret = CheckAsyKeyMaterialSize(HKS_ALG_ED25519, key, NULL);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_INFO, "invalid ed25519 key material")
    if (signature->size < HKS_SIGNATURE_MIN_SIZE) {
        HKS_LOG_E("invalid param : signature size = %" LOG_PUBLIC "u", signature->size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    struct KeyMaterial25519 *km = (struct KeyMaterial25519 *)key->data;
    if (km->priKeySize != ED25519_PRIVATE_KEY_LEN) {
        HKS_LOG_E("invalid ed25519 private key size = %" LOG_PUBLIC "u", km->priKeySize);
        return HKS_ERROR_INVALID_KEY_INFO;
    }
    /* public keysize must be 0 or 32 bytes */
    if (km->pubKeySize != ED25519_PUBLIC_KEY_LEN && km->pubKeySize != 0) {
        HKS_LOG_E("invalid ed25519 public key size = %" LOG_PUBLIC "u", km->pubKeySize);
        return HKS_ERROR_INVALID_KEY_INFO;
    }
    const uint8_t *priKey = key->data + sizeof(struct KeyMaterial25519) + km->pubKeySize;

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED25519);
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_CRYPTO_ENGINE_ERROR, "hitls ed25519 new ctx failed")

    int32_t hret;
    ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    do {
        CRYPT_EAL_PkeyPrv prv = {0};
        prv.id = CRYPT_PKEY_ED25519;
        prv.key.curve25519Prv.data = (uint8_t *)priKey;
        prv.key.curve25519Prv.len = km->priKeySize;
        hret = CRYPT_EAL_PkeySetPrv(ctx, &prv);
        if (hret != CRYPT_SUCCESS) {
            HKS_LOG_E("hitls ed25519 set private key failed, ret = %" LOG_PUBLIC "d", hret);
            break;
        }

        /* PureEdDSA: the SHA512 hash is built into the algorithm, so the message
         * must be the complete plaintext, which the three-stage framework guarantees. */
        uint32_t signLen = HKS_SIGNATURE_MIN_SIZE;
        hret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SHA512, message->data, message->size,
            signature->data, &signLen);
        if (hret != CRYPT_SUCCESS) {
            HKS_LOG_E("hitls ed25519 sign failed, ret = %" LOG_PUBLIC "d", hret);
            break;
        }
        signature->size = signLen;
        ret = HKS_SUCCESS;
    } while (0);

    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
}

int32_t HksEd25519Verify(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature)
{
    (void)usageSpec;
    int32_t ret = CheckAsyKeyMaterialSize(HKS_ALG_ED25519, key, NULL);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_INFO, "invalid ed25519 key material")
    if (signature->size < HKS_SIGNATURE_MIN_SIZE) {
        HKS_LOG_E("invalid param : signature size = %" LOG_PUBLIC "u", signature->size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    struct KeyMaterial25519 *km = (struct KeyMaterial25519 *)key->data;
    if (km->pubKeySize != ED25519_PUBLIC_KEY_LEN) {
        HKS_LOG_E("invalid ed25519 public key size = %" LOG_PUBLIC "u", km->pubKeySize);
        return HKS_ERROR_INVALID_KEY_INFO;
    }
    const uint8_t *pubKey = key->data + sizeof(struct KeyMaterial25519);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED25519);
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_CRYPTO_ENGINE_ERROR, "hitls ed25519 new ctx failed")

    int32_t hret;
    ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    do {
        CRYPT_EAL_PkeyPub pub = {0};
        pub.id = CRYPT_PKEY_ED25519;
        pub.key.curve25519Pub.data = (uint8_t *)pubKey;
        pub.key.curve25519Pub.len = km->pubKeySize;
        hret = CRYPT_EAL_PkeySetPub(ctx, &pub);
        if (hret != CRYPT_SUCCESS) {
            HKS_LOG_E("hitls ed25519 set public key failed, ret = %" LOG_PUBLIC "d", hret);
            break;
        }

        /* aligned with the L2 openssl engine: the signature size is passed
         * through as is, and any length other than 64 fails verification */
        hret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHA512, message->data, message->size,
            signature->data, signature->size);
        if (hret != CRYPT_SUCCESS) {
            HKS_LOG_E("hitls ed25519 verify failed, ret = %" LOG_PUBLIC "d", hret);
            break;
        }
        ret = HKS_SUCCESS;
    } while (0);

    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
}
#endif /* HKS_SUPPORT_ED25519_SIGN_VERIFY */
#endif /* HKS_SUPPORT_ED25519_C */
