/*
 * Copyright (c) 2020-2022 Huawei Device Co., Ltd.
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

#ifdef _CUT_AUTHENTICATE_
#undef HKS_SUPPORT_ED25519_C
#endif

#ifdef HKS_SUPPORT_ED25519_C

#include "hks_crypto_ed25519.h"


#include "hks_crypto_hal.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"

#include <crypto/ecx.h>
#include <securec.h>

#define CRYPTO_SUCCESS 1
#define ED25519_PRIVATE_KEY_LEN 32
#define ED25519_PUBLIC_KEY_LEN 32

#ifdef HKS_SUPPORT_ED25519_GENERATE_KEY
static int32_t SaveEd25519KeyMaterial(const struct HksBlob *pubKey, const struct HksBlob *priKey,
    struct HksBlob *keyOut)
{
    uint32_t totalSize = sizeof(struct KeyMaterial25519) + pubKey->size + priKey->size;
    uint8_t *buffer = (uint8_t *)HksMalloc(totalSize);
    HKS_IF_NULL_RETURN(buffer, HKS_ERROR_MALLOC_FAIL)

    struct KeyMaterial25519 *keyMaterial = (struct KeyMaterial25519 *)buffer;
    keyMaterial->keyAlg = HKS_ALG_ED25519;
    keyMaterial->keySize = HKS_CURVE25519_KEY_SIZE_256;
    keyMaterial->pubKeySize = pubKey->size;
    keyMaterial->priKeySize = priKey->size;
    keyMaterial->reserved = 0;

    uint32_t offset = sizeof(struct KeyMaterial25519);
    if (memcpy_s(buffer + offset, totalSize - offset, pubKey->data, pubKey->size) != EOK) {
        HKS_LOG_E("copy ed25519 public key failed");
        (void)memset_s(buffer, totalSize, 0, totalSize);
        HKS_FREE(buffer);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    offset += pubKey->size;
    if (memcpy_s(buffer + offset, totalSize - offset, priKey->data, priKey->size) != EOK) {
        HKS_LOG_E("copy ed25519 private key failed");
        (void)memset_s(buffer, totalSize, 0, totalSize);
        HKS_FREE(buffer);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    keyOut->data = buffer;
    keyOut->size = totalSize;
    return HKS_SUCCESS;
}

static bool IsBlobZero(const struct HksBlob *key)
{
    for (uint32_t i = 0; i < key->size; ++i) {
        if (key->data[i] != 0) {
            return false;
        }
    }
    return true;
}

int32_t HksEd25519GenerateKey(const struct HksKeySpec *spec, struct HksBlob *keyOut)
{
    (void)spec;
    uint8_t pubKey[ED25519_PUBLIC_KEY_LEN] = {0};
    uint8_t priKey[ED25519_PRIVATE_KEY_LEN] = {0};
    struct HksBlob pubKeyBlob = { ED25519_PUBLIC_KEY_LEN, pubKey };
    struct HksBlob priKeyBlob = { ED25519_PRIVATE_KEY_LEN, priKey };

    struct HksBlob tmp = { ED25519_PUBLIC_KEY_LEN, priKeyBlob.data };
    int32_t ret = HksCryptoHalFillPrivRandom(&tmp);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ossl_ed25519_public_from_private(NULL, pubKeyBlob.data, priKeyBlob.data, NULL);
    if (IsBlobZero(&pubKeyBlob) || IsBlobZero(&priKeyBlob)) {
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = SaveEd25519KeyMaterial(&pubKeyBlob, &priKeyBlob, keyOut);
    (void)memset_s(priKeyBlob.data, ED25519_PRIVATE_KEY_LEN, 0, ED25519_PRIVATE_KEY_LEN);
    return ret;
}
#endif /* HKS_SUPPORT_ED25519_GENERATE_KEY */

static int32_t CheckEd25519Material(const struct HksBlob *key)
{
    uint32_t totalSize = sizeof(struct KeyMaterial25519);
    if (key->size < totalSize) {
        HKS_LOG_E("Ed25519 key material too small");
        return HKS_ERROR_INVALID_KEY_INFO;
    }

    struct KeyMaterial25519 *km = (struct KeyMaterial25519 *)key->data;
    if (((key->size - totalSize) < km->pubKeySize) ||
        ((key->size - totalSize) < km->priKeySize) ||
        (km->pubKeySize > (UINT32_MAX - km->priKeySize)) ||
        ((key->size - totalSize) < (km->pubKeySize + km->priKeySize))) {
        HKS_LOG_E("Ed25519 key material wrong pub and pri key size %" LOG_PUBLIC "u, %" LOG_PUBLIC "u, "
            "%" LOG_PUBLIC "u", key->size, km->pubKeySize, km->priKeySize);
        return HKS_ERROR_INVALID_KEY_INFO;
    }

    return HKS_SUCCESS;
}

#ifdef HKS_SUPPORT_ED2519_GET_PUBLIC_KEY
static int32_t GetEd25519PubKeyCheck(const struct HksBlob *key, const struct HksBlob *keyOut)
{
    int32_t ret = CheckEd25519Material(key);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* check keyOut */
    struct KeyMaterial25519 *km = (struct KeyMaterial25519 *)key->data;
    if ((km->pubKeySize > (UINT32_MAX - sizeof(struct KeyMaterial25519))) ||
        (keyOut->size < (sizeof(struct KeyMaterial25519) + km->pubKeySize))) {
        HKS_LOG_E("Ecc public keyOut size too small! keyOut size = 0x%" LOG_PUBLIC "X", keyOut->size);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    return HKS_SUCCESS;
}

int32_t HksGetEd25519PubKey(const struct HksBlob *input, struct HksBlob *output)
{
    int32_t ret = GetEd25519PubKeyCheck(input, output);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    struct KeyMaterial25519 *key = (struct KeyMaterial25519 *)input->data;
    uint32_t outLen = sizeof(struct KeyMaterial25519) + key->pubKeySize;
    if (memcpy_s(output->data, output->size, key, outLen) != EOK) {
        HKS_LOG_E("memcpy_s ed25519 pub key failed");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    ((struct KeyMaterial25519 *)output->data)->priKeySize = 0;
    output->size = outLen;
    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_ED25519_SIGN_VERIFY
int32_t HksEd25519Sign(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *signature)
{
    (void)usageSpec;
    int32_t ret = CheckEd25519Material(key);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    if (signature->size < HKS_SIGNATURE_MIN_SIZE ||
        key->size <= (sizeof(struct KeyMaterial25519) + ED25519_PUBLIC_KEY_LEN)) {
        HKS_LOG_E("invalid param : signature size = %" LOG_PUBLIC "u, key size = %" LOG_PUBLIC "u",
            signature->size, key->size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    ret = ossl_ed25519_sign(signature->data, message->data, message->size,
        key->data + sizeof(struct KeyMaterial25519),
        key->data + sizeof(struct KeyMaterial25519) + ED25519_PUBLIC_KEY_LEN, NULL, NULL);
    if (ret != CRYPTO_SUCCESS) {
        HKS_LOG_E("ED25519_sign failed");
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    signature->size = HKS_SIGNATURE_MIN_SIZE;

    return HKS_SUCCESS;
}

int32_t HksEd25519Verify(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature)
{
    (void)usageSpec;
    int32_t ret = CheckEd25519Material(key);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    if (signature->size < HKS_SIGNATURE_MIN_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    ret = ossl_ed25519_verify(message->data, message->size, signature->data,
        key->data + sizeof(struct KeyMaterial25519), NULL, NULL);
    if (ret != CRYPTO_SUCCESS) {
        HKS_LOG_E("ED25519_verify failed");
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    return HKS_SUCCESS;
}
#endif /* HKS_SUPPORT_ED25519_SIGN_VERIFY */
#endif /* HKS_SUPPORT_ED25519_C */
