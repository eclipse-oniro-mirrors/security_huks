/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hks_ability.h"
#include "hks_core_ability.h"

#include "hks_crypto_ed25519.h"
#include "hks_log.h"
#include "hks_mbedtls_aes.h"
#include "hks_mbedtls_bn.h"
#include "hks_mbedtls_common.h"
#include "hks_mbedtls_des.h"
#include "hks_mbedtls_3des.h"
#include "hks_mbedtls_dh.h"
#include "hks_mbedtls_dsa.h"
#include "hks_mbedtls_ecc.h"
#include "hks_mbedtls_ecdh.h"
#include "hks_mbedtls_ecdsa.h"
#include "hks_mbedtls_hash.h"
#include "hks_mbedtls_hmac.h"
#include "hks_mbedtls_kdf.h"
#include "hks_mbedtls_rsa.h"
#include "hks_mbedtls_x25519.h"

#ifdef _CUT_AUTHENTICATE_
#undef HKS_SUPPORT_HASH_C
#undef HKS_SUPPORT_RSA_C
#undef HKS_SUPPORT_ECC_C
#undef HKS_SUPPORT_X25519_C
#undef HKS_SUPPORT_ED25519_C
#undef HKS_SUPPORT_KDF_PBKDF2
#endif

static void RegisterAbilityGenerateKey(void)
{
#if defined(HKS_SUPPORT_AES_C) && defined(HKS_SUPPORT_AES_GENERATE_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GENERATE_KEY(HKS_ALG_AES), (void *)HksMbedtlsAesGenerateKey);
#endif
#if defined(HKS_SUPPORT_DES_C) && defined(HKS_SUPPORT_DES_GENERATE_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GENERATE_KEY(HKS_ALG_DES), (void *)HksMbedtlsDesGenerateKey);
#endif
#if defined(HKS_SUPPORT_3DES_C) && defined(HKS_SUPPORT_3DES_GENERATE_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GENERATE_KEY(HKS_ALG_3DES), (void *)HksMbedtls3DesGenerateKey);
#endif
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_GENERATE_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GENERATE_KEY(HKS_ALG_RSA), (void *)HksMbedtlsRsaGenerateKey);
#endif
#if defined(HKS_SUPPORT_ECC_C) && defined(HKS_SUPPORT_ECC_GENERATE_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GENERATE_KEY(HKS_ALG_ECC), (void *)HksMbedtlsEccGenerateKey);
#endif
#if defined(HKS_SUPPORT_X25519_C) && defined(HKS_SUPPORT_X25519_GENERATE_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GENERATE_KEY(HKS_ALG_X25519), (void *)HksMbedtlsX25519GenerateKey);
#endif
#if defined(HKS_SUPPORT_ED25519_C) && defined(HKS_SUPPORT_ED25519_GENERATE_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GENERATE_KEY(HKS_ALG_ED25519), (void *)HksEd25519GenerateKey);
#endif
#if defined(HKS_SUPPORT_HMAC_C) && defined(HKS_SUPPORT_HMAC_GENERATE_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GENERATE_KEY(HKS_ALG_HMAC), (void *)HksMbedtlsHmacGenerateKey);
#endif
#if defined(HKS_SUPPORT_DSA_C) && defined(HKS_SUPPORT_DSA_GENERATE_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GENERATE_KEY(HKS_ALG_DSA), (void *)HksMbedtlsDsaGenerateKey);
#endif
#if defined(HKS_SUPPORT_DH_C) && defined(HKS_SUPPORT_DH_GENERATE_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GENERATE_KEY(HKS_ALG_DH), (void *)HksMbedtlsDhGenerateKey);
#endif
}

static void RegisterAbilityGetPublicKey(void)
{
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_GET_PUBLIC_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GET_PUBLIC_KEY(HKS_ALG_RSA), (void *)HksMbedtlsGetRsaPubKey);
#endif
#if defined(HKS_SUPPORT_ECC_C) && defined(HKS_SUPPORT_ECC_GET_PUBLIC_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GET_PUBLIC_KEY(HKS_ALG_ECC), (void *)HksMbedtlsGetEccPubKey);
#endif
#if defined(HKS_SUPPORT_ED25519_C) && defined(HKS_SUPPORT_ED2519_GET_PUBLIC_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GET_PUBLIC_KEY(HKS_ALG_ED25519), (void *)HksGetEd25519PubKey);
#endif
#if defined(HKS_SUPPORT_X25519_C) && defined(HKS_SUPPORT_X25519_GET_PUBLIC_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GET_PUBLIC_KEY(HKS_ALG_X25519), (void *)HksMbedtlsGetX25519PubKey);
#endif
#if defined(HKS_SUPPORT_DH_C) && defined(HKS_SUPPORT_DH_GET_PUBLIC_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_GET_PUBLIC_KEY(HKS_ALG_DH), (void *)HksMbedtlsGetDhPubKey);
#endif
}

static void RegisterAbilitySign(void)
{
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_SIGN_VERIFY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_SIGN(HKS_ALG_RSA), (void *)HksMbedtlsRsaSign);
#endif
#if defined(HKS_SUPPORT_ECC_C) && defined(HKS_SUPPORT_ECDSA_C) && defined(HKS_SUPPORT_ECDSA_SIGN_VERIFY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_SIGN(HKS_ALG_ECC), (void *)HksMbedtlsEcdsaSign);
#endif
#if defined(HKS_SUPPORT_ED25519_C) && defined(HKS_SUPPORT_ED25519_SIGN_VERIFY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_SIGN(HKS_ALG_ED25519), (void *)HksEd25519Sign);
#endif
}

static void RegisterAbilityVerify(void)
{
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_SIGN_VERIFY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_VERIFY(HKS_ALG_RSA), (void *)HksMbedtlsRsaVerify);
#endif
#if defined(HKS_SUPPORT_ECC_C) && defined(HKS_SUPPORT_ECDSA_C) && defined(HKS_SUPPORT_ECDSA_SIGN_VERIFY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_VERIFY(HKS_ALG_ECC), (void *)HksMbedtlsEcdsaVerify);
#endif
#if defined(HKS_SUPPORT_ED25519_C) && defined(HKS_SUPPORT_ED25519_SIGN_VERIFY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_VERIFY(HKS_ALG_ED25519), (void *)HksEd25519Verify);
#endif
}

static void RegisterAbilityEncrypt(void)
{
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_CRYPT)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_ENCRYPT(HKS_ALG_RSA), (void *)HksMbedtlsRsaEncrypt);
#endif
#ifdef HKS_SUPPORT_AES_C
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_ENCRYPT(HKS_ALG_AES), (void *)HksMbedtlsAesEncrypt);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_ENCRYPT_INIT(HKS_ALG_AES),
        (void *)HksMbedtlsAesCryptoInit);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_ENCRYPT_UPDATE(HKS_ALG_AES),
        (void *)HksMbedtlsAesCryptoUpdate);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_ENCRYPT_FINAL(HKS_ALG_AES),
        (void *)HksMbedtlsAesCryptoFinal);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_ENCRYPT_FREE_CTX(HKS_ALG_AES),
        (void *)HksMbedtlsAesHalFreeCtx);
#endif
#ifdef HKS_SUPPORT_DES_C
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_ENCRYPT_INIT(HKS_ALG_DES),
        (void *)HksMbedtlsDesCryptoInit);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_ENCRYPT_UPDATE(HKS_ALG_DES),
        (void *)HksMbedtlsDesCryptoUpdate);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_ENCRYPT_FINAL(HKS_ALG_DES),
        (void *)HksMbedtlsDesCryptoFinal);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_ENCRYPT_FREE_CTX(HKS_ALG_DES),
        (void *)HksMbedtlsDesHalFreeCtx);
#endif
#ifdef HKS_SUPPORT_3DES_C
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_ENCRYPT_INIT(HKS_ALG_3DES),
        (void *)HksMbedtls3DesCryptoInit);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_ENCRYPT_UPDATE(HKS_ALG_3DES),
        (void *)HksMbedtls3DesCryptoUpdate);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_ENCRYPT_FINAL(HKS_ALG_3DES),
        (void *)HksMbedtls3DesCryptoFinal);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_ENCRYPT_FREE_CTX(HKS_ALG_3DES),
        (void *)HksMbedtls3DesHalFreeCtx);
#endif
}

static void RegisterAbilityDecrypt(void)
{
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_CRYPT)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DECRYPT(HKS_ALG_RSA), (void *)HksMbedtlsRsaDecrypt);
#endif
#ifdef HKS_SUPPORT_AES_C
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DECRYPT(HKS_ALG_AES), (void *)HksMbedtlsAesDecrypt);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DECRYPT_INIT(HKS_ALG_AES),
        (void *)HksMbedtlsAesCryptoInit);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DECRYPT_UPDATE(HKS_ALG_AES),
        (void *)HksMbedtlsAesCryptoUpdate);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DECRYPT_FINAL(HKS_ALG_AES),
        (void *)HksMbedtlsAesCryptoFinal);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DECRYPT_FREE_CTX(HKS_ALG_AES),
        (void *)HksMbedtlsAesHalFreeCtx);
#endif
#ifdef HKS_SUPPORT_DES_C
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DECRYPT_INIT(HKS_ALG_DES),
        (void *)HksMbedtlsDesCryptoInit);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DECRYPT_UPDATE(HKS_ALG_DES),
        (void *)HksMbedtlsDesCryptoUpdate);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DECRYPT_FINAL(HKS_ALG_DES),
        (void *)HksMbedtlsDesCryptoFinal);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DECRYPT_FREE_CTX(HKS_ALG_DES),
        (void *)HksMbedtlsDesHalFreeCtx);
#endif
#ifdef HKS_SUPPORT_3DES_C
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DECRYPT_INIT(HKS_ALG_3DES),
        (void *)HksMbedtls3DesCryptoInit);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DECRYPT_UPDATE(HKS_ALG_3DES),
        (void *)HksMbedtls3DesCryptoUpdate);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DECRYPT_FINAL(HKS_ALG_3DES),
        (void *)HksMbedtls3DesCryptoFinal);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DECRYPT_FREE_CTX(HKS_ALG_3DES),
        (void *)HksMbedtls3DesHalFreeCtx);
#endif
}

static void RegisterAbilityAgree(void)
{
#if defined(HKS_SUPPORT_ECC_C) && defined(HKS_SUPPORT_ECDH_C) && defined(HKS_SUPPORT_ECDH_AGREE_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_AGREE_KEY(HKS_ALG_ECDH), (void *)HksMbedtlsEcdh);
#endif
#if defined(HKS_SUPPORT_X25519_C) && defined(HKS_SUPPORT_X25519_AGREE_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_AGREE_KEY(HKS_ALG_X25519), (void *)HksMbedtlsX25519KeyAgreement);
#endif
#ifdef HKS_SUPPORT_ED25519_TO_X25519
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_AGREE_KEY(HKS_ALG_ED25519), (void *)HksMbedtlsEd25519KeyAgreement);
#endif
#if defined(HKS_SUPPORT_DH_C) && defined(HKS_SUPPORT_DH_AGREE_KEY)
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_AGREE_KEY(HKS_ALG_DH), (void *)HksMbedtlsDhAgreeKey);
#endif
}

static void RegisterAbilityDerive(void)
{
#ifdef HKS_SUPPORT_KDF_HKDF
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DERIVE_KEY(HKS_ALG_HKDF), (void *)HksMbedtlsDeriveKey);
#endif
#ifdef HKS_SUPPORT_KDF_PBKDF2
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_DERIVE_KEY(HKS_ALG_PBKDF2), (void *)HksMbedtlsDeriveKey);
#endif
}

static void RegisterAbilityHash(void)
{
#ifdef HKS_SUPPORT_HASH_C
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_HASH, (void *)HksMbedtlsHash);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_HASH_INIT, (void *)HksMbedtlsHashInit);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_HASH_UPDATE, (void *)HksMbedtlsHashUpdate);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_HASH_FINAL, (void *)HksMbedtlsHashFinal);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_HASH_FREE_CTX, (void *)HksMbedtlsHashFreeCtx);
#endif
}

static void RegisterAbilityHmac(void)
{
#ifdef HKS_SUPPORT_HMAC_C
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_HMAC, (void *)HksMbedtlsHmac);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_HMAC_INIT, (void *)HksMbedtlsHmacInit);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_HMAC_UPDATE, (void *)HksMbedtlsHmacUpdate);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_HMAC_FINAL, (void *)HksMbedtlsHmacFinal);
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_HMAC_FREE_CTX, (void *)HksMbedtlsHmacHalFreeCtx);
#endif
}

static void RegisterAbilityFillRandom(void)
{
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_FILL_RANDOM, (void *)HksMbedtlsFillRandom);
}

static void RegisterAbilityBnExpMod(void)
{
#ifdef HKS_SUPPORT_BN_C
    (void)RegisterAbility(HKS_CRYPTO_ABILITY_BN_EXP_MOD, (void *)HksMbedtlsBnExpMod);
#endif
}

int32_t HksCryptoAbilityInitBase(void)
{
    RegisterAbilityGenerateKey();
    RegisterAbilityGetPublicKey();
    RegisterAbilitySign();
    RegisterAbilityVerify();
    RegisterAbilityEncrypt();
    RegisterAbilityDecrypt();
    RegisterAbilityAgree();
    RegisterAbilityDerive();
    RegisterAbilityHmac();
    RegisterAbilityHash();
    RegisterAbilityFillRandom();
    RegisterAbilityBnExpMod();
    return HKS_SUCCESS;
}