/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "hks_base_check.h"

#include "hks_cmd_id.h"
#include "hks_common_check.h"
#include "hks_log.h"
#include "hks_template.h"

#include "securec.h"

#ifdef _CUT_AUTHENTICATE_
#undef HKS_SUPPORT_RSA_C
#undef HKS_SUPPORT_ECC_C
#undef HKS_SUPPORT_ECDH_C
#undef HKS_SUPPORT_X25519_C
#undef HKS_SUPPORT_ED25519_C
#endif

#define HKS_BLOCK_CIPHER_CBC_IV_LEN 16
#define HKS_AES_CCM_AAD_LEN_MIN     4
#define HKS_AES_CCM_NONCE_LEN_MIN   7
#define HKS_AES_CCM_NONCE_LEN_MAX   13
#define HKS_AES_GCM_NONCE_LEN_MIN   12

#define HKS_RSA_OAEP_DIGEST_NUM 2
#define HKS_RSA_KEY_BLOCK_SIZE 8
#define HKS_BLOCK_CIPHER_CBC_BLOCK_SIZE 16

#define HKS_ECC_SIGN_MAX_TL_SIZE    8

#ifdef HKS_SUPPORT_RSA_C
static const uint32_t g_rsaKeySize[] = {
    HKS_RSA_KEY_SIZE_512,
    HKS_RSA_KEY_SIZE_768,
    HKS_RSA_KEY_SIZE_1024,
    HKS_RSA_KEY_SIZE_2048,
    HKS_RSA_KEY_SIZE_3072,
    HKS_RSA_KEY_SIZE_4096
};
static const uint32_t g_rsaPadding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_OAEP,
    HKS_PADDING_PSS,
    HKS_PADDING_PKCS1_V1_5,
    HKS_PADDING_ISO_IEC_9796_2
};
static const uint32_t g_rsaDigest[] = {
    HKS_DIGEST_MD5,
    HKS_DIGEST_NONE,
    HKS_DIGEST_SHA1,
    HKS_DIGEST_SHA224,
    HKS_DIGEST_SHA256,
    HKS_DIGEST_SHA384,
    HKS_DIGEST_SHA512
};
static const uint32_t g_rsaSignPadding[] = {
    HKS_PADDING_PSS,
    HKS_PADDING_PKCS1_V1_5,
    HKS_PADDING_ISO_IEC_9796_2
};
static const uint32_t g_rsaCipherPadding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_OAEP,
    HKS_PADDING_PKCS1_V1_5,
    HKS_PADDING_ISO_IEC_9796_2
};
#endif

#ifdef HKS_SUPPORT_AES_C
static const uint32_t g_aesKeySize[] = {
    HKS_AES_KEY_SIZE_128,
    HKS_AES_KEY_SIZE_192,
    HKS_AES_KEY_SIZE_256
};
static const uint32_t g_aesMacKeySize[] = {
    HKS_AES_KEY_SIZE_256,
};
static const uint32_t g_aesPadding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_PKCS7
};
static const uint32_t g_aesMode[] = {
    HKS_MODE_CBC,
    HKS_MODE_CCM,
    HKS_MODE_CTR,
    HKS_MODE_ECB,
    HKS_MODE_GCM
};
static const uint32_t g_aesCbcPadding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_PKCS7
};
static const uint32_t g_aesAeadPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_aesCtrPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_aesEcbPadding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_PKCS7
};
#endif

#ifdef HKS_SUPPORT_DES_C
static const uint32_t g_desKeySize[] = {
    HKS_DES_KEY_SIZE_64
};
static const uint32_t g_desMacKeySize[] = {
    HKS_DES_KEY_SIZE_64
};
static const uint32_t g_desPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_desMode[] = {
    HKS_MODE_CBC,
    HKS_MODE_ECB
};
static const uint32_t g_desCbcPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_desEcbPadding[] = {
    HKS_PADDING_NONE
};
#endif

#ifdef HKS_SUPPORT_3DES_C
static const uint32_t g_3desKeySize[] = {
    HKS_3DES_KEY_SIZE_128,
    HKS_3DES_KEY_SIZE_192
};
static const uint32_t g_3desMacKeySize[] = {
    HKS_3DES_KEY_SIZE_128,
    HKS_3DES_KEY_SIZE_192
};
static const uint32_t g_3desPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_3desMode[] = {
    HKS_MODE_CBC,
    HKS_MODE_ECB
};
static const uint32_t g_3desCbcPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_3desEcbPadding[] = {
    HKS_PADDING_NONE
};
#endif

#ifdef HKS_SUPPORT_SM4_C
static const uint32_t g_sm4KeySize[] = {
    HKS_SM4_KEY_SIZE_128,
};
static const uint32_t g_sm4Padding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_PKCS7
};
static const uint32_t g_sm4Purpose[] = {
    HKS_KEY_PURPOSE_ENCRYPT,
    HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
};
static const uint32_t g_sm4Mode[] = {
    HKS_MODE_CBC,
    HKS_MODE_CTR,
    HKS_MODE_ECB,
    HKS_MODE_CFB,
    HKS_MODE_OFB,
};
static const uint32_t g_sm4CbcPadding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_PKCS7
};
static const uint32_t g_sm4CtrPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_sm4EcbPadding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_PKCS7
};
static const uint32_t g_sm4CfbPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_sm4OfbPadding[] = {
    HKS_PADDING_NONE
};
#endif

#ifdef HKS_SUPPORT_ECC_C
static const uint32_t g_eccKeySize[] = {
    HKS_ECC_KEY_SIZE_224,
    HKS_ECC_KEY_SIZE_256,
    HKS_ECC_KEY_SIZE_384,
    HKS_ECC_KEY_SIZE_521
};

static const uint32_t g_eccDigest[] = {
    HKS_DIGEST_NONE,
    HKS_DIGEST_SHA1,
    HKS_DIGEST_SHA224,
    HKS_DIGEST_SHA256,
    HKS_DIGEST_SHA384,
    HKS_DIGEST_SHA512
};
#endif

#ifdef HKS_SUPPORT_SM2_C
static const uint32_t g_sm2KeySize[] = {
    HKS_SM2_KEY_SIZE_256
};

static const uint32_t g_sm2Digest[] = {
    HKS_DIGEST_SM3,
    HKS_DIGEST_NONE
};

static const uint32_t g_sm2CipherPadding[] = {
    HKS_PADDING_NONE,
};
#endif

#ifdef HKS_SUPPORT_SM3_C
static const uint32_t g_sm3Digest[] = {
    HKS_DIGEST_SM3
};
#endif

static const uint32_t g_digest[] = {
    HKS_DIGEST_SHA256,
    HKS_DIGEST_SHA384,
    HKS_DIGEST_SHA512
};

static const uint32_t g_macDigest[] = {
    HKS_DIGEST_SHA256
};

#ifdef HKS_SUPPORT_ECDH_C
static const uint32_t g_ecdhKeySize[] = {
    HKS_ECC_KEY_SIZE_224,
    HKS_ECC_KEY_SIZE_256,
    HKS_ECC_KEY_SIZE_384,
    HKS_ECC_KEY_SIZE_521
};
#endif

#if defined(HKS_SUPPORT_X25519_C) || defined(HKS_SUPPORT_ED25519_C)
static const uint32_t g_curve25519KeySize[] = {
    HKS_CURVE25519_KEY_SIZE_256,
};
#endif
#ifdef HKS_SUPPORT_HMAC_C
static const uint32_t g_hmacDigest[] = {
    HKS_DIGEST_SHA1,
    HKS_DIGEST_SHA224,
    HKS_DIGEST_SHA256,
    HKS_DIGEST_SHA384,
    HKS_DIGEST_SHA512,
    HKS_DIGEST_SM3
};
#endif

#ifdef HKS_SUPPORT_DSA_C
static const uint32_t g_dsaDigest[] = {
    HKS_DIGEST_NONE,
    HKS_DIGEST_SHA1,
    HKS_DIGEST_SHA224,
    HKS_DIGEST_SHA256,
    HKS_DIGEST_SHA384,
    HKS_DIGEST_SHA512
};
#endif
#ifdef HKS_SUPPORT_DH_C
static const uint32_t g_dhKeySize[] = {
    HKS_DH_KEY_SIZE_2048,
    HKS_DH_KEY_SIZE_3072,
    HKS_DH_KEY_SIZE_4096
};
#endif

#ifdef HKS_SUPPORT_RSA_C
static const struct ParamsValuesChecker g_rsaParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { true, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { true, 0, false}, { true, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectRsaParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_rsaKeySize, HKS_ARRAY_SIZE(g_rsaKeySize) },
        { true, g_rsaPadding, HKS_ARRAY_SIZE(g_rsaPadding) },
        { false, NULL, 0 },
        { true, g_rsaDigest, HKS_ARRAY_SIZE(g_rsaDigest) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { true, g_rsaKeySize, HKS_ARRAY_SIZE(g_rsaKeySize) },
        { true, g_rsaPadding, HKS_ARRAY_SIZE(g_rsaPadding) },
        { false, NULL, 0 },
        { true, g_rsaDigest, HKS_ARRAY_SIZE(g_rsaDigest) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_AES_C
static const struct ParamsValuesChecker g_aesParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
	{ HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, { { true, 0, false}, { false, 0, false}, { false, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, { { true, 0, false}, { false, 0, false}, { false, 0, false}, { true, 0, false},
        { false, 0, false} } }
};

static const struct ExpectParamsValuesChecker g_expectAesParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_aesKeySize, HKS_ARRAY_SIZE(g_aesKeySize) },
        { true, g_aesPadding, HKS_ARRAY_SIZE(g_aesPadding) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_aesMode, HKS_ARRAY_SIZE(g_aesMode) }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { true, g_aesPadding, HKS_ARRAY_SIZE(g_aesPadding) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_aesMode, HKS_ARRAY_SIZE(g_aesMode) }
        }
    },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, {
        { true, g_aesMacKeySize, HKS_ARRAY_SIZE(g_aesMacKeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_macDigest, HKS_ARRAY_SIZE(g_macDigest) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, {
        { true, g_aesKeySize, HKS_ARRAY_SIZE(g_aesKeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_digest, HKS_ARRAY_SIZE(g_digest) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_DES_C
static const struct ParamsValuesChecker g_desParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, { { true, 0, false}, { false, 0, false}, { false, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, { { true, 0, false}, { false, 0, false}, { false, 0, false}, { true, 0, false},
        { false, 0, false} } }
};

static const struct ExpectParamsValuesChecker g_expectDesParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_desKeySize, HKS_ARRAY_SIZE(g_desKeySize) },
        { true, g_desPadding, HKS_ARRAY_SIZE(g_desPadding) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_desMode, HKS_ARRAY_SIZE(g_desMode) }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { true, g_desPadding, HKS_ARRAY_SIZE(g_desPadding) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_desMode, HKS_ARRAY_SIZE(g_desMode) }
        }
    },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, {
        { true, g_desMacKeySize, HKS_ARRAY_SIZE(g_desMacKeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_macDigest, HKS_ARRAY_SIZE(g_macDigest) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, {
        { true, g_desKeySize, HKS_ARRAY_SIZE(g_desKeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_digest, HKS_ARRAY_SIZE(g_digest) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_3DES_C
static const struct ParamsValuesChecker g_3desParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, { { true, 0, false}, { false, 0, false}, { false, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, { { true, 0, false}, { false, 0, false}, { false, 0, false}, { true, 0, false},
        { false, 0, false} } }
};

static const struct ExpectParamsValuesChecker g_expect3DesParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_3desKeySize, HKS_ARRAY_SIZE(g_3desKeySize) },
        { true, g_3desPadding, HKS_ARRAY_SIZE(g_3desPadding) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_3desMode, HKS_ARRAY_SIZE(g_3desMode) }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { true, g_3desPadding, HKS_ARRAY_SIZE(g_3desPadding) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_3desMode, HKS_ARRAY_SIZE(g_3desMode) }
        }
    },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, {
        { true, g_3desMacKeySize, HKS_ARRAY_SIZE(g_3desMacKeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_macDigest, HKS_ARRAY_SIZE(g_macDigest) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, {
        { true, g_3desKeySize, HKS_ARRAY_SIZE(g_3desKeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_digest, HKS_ARRAY_SIZE(g_digest) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_ECC_C
static const struct ParamsValuesChecker g_eccParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectEccParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_eccKeySize, HKS_ARRAY_SIZE(g_eccKeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_eccDigest, HKS_ARRAY_SIZE(g_eccDigest) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_eccDigest, HKS_ARRAY_SIZE(g_eccDigest) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_SM2_C
static const struct ParamsValuesChecker g_sm2ParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectSm2Params[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_sm2KeySize, HKS_ARRAY_SIZE(g_sm2KeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_sm2Digest, HKS_ARRAY_SIZE(g_sm2Digest) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { true, g_sm2KeySize, HKS_ARRAY_SIZE(g_sm2KeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_sm2Digest, HKS_ARRAY_SIZE(g_sm2Digest) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_SM3_C
static const struct ParamsValuesChecker g_sm3ParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectSm3Params[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_sm3Digest, sizeof(g_sm3Digest) / sizeof(g_sm3Digest[0]) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_sm3Digest, sizeof(g_sm3Digest) / sizeof(g_sm3Digest[0]) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_SM4_C
static const struct ParamsValuesChecker g_sm4ParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { true, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, { { true, 0, false}, { false, 0, false}, { false, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectSm4Params[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_sm4KeySize, HKS_ARRAY_SIZE(g_sm4KeySize) },
        { true, g_sm4Padding, HKS_ARRAY_SIZE(g_sm4Padding) },
        { true, g_sm4Purpose, HKS_ARRAY_SIZE(g_sm4Purpose) },
        { false, NULL, 0 },
        { true, g_sm4Mode, HKS_ARRAY_SIZE(g_sm4Mode) }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { true, g_sm4KeySize, HKS_ARRAY_SIZE(g_sm4KeySize) },
        { true, g_sm4Padding, HKS_ARRAY_SIZE(g_sm4Padding) },
        { true, g_sm4Purpose, HKS_ARRAY_SIZE(g_sm4Purpose) },
        { false, NULL, 0 },
        { true, g_sm4Mode, HKS_ARRAY_SIZE(g_sm4Mode) }
        }
    },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, {
        { true, g_sm4KeySize, HKS_ARRAY_SIZE(g_sm4KeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_sm3Digest, HKS_ARRAY_SIZE(g_sm3Digest) },
        { false, NULL, 0 }
        }
    }
};
#endif

#if defined(HKS_SUPPORT_X25519_C) || defined(HKS_SUPPORT_ED25519_C)
static const struct ParamsValuesChecker g_curve25519ParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { false, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { false, 0, false}, { true, 0, false}, { false, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectCurve25519Params[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_curve25519KeySize, sizeof(g_curve25519KeySize) / sizeof(g_curve25519KeySize[0]) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_HMAC_C
static const struct ParamsValuesChecker g_hmacParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectHmacParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_hmacDigest, sizeof(g_hmacDigest) / sizeof(g_hmacDigest[0]) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_hmacDigest, sizeof(g_hmacDigest) / sizeof(g_hmacDigest[0]) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_hmacDigest, sizeof(g_hmacDigest) / sizeof(g_hmacDigest[0]) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_CMAC_C
static const struct ParamsValuesChecker g_cmacParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectCmacParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_DSA_C
static const struct ParamsValuesChecker g_dsaParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectDsaParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_dsaDigest, sizeof(g_dsaDigest) / sizeof(g_dsaDigest[0]) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_dsaDigest, sizeof(g_dsaDigest) / sizeof(g_dsaDigest[0]) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_DH_C
static const struct ParamsValuesChecker g_dhParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { false, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { false, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectDhParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_dhKeySize, sizeof(g_dhKeySize) / sizeof(g_dhKeySize[0]) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { true, g_dhKeySize, sizeof(g_dhKeySize) / sizeof(g_dhKeySize[0]) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_ECDH_C
static const struct ParamsValuesChecker g_ecdhParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { false, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { false, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectEcdhParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_ecdhKeySize, sizeof(g_ecdhKeySize) / sizeof(g_ecdhKeySize[0]) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { true, g_ecdhKeySize, sizeof(g_ecdhKeySize) / sizeof(g_ecdhKeySize[0]) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifndef _CUT_AUTHENTICATE_
static const uint32_t g_invalidPurpose[][2] = {
#ifdef HKS_SUPPORT_RSA_C
    {
        HKS_ALG_RSA,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP |
            HKS_KEY_PURPOSE_AGREE,
    },
#endif
#ifdef HKS_SUPPORT_ECC_C
    {
        HKS_ALG_ECC,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
    },
#endif
#ifdef HKS_SUPPORT_SM2_C
    {
        HKS_ALG_SM2,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_WRAP,
    },
#endif
#ifdef HKS_SUPPORT_SM3_C
    {
        HKS_ALG_SM3,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_UNWRAP | HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT | HKS_KEY_PURPOSE_AGREE,
    },
#endif
#ifdef HKS_SUPPORT_SM4_C
    {
        HKS_ALG_SM4,
        HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_UNWRAP | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_AGREE,
    },
#endif
#ifdef HKS_SUPPORT_AES_C
    {
        HKS_ALG_AES,
        HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_AGREE | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_UNWRAP,
    },
#endif
#ifdef HKS_SUPPORT_DES_C
    {
        HKS_ALG_DES,
        HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_AGREE | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_UNWRAP,
    },
#endif
#ifdef HKS_SUPPORT_3DES_C
    {
        HKS_ALG_3DES,
        HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_AGREE | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_UNWRAP,
    },
#endif
#ifdef HKS_SUPPORT_ED25519_C
    {
        HKS_ALG_ED25519,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP |
            HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
    },
#endif
#ifdef HKS_SUPPORT_X25519_C
    {
        HKS_ALG_X25519,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT |
            HKS_KEY_PURPOSE_WRAP,
    },
#endif
#ifdef HKS_SUPPORT_HMAC_C
    {
        HKS_ALG_HMAC,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_UNWRAP | HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT | HKS_KEY_PURPOSE_AGREE,
    },
#endif
#ifdef HKS_SUPPORT_CMAC_C
    {
        HKS_ALG_CMAC,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_UNWRAP | HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT | HKS_KEY_PURPOSE_AGREE,
    },
#endif
#ifdef HKS_SUPPORT_DSA_C
    {
        HKS_ALG_DSA,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP |
            HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT | HKS_KEY_PURPOSE_AGREE,
    },
#endif
#ifdef HKS_SUPPORT_DH_C
    {
        HKS_ALG_DH,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP |
            HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT | HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
#endif
#ifdef HKS_SUPPORT_ECDH_C
    {
        HKS_ALG_ECDH,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP |
            HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT | HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
#endif
};

static const uint32_t g_invalidImportKeyPurpose[][2] = {
#ifdef HKS_SUPPORT_ECC_C
    {
        HKS_ALG_ECC,
        HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP,
    },
#endif
#ifdef HKS_SUPPORT_X25519_C
    {
        HKS_ALG_X25519,
        HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP,
    },
#endif
#ifdef HKS_SUPPORT_SM2_C
    {
        HKS_ALG_SM2,
        HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP,
    },
#endif
};
#endif

#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
static const uint32_t g_userAuthChallengeType[] = {
    HKS_CHALLENGE_TYPE_NORMAL,
    HKS_CHALLENGE_TYPE_CUSTOM,
    HKS_CHALLENGE_TYPE_NONE,
};

static const uint32_t g_validBiometricAuthAccessType[] = {
    HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL,
    HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD,
    HKS_AUTH_ACCESS_ALWAYS_VALID
};

static const uint32_t g_validPinAuthAccessType[] = {
    HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD,
    HKS_AUTH_ACCESS_ALWAYS_VALID
};

static const struct AuthAccessTypeChecker g_expectAuthAccessParams[] = {
    { HKS_USER_AUTH_TYPE_FACE,
        { true, g_validBiometricAuthAccessType, HKS_ARRAY_SIZE(g_validBiometricAuthAccessType)}
    },
    { HKS_USER_AUTH_TYPE_FINGERPRINT,
        { true, g_validBiometricAuthAccessType, HKS_ARRAY_SIZE(g_validBiometricAuthAccessType)}
    },
    { HKS_USER_AUTH_TYPE_PIN,
        { true, g_validPinAuthAccessType, HKS_ARRAY_SIZE(g_validPinAuthAccessType)}
    }
};

static const uint32_t g_supportUserAuthTypes[] = {
    HKS_USER_AUTH_TYPE_PIN,
    HKS_USER_AUTH_TYPE_FINGERPRINT,
    HKS_USER_AUTH_TYPE_FACE,
    HKS_USER_AUTH_TYPE_PIN | HKS_USER_AUTH_TYPE_FINGERPRINT,
    HKS_USER_AUTH_TYPE_PIN | HKS_USER_AUTH_TYPE_FACE,
    HKS_USER_AUTH_TYPE_FACE | HKS_USER_AUTH_TYPE_FINGERPRINT,
    HKS_USER_AUTH_TYPE_PIN | HKS_USER_AUTH_TYPE_FACE | HKS_USER_AUTH_TYPE_FINGERPRINT
};

static const uint32_t g_supportSecureSignType[] = {
    HKS_SECURE_SIGN_WITH_AUTHINFO
};

#ifdef HKS_SUPPORT_AES_C
static const uint32_t g_supportAesPurpose[] = {
    HKS_KEY_PURPOSE_ENCRYPT,
    HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_DERIVE,
    HKS_KEY_PURPOSE_MAC
};

static const uint32_t g_supportAesCipherMode[] = {
    HKS_MODE_CBC,
    HKS_MODE_GCM,
    HKS_MODE_CCM
};

static const struct KeyInfoParams g_validAesKeyInfo[] = {
    { true, HKS_TAG_PURPOSE, g_supportAesPurpose, HKS_ARRAY_SIZE(g_supportAesPurpose) },
    { true, HKS_TAG_BLOCK_MODE, g_supportAesCipherMode, HKS_ARRAY_SIZE(g_supportAesCipherMode) }
};
#endif

#ifdef HKS_SUPPORT_DES_C
static const uint32_t g_supportDesPurpose[] = {
    HKS_KEY_PURPOSE_ENCRYPT,
    HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_DERIVE,
    HKS_KEY_PURPOSE_MAC
};

static const uint32_t g_supportDesCipherMode[] = {
    HKS_MODE_CBC,
    HKS_MODE_ECB
};

static const struct KeyInfoParams g_validDesKeyInfo[] = {
    { true, HKS_TAG_PURPOSE, g_supportDesPurpose, HKS_ARRAY_SIZE(g_supportDesPurpose) },
    { true, HKS_TAG_BLOCK_MODE, g_supportDesCipherMode, HKS_ARRAY_SIZE(g_supportDesCipherMode) }
};
#endif

#ifdef HKS_SUPPORT_3DES_C
static const uint32_t g_support3DesPurpose[] = {
    HKS_KEY_PURPOSE_ENCRYPT,
    HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_DERIVE,
    HKS_KEY_PURPOSE_MAC
};

static const uint32_t g_support3DesCipherMode[] = {
    HKS_MODE_CBC,
    HKS_MODE_ECB
};

static const struct KeyInfoParams g_valid3DesKeyInfo[] = {
    { true, HKS_TAG_PURPOSE, g_support3DesPurpose, HKS_ARRAY_SIZE(g_support3DesPurpose) },
    { true, HKS_TAG_BLOCK_MODE, g_support3DesCipherMode, HKS_ARRAY_SIZE(g_support3DesCipherMode) }
};
#endif

#ifdef HKS_SUPPORT_SM4_C
static const uint32_t g_supportSm4Purpose[] = {
    HKS_KEY_PURPOSE_ENCRYPT,
    HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
};

static const uint32_t g_supportSm4CipherMode[] = {
    HKS_MODE_CBC
};

static const struct KeyInfoParams g_validSm4KeyInfo[] = {
    { true, HKS_TAG_PURPOSE, g_supportSm4Purpose, HKS_ARRAY_SIZE(g_supportSm4Purpose) },
    { true, HKS_TAG_BLOCK_MODE, g_supportSm4CipherMode, HKS_ARRAY_SIZE(g_supportSm4CipherMode) }
};
#endif

static const struct AuthAcceessKeyInfoChecker g_validKeyInfo[] = {
#ifdef HKS_SUPPORT_AES_C
    { HKS_ALG_AES, g_validAesKeyInfo, HKS_ARRAY_SIZE(g_validAesKeyInfo) },
#endif
#ifdef HKS_SUPPORT_DES_C
    { HKS_ALG_DES, g_validDesKeyInfo, HKS_ARRAY_SIZE(g_validDesKeyInfo) },
#endif
#ifdef HKS_SUPPORT_3DES_C
    { HKS_ALG_3DES, g_valid3DesKeyInfo, HKS_ARRAY_SIZE(g_valid3DesKeyInfo) },
#endif
#ifdef HKS_SUPPORT_SM4_C
    { HKS_ALG_SM4, g_validSm4KeyInfo, HKS_ARRAY_SIZE(g_validSm4KeyInfo) }
#endif
};
#endif

#ifndef _CUT_AUTHENTICATE_
#ifndef _STORAGE_LITE_
static int32_t CheckAndGetKeySize(const struct HksBlob *key, const uint32_t *expectKeySize,
    uint32_t expectCnt, uint32_t *keySize)
{
    if (key->size < sizeof(struct HksParamSet)) {
        HKS_LOG_E("check key size: invalid keyfile size: %" LOG_PUBLIC "u", key->size);
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    struct HksParamSet *keyParamSet = (struct HksParamSet *)key->data;
    int32_t ret = HksCheckParamSetValidity(keyParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE, "check key size: paramset invalid failed")

    struct HksParam *keySizeParam = NULL;
    ret = HksGetParam(keyParamSet, HKS_TAG_KEY_SIZE, &keySizeParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE,
        "check key size: get param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_KEY_SIZE)

    ret = HksCheckValue(keySizeParam->uint32Param, expectKeySize, expectCnt);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE,
        "check key size: key size value %" LOG_PUBLIC "u not expected", keySizeParam->uint32Param)
    *keySize = keySizeParam->uint32Param;
    return ret;
}
#else
static int32_t CheckAndGetKeySize(const struct HksBlob *key, const uint32_t *expectKeySize,
    uint32_t expectCnt, uint32_t *keySize)
{
    if (key->size < sizeof(struct HksStoreKeyInfo)) {
        HKS_LOG_E("check key size: invalid keyfile size: %" LOG_PUBLIC "u", key->size);
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    struct HksStoreKeyInfo *keyInfo = (struct HksStoreKeyInfo *)key->data;
    uint32_t keyLen = keyInfo->keyLen;
    int32_t ret = HksCheckValue(keyLen, expectKeySize, expectCnt);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE,
        "check key size: keySize value %" LOG_PUBLIC "u not expected", keyLen)
    *keySize = keyLen;
    return ret;
}
#endif

#ifdef HKS_SUPPORT_RSA_C
#ifdef HKS_SUPPORT_RSA_C_FLEX_KEYSIZE
static int32_t CheckRsaKeySize(uint32_t keyLen)
{
    if ((keyLen >= HKS_RSA_KEY_SIZE_1024) &&
        (keyLen <= HKS_RSA_KEY_SIZE_2048) &&
        ((keyLen % HKS_RSA_KEY_BLOCK_SIZE) == 0)) {
        return HKS_SUCCESS;
    } else {
        return HKS_ERROR_INVALID_KEY_FILE;
    }
}

static int32_t CheckAndGetRsaKeySize(const struct HksBlob *key, uint32_t *keySize)
{
    if (key->size < sizeof(struct HksParamSet)) {
        HKS_LOG_E("check key size: invalid keyfile size: %" LOG_PUBLIC "u", key->size);
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    struct HksParamSet *keyParamSet = (struct HksParamSet *)key->data;
    int32_t ret = HksCheckParamSetValidity(keyParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE, "check key size: paramset invalid failed")

    struct HksParam *keySizeParam = NULL;
    ret = HksGetParam(keyParamSet, HKS_TAG_KEY_SIZE, &keySizeParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE,
        "check key size: get param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_KEY_SIZE)
    ret = CheckRsaKeySize(keySizeParam->uint32Param);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE,
        "check key size: key size value %" LOG_PUBLIC "u not expected", keySizeParam->uint32Param)
    *keySize = keySizeParam->uint32Param;

    return ret;
}
#endif
#endif

static int32_t CheckPurposeUnique(uint32_t inputPurpose)
{
    /* key usage uniqueness */
    uint32_t purposeCipher = inputPurpose & (HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT);
    uint32_t purposeSign = inputPurpose & (HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY);
    uint32_t purposeDerive = inputPurpose & HKS_KEY_PURPOSE_DERIVE;
    uint32_t purposeWrap = inputPurpose & (HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP);
    uint32_t purposeMac = inputPurpose & HKS_KEY_PURPOSE_MAC;
    uint32_t purposeAgree = inputPurpose & HKS_KEY_PURPOSE_AGREE;

    uint32_t purposeCount = (purposeCipher != 0) ? 1 : 0;
    purposeCount += (purposeSign != 0) ? 1 : 0;
    purposeCount += (purposeDerive != 0) ? 1 : 0;
    purposeCount += (purposeWrap != 0) ? 1 : 0;
    purposeCount += (purposeMac != 0) ? 1 : 0;
    purposeCount += (purposeAgree != 0) ? 1 : 0;

    return (purposeCount == 1) ? HKS_SUCCESS : HKS_ERROR_INVALID_PURPOSE;
}

static int32_t GetInvalidPurpose(uint32_t alg, uint32_t *inputPurpose, uint32_t keyFlag)
{
    int32_t result = HKS_ERROR_INVALID_ALGORITHM;
    if (sizeof(g_invalidPurpose) == 0) {
        return result;
    }
    uint32_t count = sizeof(g_invalidPurpose) / sizeof(g_invalidPurpose[0]);
    for (uint32_t i = 0; i < count; i++) {
        if (alg == g_invalidPurpose[i][0]) {
            result = HKS_SUCCESS;
            *inputPurpose = g_invalidPurpose[i][1];
            break;
        }
    }
    if ((keyFlag != HKS_KEY_FLAG_IMPORT_KEY) || (sizeof(g_invalidImportKeyPurpose) == 0)) {
        return result;
    }
    // add invalid purpose for import key additionally
    count = sizeof(g_invalidImportKeyPurpose) / sizeof(g_invalidImportKeyPurpose[0]);
    for (uint32_t i = 0; i < count; i++) {
        if (alg == g_invalidImportKeyPurpose[i][0]) {
            *inputPurpose |= g_invalidImportKeyPurpose[i][1];
            break;
        }
    }
    return result;
}

static int32_t CheckPurposeValid(uint32_t alg, uint32_t inputPurpose, uint32_t keyFlag)
{
    uint32_t invalidPurpose = 0;

    int32_t result = GetInvalidPurpose(alg, &invalidPurpose, keyFlag);
    HKS_IF_NOT_SUCC_RETURN(result, result)

    if ((inputPurpose & invalidPurpose) != 0) {
        return HKS_ERROR_INVALID_PURPOSE;
    }

    return HKS_SUCCESS;
}
#endif /* _CUT_AUTHENTICATE_ */

// If tag is optional param, when tag is empty, it is supported.
static int32_t GetOptionalParams(const struct HksParamSet *paramSet, uint32_t tag, bool needCheck, uint32_t* value,
    bool* isAbsent)
{
    if (needCheck) {
        struct HksParam *param;
        int32_t ret = HksGetParam(paramSet, tag, &param);
        if (ret == HKS_SUCCESS) {
            *value = param->uint32Param;
            return ret;
        }
        if (ret == HKS_ERROR_PARAM_NOT_EXIST) {
            HKS_LOG_I("tag is empty, but it is supported!");
            *isAbsent = true;
            return HKS_SUCCESS;
        }
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t GetInputParams(const struct HksParamSet *paramSet, struct ParamsValues *inputParams)
{
    int32_t ret = HKS_SUCCESS;
    struct HksParam *checkParam = NULL;
    if (inputParams->keyLen.needCheck) {
        ret = HksGetParam(paramSet, HKS_TAG_KEY_SIZE, &checkParam);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_KEY_SIZE_FAIL,
            "get Param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_KEY_SIZE);
        inputParams->keyLen.value = checkParam->uint32Param;
    }

    if (inputParams->purpose.needCheck) {
        ret = HksGetParam(paramSet, HKS_TAG_PURPOSE, &checkParam);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_PURPOSE_FAIL,
            "get Param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_PURPOSE);
        inputParams->purpose.value = checkParam->uint32Param;
    }

    ret = GetOptionalParams(paramSet, HKS_TAG_PADDING, inputParams->padding.needCheck, &inputParams->padding.value,
        &inputParams->padding.isAbsent);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_PADDING_FAIL,
        "get Param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_PADDING);
    ret = GetOptionalParams(paramSet, HKS_TAG_DIGEST, inputParams->digest.needCheck, &inputParams->digest.value,
        &inputParams->digest.isAbsent);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_DIGEST_FAIL,
        "get Param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_DIGEST);
    ret = GetOptionalParams(paramSet, HKS_TAG_BLOCK_MODE, inputParams->mode.needCheck, &inputParams->mode.value,
        &inputParams->mode.isAbsent);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_MODE_FAIL,
        "get Param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_BLOCK_MODE);
    return ret;
}

static int32_t InitInputParams(enum CheckKeyType checkType, struct ParamsValues *inputParams,
    const struct ParamsValuesChecker *checkSet, uint32_t checkSetSize)
{
    for (uint32_t i = 0; i < checkSetSize; ++i) {
        if (checkType == checkSet[i].checkType) {
            (void)memcpy_s(inputParams, sizeof(*inputParams), &checkSet[i].paramValues,
                sizeof(checkSet[i].paramValues));
            return HKS_SUCCESS;
        }
    }
    return HKS_ERROR_NOT_SUPPORTED;
}


static int32_t InitInputParamsByAlgOne(uint32_t alg, enum CheckKeyType checkType, struct ParamsValues *inputParams)
{
    switch (alg) {
#ifdef HKS_SUPPORT_HMAC_C
        case HKS_ALG_HMAC:
            return InitInputParams(checkType, inputParams, g_hmacParamSet, HKS_ARRAY_SIZE(g_hmacParamSet));
#endif
#ifdef HKS_SUPPORT_CMAC_C
        case HKS_ALG_CMAC:
            return InitInputParams(checkType, inputParams, g_cmacParamSet, HKS_ARRAY_SIZE(g_cmacParamSet));
#endif
#ifdef HKS_SUPPORT_DSA_C
        case HKS_ALG_DSA:
            return InitInputParams(checkType, inputParams, g_dsaParamSet, HKS_ARRAY_SIZE(g_dsaParamSet));
#endif
#ifdef HKS_SUPPORT_DH_C
        case HKS_ALG_DH:
            return InitInputParams(checkType, inputParams, g_dhParamSet, HKS_ARRAY_SIZE(g_dhParamSet));
#endif
#ifdef HKS_SUPPORT_ECDH_C
        case HKS_ALG_ECDH:
            return InitInputParams(checkType, inputParams, g_ecdhParamSet, HKS_ARRAY_SIZE(g_ecdhParamSet));
#endif
        default:
            return HKS_ERROR_INVALID_ALGORITHM;
    }
}

static int32_t InitInputParamsByAlg(uint32_t alg, enum CheckKeyType checkType, struct ParamsValues *inputParams)
{
    switch (alg) {
#ifdef HKS_SUPPORT_RSA_C
        case HKS_ALG_RSA:
            return InitInputParams(checkType, inputParams, g_rsaParamSet, HKS_ARRAY_SIZE(g_rsaParamSet));
#endif
#ifdef HKS_SUPPORT_AES_C
        case HKS_ALG_AES:
            return InitInputParams(checkType, inputParams, g_aesParamSet, HKS_ARRAY_SIZE(g_aesParamSet));
#endif
#ifdef HKS_SUPPORT_DES_C
        case HKS_ALG_DES:
            return InitInputParams(checkType, inputParams, g_desParamSet, HKS_ARRAY_SIZE(g_desParamSet));
#endif
#ifdef HKS_SUPPORT_3DES_C
        case HKS_ALG_3DES:
            return InitInputParams(checkType, inputParams, g_3desParamSet, HKS_ARRAY_SIZE(g_3desParamSet));
#endif
#ifdef HKS_SUPPORT_ECC_C
        case HKS_ALG_ECC:
            return InitInputParams(checkType, inputParams, g_eccParamSet, HKS_ARRAY_SIZE(g_eccParamSet));
#endif
#ifdef HKS_SUPPORT_SM2_C
        case HKS_ALG_SM2:
            return InitInputParams(checkType, inputParams, g_sm2ParamSet, HKS_ARRAY_SIZE(g_sm2ParamSet));
#endif
#ifdef HKS_SUPPORT_SM3_C
        case HKS_ALG_SM3:
            return InitInputParams(checkType, inputParams, g_sm3ParamSet, HKS_ARRAY_SIZE(g_sm3ParamSet));
#endif
#ifdef HKS_SUPPORT_SM4_C
        case HKS_ALG_SM4:
            return InitInputParams(checkType, inputParams, g_sm4ParamSet, HKS_ARRAY_SIZE(g_sm4ParamSet));
#endif
#if defined(HKS_SUPPORT_X25519_C) || defined(HKS_SUPPORT_ED25519_C)
        case HKS_ALG_X25519:
        case HKS_ALG_ED25519:
            return InitInputParams(checkType, inputParams, g_curve25519ParamSet, HKS_ARRAY_SIZE(g_curve25519ParamSet));
#endif
        default:
            return InitInputParamsByAlgOne(alg, checkType, inputParams);
    }
}

static int32_t InitExpectParams(enum CheckKeyType checkType, struct ExpectParamsValues *expectValues,
    const struct ExpectParamsValuesChecker *checkSet, uint32_t checkSetSize)
{
    for (uint32_t i = 0; i < checkSetSize; ++i) {
        if (checkType == checkSet[i].checkType) {
            (void)memcpy_s(expectValues, sizeof(*expectValues), &checkSet[i].paramValues,
                sizeof(checkSet[i].paramValues));
            return HKS_SUCCESS;
        }
    }
    return HKS_ERROR_NOT_SUPPORTED;
}

static int32_t GetExpectParamsByAlg(uint32_t alg, enum CheckKeyType checkType, struct ExpectParamsValues *expectValues)
{
    switch (alg) {
#ifdef HKS_SUPPORT_HMAC_C
        case HKS_ALG_HMAC:
            return InitExpectParams(checkType, expectValues, g_expectHmacParams, HKS_ARRAY_SIZE(g_expectHmacParams));
#endif
#ifdef HKS_SUPPORT_CMAC_C
        case HKS_ALG_CMAC:
            return InitExpectParams(checkType, expectValues, g_expectCmacParams, HKS_ARRAY_SIZE(g_expectCmacParams));
#endif
#ifdef HKS_SUPPORT_DSA_C
        case HKS_ALG_DSA:
            return InitExpectParams(checkType, expectValues, g_expectDsaParams, HKS_ARRAY_SIZE(g_expectDsaParams));
#endif
#ifdef HKS_SUPPORT_DH_C
        case HKS_ALG_DH:
            return InitExpectParams(checkType, expectValues, g_expectDhParams, HKS_ARRAY_SIZE(g_expectDhParams));
#endif
#ifdef HKS_SUPPORT_ECDH_C
        case HKS_ALG_ECDH:
            return InitExpectParams(checkType, expectValues, g_expectEcdhParams, HKS_ARRAY_SIZE(g_expectEcdhParams));
#endif
        default:
            return HKS_ERROR_INVALID_ALGORITHM;
    }
}

static int32_t GetExpectParams(uint32_t alg, enum CheckKeyType checkType, struct ExpectParamsValues *expectValues)
{
    switch (alg) {
#ifdef HKS_SUPPORT_RSA_C
        case HKS_ALG_RSA:
            return InitExpectParams(checkType, expectValues, g_expectRsaParams, HKS_ARRAY_SIZE(g_expectRsaParams));
#endif
#ifdef HKS_SUPPORT_AES_C
        case HKS_ALG_AES:
            return InitExpectParams(checkType, expectValues, g_expectAesParams, HKS_ARRAY_SIZE(g_expectAesParams));
#endif
#ifdef HKS_SUPPORT_DES_C
        case HKS_ALG_DES:
            return InitExpectParams(checkType, expectValues, g_expectDesParams, HKS_ARRAY_SIZE(g_expectDesParams));
#endif
#ifdef HKS_SUPPORT_3DES_C
        case HKS_ALG_3DES:
            return InitExpectParams(checkType, expectValues, g_expect3DesParams, HKS_ARRAY_SIZE(g_expect3DesParams));
#endif
#ifdef HKS_SUPPORT_ECC_C
        case HKS_ALG_ECC:
            return InitExpectParams(checkType, expectValues, g_expectEccParams, HKS_ARRAY_SIZE(g_expectEccParams));
#endif
#ifdef HKS_SUPPORT_SM2_C
        case HKS_ALG_SM2:
            return InitExpectParams(checkType, expectValues, g_expectSm2Params, HKS_ARRAY_SIZE(g_expectSm2Params));
#endif
#ifdef HKS_SUPPORT_SM3_C
        case HKS_ALG_SM3:
            return InitExpectParams(checkType, expectValues, g_expectSm3Params, HKS_ARRAY_SIZE(g_expectSm3Params));
#endif
#ifdef HKS_SUPPORT_SM4_C
        case HKS_ALG_SM4:
            return InitExpectParams(checkType, expectValues, g_expectSm4Params, HKS_ARRAY_SIZE(g_expectSm4Params));
#endif
#if defined(HKS_SUPPORT_X25519_C) || defined(HKS_SUPPORT_ED25519_C)
        case HKS_ALG_X25519:
        case HKS_ALG_ED25519:
            return InitExpectParams(checkType, expectValues, g_expectCurve25519Params,
                HKS_ARRAY_SIZE(g_expectCurve25519Params));
#endif
        default:
            return GetExpectParamsByAlg(alg, checkType, expectValues);
    }
}

#ifdef HKS_SUPPORT_ECC_C
static int32_t CheckEccSignature(uint32_t cmdId, uint32_t keySize, const struct HksBlob *signature)
{
    /*
     * ecc sign format: 0x30 + len1 + 0x02 + len2 + 0x00 (optional) + r + 0x02 + len3 + 0x00(optional) + s
     * sign: signSize no less than 2*keySize/8 + 8;
     * verify: signSize no greater than 2*keySize/8 + 8
     */
    uint32_t eccSignRSize = keySize / HKS_BITS_PER_BYTE + keySize % HKS_BITS_PER_BYTE;
    uint32_t eccSignSSize = eccSignRSize;
    switch (cmdId) {
        case HKS_CMD_ID_SIGN:
            if (signature->size < (eccSignRSize + eccSignSSize + HKS_ECC_SIGN_MAX_TL_SIZE)) {
                HKS_LOG_E("eccsign: signature size too small, keySize %" LOG_PUBLIC "u, signatureSize %" LOG_PUBLIC "u",
                    keySize, signature->size);
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            break;
        case HKS_CMD_ID_VERIFY:
            if (signature->size > (eccSignRSize + eccSignSSize + HKS_ECC_SIGN_MAX_TL_SIZE)) {
                HKS_LOG_E("eccverfiy: invalid signature size, keySize %" LOG_PUBLIC "u, signatureSize %" LOG_PUBLIC "u",
                    keySize, signature->size);
                return HKS_ERROR_INVALID_SIGNATURE_SIZE;
            }
            break;
        default:
            return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_ED25519_C
static int32_t CheckEd25519Signature(uint32_t cmdId, const struct HksBlob *signature)
{
    switch (cmdId) {
        case HKS_CMD_ID_SIGN:
            if (signature->size < HKS_SIGNATURE_MIN_SIZE) {
                HKS_LOG_E("ed25519 sign: signature size too small, signatureSize %" LOG_PUBLIC "u", signature->size);
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            break;
        case HKS_CMD_ID_VERIFY:
            if (signature->size < HKS_SIGNATURE_MIN_SIZE) {
                HKS_LOG_E("ed25519 verfiy: invalid signature size, signatureSize %" LOG_PUBLIC "u", signature->size);
                return HKS_ERROR_INVALID_SIGNATURE_SIZE;
            }
            break;
        default:
            return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_RSA_C
static int32_t CheckRsaGenKeyPadding(const struct ParamsValues *inputParams)
{
    if (inputParams->padding.isAbsent) {
        return HKS_SUCCESS;
    }
    if ((inputParams->purpose.value & (HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT)) != 0) {
        return HksCheckValue(inputParams->padding.value, g_rsaCipherPadding, HKS_ARRAY_SIZE(g_rsaCipherPadding));
    } else if ((inputParams->purpose.value & (HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY)) != 0) {
        return HksCheckValue(inputParams->padding.value, g_rsaSignPadding, HKS_ARRAY_SIZE(g_rsaSignPadding));
    }
    return HKS_SUCCESS;
}

#ifdef HKS_SUPPORT_RSA_SIGN_VERIFY
static int32_t CheckRsaSignature(uint32_t cmdId, uint32_t keySize, const struct HksBlob *signature)
{
    /*
     * k: the length of the RSA modulus n
     * sign: signSize no less than k; verify: signSize is same as k, thus no greater than keySize / 8
     */
    switch (cmdId) {
        case HKS_CMD_ID_SIGN:
            if (signature->size < keySize / HKS_BITS_PER_BYTE) {
                HKS_LOG_E("rsasign: signature size too small, keySize %" LOG_PUBLIC "u, signatureSize %" LOG_PUBLIC "u",
                    keySize, signature->size);
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            break;
        case HKS_CMD_ID_VERIFY:
            if (signature->size > keySize / HKS_BITS_PER_BYTE) {
                HKS_LOG_E("rsaverfiy: invalid signature size, keySize %" LOG_PUBLIC "u, signatureSize %" LOG_PUBLIC "u",
                    keySize, signature->size);
                return HKS_ERROR_INVALID_SIGNATURE_SIZE;
            }
            break;
        default:
            return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_RSA_CRYPT
static int32_t CheckRsaNoPadCipherData(uint32_t keySize, const struct HksBlob *inData,
    const struct HksBlob *outData)
{
    /* encrypt/decrypt: inSize no greater than keySize, outSize no less than keySize */
    if (inData->size > keySize) {
        HKS_LOG_E("invalid inData size: %" LOG_PUBLIC "u, keySize: %" LOG_PUBLIC "u", inData->size, keySize);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (outData->size < keySize) {
        HKS_LOG_E("outData buffer too small size: %" LOG_PUBLIC "u, keySize: %" LOG_PUBLIC "u",
            outData->size, keySize);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    return HKS_SUCCESS;
}

static int32_t CheckRsaOaepCipherData(uint32_t cmdId, uint32_t keySize, uint32_t digest,
    const struct HksBlob *inData, const struct HksBlob *outData)
{
    uint32_t digestLen;
    if (digest == HKS_DIGEST_NONE) {
        digest = HKS_DIGEST_SHA1;
    }
    int32_t ret = HksGetDigestLen(digest, &digestLen);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "GetDigestLen failed, ret = %" LOG_PUBLIC "x", ret)

    /*
     * encrypt: inSize no greater than keySize - 2*digestLen - 2, outSize no less than keySize (in: plain; out: cipher)
     * decrypt: inSize no greater than keySize, outSize no less than keySize - 2*digestLen - 2 (in: cipher; out: plain)
     */
    if (keySize <= (HKS_RSA_OAEP_DIGEST_NUM * digestLen + HKS_RSA_OAEP_DIGEST_NUM)) {
        return HKS_ERROR_INVALID_KEY_FILE;
    }
    uint32_t size = keySize - HKS_RSA_OAEP_DIGEST_NUM * digestLen - HKS_RSA_OAEP_DIGEST_NUM;
    if (cmdId == HKS_CMD_ID_ENCRYPT) {
        if (inData->size > size) {
            HKS_LOG_E("encrypt, invalid insize: %" LOG_PUBLIC "u, keySize: %" LOG_PUBLIC "u, "
                "digestLen: %" LOG_PUBLIC "u", inData->size, keySize, digestLen);
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        if (outData->size < keySize) {
            HKS_LOG_E("encrypt, outData buffer too small size: %" LOG_PUBLIC "u, keySize: %" LOG_PUBLIC "u",
                outData->size, keySize);
            return HKS_ERROR_BUFFER_TOO_SMALL;
        }
    } else if (cmdId == HKS_CMD_ID_DECRYPT) {
        if (inData->size > keySize) {
            HKS_LOG_E("decrypt, invalid inData size: %" LOG_PUBLIC "u, keySize: %" LOG_PUBLIC "u",
                inData->size, keySize);
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        if (outData->size < size) {
            HKS_LOG_E("decrypt, outData buffer too small size: %" LOG_PUBLIC "u, keySize: %" LOG_PUBLIC "u",
                outData->size, keySize);
            return HKS_ERROR_BUFFER_TOO_SMALL;
        }
    }

    return HKS_SUCCESS;
}

static int32_t CheckRsaCipherData(uint32_t cmdId, const struct ParamsValues *inputParams,
    const struct HksBlob *inData, const struct HksBlob *outData)
{
    uint32_t padding = inputParams->padding.value;
    uint32_t keySize = inputParams->keyLen.value / HKS_BITS_PER_BYTE;
    int32_t ret = HKS_SUCCESS;

    if (padding == HKS_PADDING_NONE) {
        ret = CheckRsaNoPadCipherData(keySize, inData, outData);
    } else if (padding == HKS_PADDING_OAEP) {
        ret = CheckRsaOaepCipherData(cmdId, keySize, inputParams->digest.value, inData, outData);
    }

    HKS_IF_NOT_SUCC_LOGE(ret, "Check Rsa CipherData failed, cmdId: %" LOG_PUBLIC "u, padding: %" LOG_PUBLIC "u, "
        "keyLen: %" LOG_PUBLIC "u, inData size: %" LOG_PUBLIC "u, outData size: %" LOG_PUBLIC "u",
        cmdId, padding, keySize, inData->size, outData->size)

    return ret;
}
#endif
#endif

#ifdef HKS_SUPPORT_AES_C
static int32_t CheckAesAeCipherData(uint32_t cmdId, const struct HksBlob *inData, const struct HksBlob *outData);
#endif

#if defined(HKS_SUPPORT_AES_C) || defined(HKS_SUPPORT_DES_C) || defined(HKS_SUPPORT_3DES_C) || \
    defined(HKS_SUPPORT_SM4_C)
static int32_t CheckBlockCbcCipherData(uint32_t mode, uint32_t cmdId, uint32_t padding,
    const struct HksBlob *inData, const struct HksBlob *outData)
{
    /*
     * encrypt: inSize greater than 0(has been checked), no-padding: inSize need to be integer multiple of 16
     *          outSize no less than inSize + (16 - inSize % 16) (in: plain; out: cipher)
     * decrypt: inSize greater than 0(has been checked) && inSize is integer multiple of 16
     *          outSize no less than inSize (in: cipher; out: plain)
     */
    switch (cmdId) {
        case HKS_CMD_ID_ENCRYPT: {
            uint32_t paddingSize = 0;
            if (padding == HKS_PADDING_NONE) {
                if ((mode == HKS_MODE_CBC || mode == HKS_MODE_ECB) &&
                    inData->size % HKS_BLOCK_CIPHER_CBC_BLOCK_SIZE != 0) {
                    HKS_LOG_E("encrypt, mode id: %" LOG_PUBLIC "u, no-padding, invalid inSize: %" LOG_PUBLIC "u",
                        mode, inData->size);
                    return HKS_ERROR_INVALID_ARGUMENT;
                }
            } else {
                paddingSize = HKS_BLOCK_CIPHER_CBC_BLOCK_SIZE - inData->size % HKS_BLOCK_CIPHER_CBC_BLOCK_SIZE;
                if (inData->size > (UINT32_MAX - paddingSize)) {
                    HKS_LOG_E("encrypt, invalid inData size: %" LOG_PUBLIC "u", inData->size);
                    return HKS_ERROR_INVALID_ARGUMENT;
                }
            }
            if (outData->size < (inData->size + paddingSize)) {
                HKS_LOG_E("encrypt, outData buffer too small size: %" LOG_PUBLIC "u, need: %" LOG_PUBLIC "u",
                    outData->size, inData->size + paddingSize);
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            break;
        }
        case HKS_CMD_ID_DECRYPT:
            if ((mode == HKS_MODE_CBC || mode == HKS_MODE_ECB) && inData->size % HKS_BLOCK_CIPHER_CBC_BLOCK_SIZE != 0) {
                HKS_LOG_E("decrypt, mode id: %" LOG_PUBLIC "u, invalid inData size: %" LOG_PUBLIC "u",
                    mode, inData->size);
                return HKS_ERROR_INVALID_ARGUMENT;
            }
            if (outData->size < inData->size) {
                HKS_LOG_E("decrypt, outData buffer too small size: %" LOG_PUBLIC "u, inDataSize: %" LOG_PUBLIC "u",
                    outData->size, inData->size);
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            break;
        default:
            return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

static int32_t CheckBlockCipherData(uint32_t cmdId, const struct ParamsValues *inputParams,
    const struct HksBlob *inData, const struct HksBlob *outData, uint32_t alg)
{
    uint32_t mode = inputParams->mode.value;

#if defined(HKS_SUPPORT_AES_C)
    if (alg == HKS_ALG_AES) {
        if (mode == HKS_MODE_CBC || mode == HKS_MODE_CTR || mode == HKS_MODE_ECB) {
            uint32_t padding = inputParams->padding.value;
            return CheckBlockCbcCipherData(mode, cmdId, padding, inData, outData);
        } else if (mode == HKS_MODE_GCM || mode == HKS_MODE_CCM) {
            return CheckAesAeCipherData(cmdId, inData, outData);
        }
    }
#endif

#if defined(HKS_SUPPORT_DES_C)
    if (alg == HKS_ALG_DES) {
        if (mode == HKS_MODE_CBC || mode == HKS_MODE_ECB) {
            uint32_t padding = inputParams->padding.value;
            return CheckBlockCbcCipherData(mode, cmdId, padding, inData, outData);
        }
    }
#endif

#if defined(HKS_SUPPORT_3DES_C)
    if (alg == HKS_ALG_3DES) {
        if (mode == HKS_MODE_CBC || mode == HKS_MODE_ECB) {
            uint32_t padding = inputParams->padding.value;
            return CheckBlockCbcCipherData(mode, cmdId, padding, inData, outData);
        }
    }
#endif

#if defined(HKS_SUPPORT_SM4_C)
    if (alg == HKS_ALG_SM4) {
        for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_sm4Mode); i++) {
            if (mode == g_sm4Mode[i]) {
                uint32_t padding = inputParams->padding.value;
                return CheckBlockCbcCipherData(mode, cmdId, padding, inData, outData);
            }
        }
    }
#endif

    return HKS_ERROR_INVALID_MODE;
}

static int32_t CheckBlockCipherIvMaterial(const struct HksParamSet *paramSet)
{
    struct HksParam *ivParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IV, &ivParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_IV_FAIL, "cipher get iv param failed!")

    if ((ivParam->blob.size != HKS_BLOCK_CIPHER_CBC_IV_LEN) || (ivParam->blob.data == NULL)) {
        HKS_LOG_E("cbc iv param invalid");
        return HKS_ERROR_INVALID_IV;
    }

    return ret;
}
#endif // defined(HKS_SUPPORT_AES_C) || defined(HKS_SUPPORT_DES_C) || defined(HKS_SUPPORT_3DES_C)
       // || defined(HKS_SUPPORT_SM4_C)

#ifdef HKS_SUPPORT_AES_C
static int32_t CheckAesPadding(const struct ParamsValues *inputParams)
{
    if ((inputParams->mode.isAbsent) || (inputParams->padding.isAbsent)) {
        return HKS_SUCCESS;
    }
    uint32_t mode = inputParams->mode.value;
    uint32_t padding = inputParams->padding.value;
    if (mode == HKS_MODE_CBC) {
        return HksCheckValue(padding, g_aesCbcPadding, HKS_ARRAY_SIZE(g_aesCbcPadding));
    }

    if (mode == HKS_MODE_CTR) {
        return HksCheckValue(padding, g_aesCtrPadding, HKS_ARRAY_SIZE(g_aesCtrPadding));
    }

    if (mode == HKS_MODE_ECB) {
        return HksCheckValue(padding, g_aesEcbPadding, HKS_ARRAY_SIZE(g_aesEcbPadding));
    }

    if ((mode == HKS_MODE_GCM) || (mode == HKS_MODE_CCM)) {
        return HksCheckValue(padding, g_aesAeadPadding, HKS_ARRAY_SIZE(g_aesAeadPadding));
    }

    return HKS_SUCCESS;
}

static int32_t CheckAesAeCipherData(uint32_t cmdId, const struct HksBlob *inData, const struct HksBlob *outData)
{
    /*
     * encrypt: inSize greater than 0(has been checked),
     *          outSize no less than inSize + 16(tagLen) (in: plain; out: cipher)
     * decrypt: inSize greater than 16(tagLen), outSize no less than inSize - 16(tagLen)
     * decryptFinal: inSize greater than 0(has been checked), outSize no less than inSize (in: cipher; out: plain)
     */
    switch (cmdId) {
        case HKS_CMD_ID_ENCRYPT:
            if (inData->size > (UINT32_MAX - HKS_AE_TAG_LEN)) {
                HKS_LOG_E("encrypt, invalid inSize: %" LOG_PUBLIC "u", inData->size);
                return HKS_ERROR_INVALID_ARGUMENT;
            }
            if (outData->size < (inData->size + HKS_AE_TAG_LEN)) {
                HKS_LOG_E("encrypt, out buffer too small size: %" LOG_PUBLIC "u, inSize: %" LOG_PUBLIC "u",
                    outData->size, inData->size);
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            break;
        case HKS_CMD_ID_DECRYPT:
            if ((inData->size < HKS_AE_TAG_LEN) || (outData->size < inData->size - HKS_AE_TAG_LEN)) {
                HKS_LOG_E("decryptfinal, out buffer too small size: %" LOG_PUBLIC "u, inSize: %" LOG_PUBLIC "u",
                    outData->size, inData->size);
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            break;
        default:
            return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

static int32_t CheckCipherAeAadMaterial(uint32_t mode, const struct HksParamSet *paramSet)
{
    struct HksParam *aadParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ASSOCIATED_DATA, &aadParam);
    if (mode == HKS_MODE_GCM && ret == HKS_ERROR_PARAM_NOT_EXIST) {
        HKS_LOG_W("gcm no input aad");
        return HKS_SUCCESS;
    } else if (ret != HKS_SUCCESS) {
        HKS_LOG_E("cipher get aad param failed!");
        return HKS_ERROR_CHECK_GET_AAD_FAIL;
    }
    HKS_IF_NOT_SUCC_RETURN(CheckBlob(&aadParam->blob), HKS_ERROR_INVALID_AAD)

    /* gcmMode: aadSize greater than 0 (has been checked); ccmMode: aadSize no less than 4 */
    if (mode == HKS_MODE_CCM) {
        if (aadParam->blob.size < HKS_AES_CCM_AAD_LEN_MIN) {
            HKS_LOG_E("ccm invalid aad size, aad size = %" LOG_PUBLIC "u", aadParam->blob.size);
            return HKS_ERROR_INVALID_AAD;
        }
    }

    return HKS_SUCCESS;
}

static int32_t CheckCipherAeNonceMaterial(uint32_t mode, const struct HksParamSet *paramSet)
{
    struct HksParam *nonceParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_NONCE, &nonceParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_NONCE_FAIL, "cipher get nonce param failed!")
    HKS_IF_NOT_SUCC_RETURN(CheckBlob(&nonceParam->blob), HKS_ERROR_INVALID_NONCE)

    /* gcmMode: nonceSize no less than 12; ccmMode: nonceSize no less than 7, and no greater than 13 */
    if (mode == HKS_MODE_GCM) {
        if (nonceParam->blob.size < HKS_AES_GCM_NONCE_LEN_MIN) {
            HKS_LOG_E("gcm invalid nonce size, nonce size = %" LOG_PUBLIC "u", nonceParam->blob.size);
            return HKS_ERROR_INVALID_NONCE;
        }
    } else if (mode == HKS_MODE_CCM) {
        if ((nonceParam->blob.size < HKS_AES_CCM_NONCE_LEN_MIN) ||
            (nonceParam->blob.size > HKS_AES_CCM_NONCE_LEN_MAX)) {
            HKS_LOG_E("ccm invalid nonce size, nonce size = %" LOG_PUBLIC "u", nonceParam->blob.size);
            return HKS_ERROR_INVALID_NONCE;
        }
    }

    return HKS_SUCCESS;
}

static int32_t CheckCipherAeMaterial(uint32_t mode, const struct HksParamSet *paramSet)
{
    int32_t ret = CheckCipherAeAadMaterial(mode, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check ae cipher aad failed!")

    ret = CheckCipherAeNonceMaterial(mode, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check ae cipher nonce failed!")

    return ret;
}
#endif

#ifdef HKS_SUPPORT_DES_C
static int32_t CheckDesPadding(const struct ParamsValues *inputParams)
{
    if ((inputParams->mode.isAbsent) || (inputParams->padding.isAbsent)) {
        return HKS_SUCCESS;
    }
    uint32_t mode = inputParams->mode.value;
    uint32_t padding = inputParams->padding.value;
    if (mode == HKS_MODE_CBC) {
        return HksCheckValue(padding, g_desCbcPadding, HKS_ARRAY_SIZE(g_desCbcPadding));
    }

    if (mode == HKS_MODE_ECB) {
        return HksCheckValue(padding, g_desEcbPadding, HKS_ARRAY_SIZE(g_desEcbPadding));
    }

    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_3DES_C
static int32_t Check3DesPadding(const struct ParamsValues *inputParams)
{
    if ((inputParams->mode.isAbsent) || (inputParams->padding.isAbsent)) {
        return HKS_SUCCESS;
    }
    uint32_t mode = inputParams->mode.value;
    uint32_t padding = inputParams->padding.value;
    if (mode == HKS_MODE_CBC) {
        return HksCheckValue(padding, g_3desCbcPadding, HKS_ARRAY_SIZE(g_3desCbcPadding));
    }

    if (mode == HKS_MODE_ECB) {
        return HksCheckValue(padding, g_3desEcbPadding, HKS_ARRAY_SIZE(g_3desEcbPadding));
    }

    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_SM4_C
static int32_t CheckSm4Padding(const struct ParamsValues *inputParams)
{
    if ((inputParams->mode.isAbsent) || (inputParams->padding.isAbsent)) {
        return HKS_SUCCESS;
    }
    uint32_t mode = inputParams->mode.value;
    uint32_t padding = inputParams->padding.value;
    if (mode == HKS_MODE_CBC) {
        return HksCheckValue(padding, g_sm4CbcPadding, HKS_ARRAY_SIZE(g_sm4CbcPadding));
    }

    if (mode == HKS_MODE_CTR) {
        return HksCheckValue(padding, g_sm4CtrPadding, HKS_ARRAY_SIZE(g_sm4CtrPadding));
    }

    if (mode == HKS_MODE_ECB) {
        return HksCheckValue(padding, g_sm4EcbPadding, HKS_ARRAY_SIZE(g_sm4EcbPadding));
    }

    if (mode == HKS_MODE_CFB) {
        return HksCheckValue(padding, g_sm4CfbPadding, HKS_ARRAY_SIZE(g_sm4CfbPadding));
    }

    if (mode == HKS_MODE_OFB) {
        return HksCheckValue(padding, g_sm4OfbPadding, HKS_ARRAY_SIZE(g_sm4OfbPadding));
    }

    return HKS_ERROR_INVALID_ARGUMENT;
}
#endif

int32_t HksCheckValue(uint32_t inputValue, const uint32_t *expectValues, uint32_t valuesCount)
{
    for (uint32_t i = 0; i < valuesCount; ++i) {
        if (inputValue == expectValues[i]) {
            return HKS_SUCCESS;
        }
    }
    return HKS_ERROR_INVALID_ARGUMENT;
}

#ifndef _CUT_AUTHENTICATE_
int32_t HksCheckGenKeyPurpose(uint32_t alg, uint32_t inputPurpose, uint32_t keyFlag)
{
    int32_t ret = CheckPurposeUnique(inputPurpose);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "gen key purpose not unique")

    return CheckPurposeValid(alg, inputPurpose, keyFlag);
}

#ifdef HKS_SUPPORT_DSA_C
static int32_t HksGetDsaKeySize(const struct HksBlob *key, uint32_t *keySize)
{
    if (key->size < sizeof(struct HksParamSet)) {
        HKS_LOG_E("check dsa key size: invalid keyfile size: %" LOG_PUBLIC "u", key->size);
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    struct HksParamSet *keyParamSet = (struct HksParamSet *)key->data;
    int32_t ret = HksCheckParamSetValidity(keyParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE, "check dsa key size: paramset invalid failed")

    struct HksParam *keySizeParam = NULL;
    ret = HksGetParam(keyParamSet, HKS_TAG_KEY_SIZE, &keySizeParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE,
        "check dsa key size: get param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_KEY_SIZE)
    *keySize = keySizeParam->uint32Param;
    return ret;
}
#endif

int32_t HksGetKeySize(uint32_t alg, const struct HksBlob *key, uint32_t *keySize)
{
    int32_t ret = HKS_ERROR_INVALID_ALGORITHM;
    switch (alg) {
#ifdef HKS_SUPPORT_RSA_C
        case HKS_ALG_RSA:
            ret = CheckAndGetKeySize(key, g_rsaKeySize, HKS_ARRAY_SIZE(g_rsaKeySize), keySize);
#ifdef HKS_SUPPORT_RSA_C_FLEX_KEYSIZE
            if (ret != HKS_SUCCESS) {
                ret = CheckAndGetRsaKeySize(key, keySize);
            }
#endif
            return ret;
#endif
#ifdef HKS_SUPPORT_DSA_C
        case HKS_ALG_DSA:
#ifndef _STORAGE_LITE_
            return HksGetDsaKeySize(key, keySize);
#else
            return HKS_ERROR_INVALID_ALGORITHM;
#endif
#endif
#ifdef HKS_SUPPORT_ECC_C
        case HKS_ALG_ECC:
            return CheckAndGetKeySize(key, g_eccKeySize, HKS_ARRAY_SIZE(g_eccKeySize), keySize);
#endif
#ifdef HKS_SUPPORT_ECDH_C
        case HKS_ALG_ECDH:
            return CheckAndGetKeySize(key, g_ecdhKeySize, HKS_ARRAY_SIZE(g_ecdhKeySize), keySize);
#endif
#if defined(HKS_SUPPORT_X25519_C) || defined(HKS_SUPPORT_ED25519_C)
        case HKS_ALG_X25519:
        case HKS_ALG_ED25519:
            return CheckAndGetKeySize(key, g_curve25519KeySize, HKS_ARRAY_SIZE(g_curve25519KeySize), keySize);
#endif
#ifdef HKS_SUPPORT_DH_C
        case HKS_ALG_DH:
            return CheckAndGetKeySize(key, g_dhKeySize, HKS_ARRAY_SIZE(g_dhKeySize), keySize);
#endif
#ifdef HKS_SUPPORT_SM4_C
        case HKS_ALG_SM4:
            return CheckAndGetKeySize(key, g_sm4KeySize, HKS_ARRAY_SIZE(g_sm4KeySize), keySize);
#endif
#ifdef HKS_SUPPORT_SM2_C
        case HKS_ALG_SM2:
            return CheckAndGetKeySize(key, g_sm2KeySize, HKS_ARRAY_SIZE(g_sm2KeySize), keySize);
#endif
        default:
            return ret;
    }
}
#endif /* _CUT_AUTHENTICATE_ */

int32_t HksGetInputParmasByAlg(uint32_t alg, enum CheckKeyType checkType, const struct HksParamSet *paramSet,
    struct ParamsValues *inputParams)
{
    int32_t ret = InitInputParamsByAlg(alg, checkType, inputParams);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "init input params failed!")

    ret = GetInputParams(paramSet, inputParams);
    HKS_IF_NOT_SUCC_LOGE(ret, "get input params failed!")

    return ret;
}
static int32_t CheckOptionalParams(bool needCheck, bool isAbsent, uint32_t inputValue, const uint32_t* expectValue,
    uint32_t expectCnt)
{
    if (needCheck) {
        if (!isAbsent) {
            if (HksCheckValue(inputValue, expectValue, expectCnt) != HKS_SUCCESS) {
                HKS_LOG_E("CheckOptionalParams invalid argument, %" LOG_PUBLIC "u", inputValue);
                return HKS_ERROR_INVALID_ARGUMENT;
            }
        }
    }
    return HKS_SUCCESS;
}

static int32_t InitCheckOptionalParams(bool needCheck, bool isAbsent, struct HksParam *param,
    const uint32_t* expectValue, uint32_t expectCnt)
{
    if (needCheck) {
        if (!isAbsent) {
            if (HksCheckValue(param->uint32Param, expectValue, expectCnt) != HKS_SUCCESS) {
                return HKS_ERROR_INVALID_ARGUMENT;
            }
        } else {
            HKS_LOG_E("This param is absent, but it is necessary.");
            return HKS_ERROR_NOT_EXIST;
        }
    }
    return HKS_SUCCESS;
}

int32_t HksCheckOptionalParam(uint32_t tag, uint32_t alg, uint32_t purpose, bool isAbsent, struct HksParam *param)
{
    enum CheckKeyType checkType = HKS_CHECK_TYPE_GEN_KEY;
    if (((purpose & HKS_KEY_PURPOSE_DERIVE) != 0) || ((purpose & HKS_KEY_PURPOSE_MAC) != 0)) {
        if ((alg != HKS_ALG_AES) && (alg != HKS_ALG_DES) && (alg != HKS_ALG_3DES) &&
            (alg != HKS_ALG_HMAC) && (alg != HKS_ALG_CMAC) && (alg != HKS_ALG_SM3)) {
            HKS_LOG_E("check mac or derive, not aes alg, alg: %" LOG_PUBLIC "u", alg);
            return HKS_ERROR_INVALID_PURPOSE;
        }
        if (purpose == HKS_KEY_PURPOSE_DERIVE) {
            checkType = HKS_CHECK_TYPE_GEN_DERIVE_KEY;
        } else {
            checkType = HKS_CHECK_TYPE_GEN_MAC_KEY;
        }
    }
    struct ExpectParamsValues expectValues = EXPECT_PARAMS_VALUES_INIT;
    int32_t ret = GetExpectParams(alg, checkType, &expectValues);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    switch (tag) {
        case HKS_TAG_BLOCK_MODE:
            ret = InitCheckOptionalParams(expectValues.mode.needCheck, isAbsent, param,
                expectValues.mode.values, expectValues.mode.valueCnt);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_MODE_FAIL,
                "check param fail:0x%" LOG_PUBLIC "x failed", HKS_TAG_BLOCK_MODE);
            break;
        case HKS_TAG_DIGEST:
            ret = InitCheckOptionalParams(expectValues.digest.needCheck, isAbsent, param,
                expectValues.digest.values, expectValues.digest.valueCnt);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_DIGEST_FAIL,
                "check param fail:0x%" LOG_PUBLIC "x failed", HKS_TAG_DIGEST);
            break;
        case HKS_TAG_PADDING:
            ret = InitCheckOptionalParams(expectValues.padding.needCheck, isAbsent, param,
                expectValues.padding.values, expectValues.padding.valueCnt);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_PADDING_FAIL,
                "check param fail:0x%" LOG_PUBLIC "x failed", HKS_TAG_PADDING);
            break;
        default:
            HKS_LOG_E("invalid tag: %" LOG_PUBLIC "u", tag);
            ret = HKS_FAILURE;
    }
    return ret;
}

int32_t HksCheckFixedParams(uint32_t alg, enum CheckKeyType checkType, const struct ParamsValues *inputParams)
{
    struct ExpectParamsValues expectValues = EXPECT_PARAMS_VALUES_INIT;
    int32_t ret = GetExpectParams(alg, checkType, &expectValues);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = CheckOptionalParams(expectValues.keyLen.needCheck, inputParams->keyLen.isAbsent, inputParams->keyLen.value,
        expectValues.keyLen.values, expectValues.keyLen.valueCnt);
#ifdef HKS_SUPPORT_RSA_C_FLEX_KEYSIZE
    if ((ret != HKS_SUCCESS) && (alg == HKS_ALG_RSA)) {
        ret = CheckRsaKeySize(inputParams->keyLen.value);
    }
#endif
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_SIZE,
        "check keyLen not expected, len = %" LOG_PUBLIC "u", inputParams->keyLen.value);
    ret = CheckOptionalParams(expectValues.padding.needCheck, inputParams->padding.isAbsent, inputParams->padding.value,
        expectValues.padding.values, expectValues.padding.valueCnt);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_PADDING,
        "check padding not expected, padding = %" LOG_PUBLIC "u", inputParams->padding.value);
    ret = CheckOptionalParams(expectValues.purpose.needCheck, inputParams->purpose.isAbsent, inputParams->purpose.value,
        expectValues.purpose.values, expectValues.purpose.valueCnt);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_PURPOSE,
        "check purpose not expected, purpose = %" LOG_PUBLIC "u", inputParams->purpose.value);
    ret = CheckOptionalParams(expectValues.digest.needCheck, inputParams->digest.isAbsent, inputParams->digest.value,
        expectValues.digest.values, expectValues.digest.valueCnt);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_DIGEST,
        "check digest not expected, digest = %" LOG_PUBLIC "u", inputParams->digest.value);
    ret = CheckOptionalParams(expectValues.mode.needCheck, inputParams->mode.isAbsent, inputParams->mode.value,
        expectValues.mode.values, expectValues.mode.valueCnt);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_MODE,
        "check mode not expected, mode = %" LOG_PUBLIC "u", inputParams->mode.value);
    return ret;
}

#ifndef _CUT_AUTHENTICATE_
int32_t HksCheckGenKeyMutableParams(uint32_t alg, const struct ParamsValues *inputParams)
{
    int32_t ret = HKS_SUCCESS;
    switch (alg) {
#ifdef HKS_SUPPORT_RSA_C
        case HKS_ALG_RSA:
            ret = CheckRsaGenKeyPadding(inputParams);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_PADDING,
                "Check padding not expected, padding = %" LOG_PUBLIC "u", inputParams->padding.value);
            break;
#endif
#ifdef HKS_SUPPORT_AES_C
        case HKS_ALG_AES:
            ret = CheckAesPadding(inputParams);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_PADDING,
                "Check padding not expected, padding = %" LOG_PUBLIC "u", inputParams->padding.value);
            break;
#endif
#ifdef HKS_SUPPORT_DES_C
        case HKS_ALG_DES:
            ret = CheckDesPadding(inputParams);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_PADDING,
                "Check padding not expected, padding = %" LOG_PUBLIC "u", inputParams->padding.value);
            break;
#endif
#ifdef HKS_SUPPORT_3DES_C
        case HKS_ALG_3DES:
            ret = Check3DesPadding(inputParams);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_PADDING,
                "Check padding not expected, padding = %" LOG_PUBLIC "u", inputParams->padding.value);
            break;
#endif
#ifdef HKS_SUPPORT_SM4_C
        case HKS_ALG_SM4:
            ret = CheckSm4Padding(inputParams);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_PADDING,
                "Check padding not expected, padding = %" LOG_PUBLIC "u", inputParams->padding.value);
            break;
#endif
        default:
            /* other alg no need check padding */
            break;
    }

    return ret;
}

int32_t CheckImportMutableParams(uint32_t alg, const struct ParamsValues *params)
{
    if (((alg == HKS_ALG_DSA) || (alg == HKS_ALG_ED25519)) &&
        (params->purpose.value != HKS_KEY_PURPOSE_VERIFY)) {
        HKS_LOG_E("Import key check purpose failed.");
        return HKS_ERROR_INVALID_PURPOSE;
    }

    if ((alg == HKS_ALG_SM2) &&
        ((params->purpose.value != HKS_KEY_PURPOSE_VERIFY) && (params->purpose.value != HKS_KEY_PURPOSE_ENCRYPT))) {
        HKS_LOG_E("Import key check purpose failed.");
        return HKS_ERROR_INVALID_PURPOSE;
    }

    if ((alg == HKS_ALG_ECC) &&
        ((params->purpose.value != HKS_KEY_PURPOSE_VERIFY) && (params->purpose.value != HKS_KEY_PURPOSE_UNWRAP) &&
        (params->purpose.value != HKS_KEY_PURPOSE_AGREE))) {
        HKS_LOG_E("Import key check purpose failed.");
        return HKS_ERROR_INVALID_PURPOSE;
    }

    if ((alg == HKS_ALG_RSA) &&
        ((params->purpose.value != HKS_KEY_PURPOSE_VERIFY) && (params->purpose.value != HKS_KEY_PURPOSE_ENCRYPT))) {
        HKS_LOG_E("Import key check purpose failed.");
        return HKS_ERROR_INVALID_PURPOSE;
    }

    if (alg == HKS_ALG_RSA) {
#ifdef HKS_SUPPORT_RSA_C
        if (params->padding.isAbsent) {
            return HKS_SUCCESS;
        }
        if (params->purpose.value == HKS_KEY_PURPOSE_ENCRYPT) {
            return HksCheckValue(params->padding.value, g_rsaCipherPadding, HKS_ARRAY_SIZE(g_rsaCipherPadding));
        } else if (params->purpose.value == HKS_KEY_PURPOSE_VERIFY) {
            return HksCheckValue(params->padding.value, g_rsaSignPadding, HKS_ARRAY_SIZE(g_rsaSignPadding));
        }
#else
        return HKS_ERROR_NOT_SUPPORTED;
#endif
    }

    return HKS_SUCCESS;
}

int32_t HksCheckSignature(uint32_t cmdId, uint32_t alg, uint32_t keySize, const struct HksBlob *signature)
{
    (void)cmdId;
    (void)keySize;
    (void)signature;
    int32_t ret = HKS_ERROR_INVALID_ALGORITHM;
    switch (alg) {
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_SIGN_VERIFY)
        case HKS_ALG_RSA:
            ret = HksCheckValue(keySize, g_rsaKeySize, HKS_ARRAY_SIZE(g_rsaKeySize));
#ifdef HKS_SUPPORT_RSA_C_FLEX_KEYSIZE
            if (ret != HKS_SUCCESS) {
                ret = CheckRsaKeySize(keySize);
            }
#endif
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret,
                HKS_ERROR_INVALID_ARGUMENT, "check key size: key size value %" LOG_PUBLIC "u not expected", keySize)
            return CheckRsaSignature(cmdId, keySize, signature);
#endif
#if defined(HKS_SUPPORT_DSA_C) && defined(HKS_SUPPORT_DSA_SIGN_VERIFY)
        case HKS_ALG_DSA:
            return HKS_SUCCESS;
#endif
#ifdef HKS_SUPPORT_ECC_C
        case HKS_ALG_ECC:
            HKS_IF_NOT_SUCC_LOGE_RETURN(HksCheckValue(keySize, g_eccKeySize, HKS_ARRAY_SIZE(g_eccKeySize)),
                HKS_ERROR_INVALID_ARGUMENT, "check key size: key size value %" LOG_PUBLIC "u not expected", keySize)
            return CheckEccSignature(cmdId, keySize, signature);
#endif
#ifdef HKS_SUPPORT_ED25519_C
        case HKS_ALG_ED25519:
            return CheckEd25519Signature(cmdId, signature);
#endif
#ifdef HKS_SUPPORT_SM2_C
        case HKS_ALG_SM2:
            HKS_IF_NOT_SUCC_LOGE_RETURN(HksCheckValue(keySize, g_sm2KeySize, HKS_ARRAY_SIZE(g_sm2KeySize)),
                HKS_ERROR_INVALID_ARGUMENT, "check key size: key size value %" LOG_PUBLIC "u not expected", keySize)
            return CheckEccSignature(cmdId, keySize, signature);
#endif
        default:
            return ret;
    }
}

int32_t HksCheckSignVerifyMutableParams(uint32_t cmdId, uint32_t alg, const struct ParamsValues *inputParams)
{
    switch (cmdId) {
        case HKS_CMD_ID_SIGN:
            if ((inputParams->purpose.value & HKS_KEY_PURPOSE_SIGN) == 0) {
                return HKS_ERROR_INVALID_PURPOSE;
            }
            break;
        case HKS_CMD_ID_VERIFY:
            if ((inputParams->purpose.value & HKS_KEY_PURPOSE_VERIFY) == 0) {
                return HKS_ERROR_INVALID_PURPOSE;
            }
            break;
        default:
            return HKS_ERROR_INVALID_ARGUMENT;
    }

    switch (alg) {
#ifdef HKS_SUPPORT_RSA_C
        case HKS_ALG_RSA:
            HKS_IF_NOT_SUCC_RETURN(HksCheckValue(inputParams->padding.value, g_rsaSignPadding,
                HKS_ARRAY_SIZE(g_rsaSignPadding)), HKS_ERROR_INVALID_PADDING)
            break;
#endif
#ifdef HKS_SUPPORT_DSA_C
        case HKS_ALG_DSA:
            break;
#endif
#ifdef HKS_SUPPORT_ECC_C
        case HKS_ALG_ECC:
            break;
#endif
        default:
            /* other alg no need check padding */
            break;
    }
    return HKS_SUCCESS;
}
#endif /* _CUT_AUTHENTICATE_ */

#if defined(HKS_SUPPORT_DES_C) || defined(HKS_SUPPORT_3DES_C)
static int32_t HksCheckCipherMutableParamsByAlg(uint32_t alg, const struct ParamsValues *inputParams)
{
    int32_t ret = HKS_ERROR_INVALID_PADDING;
    switch (alg) {
#ifdef HKS_SUPPORT_DES_C
        case HKS_ALG_DES:
            ret = CheckDesPadding(inputParams);
            break;
#endif
#ifdef HKS_SUPPORT_3DES_C
        case HKS_ALG_3DES:
            ret = Check3DesPadding(inputParams);
            break;
#endif
        default:
            return HKS_ERROR_INVALID_ALGORITHM;
    }

    return ret;
}
#endif

int32_t HksCheckCipherMutableParams(uint32_t cmdId, uint32_t alg, const struct ParamsValues *inputParams)
{
    switch (cmdId) {
        case HKS_CMD_ID_ENCRYPT:
            if ((inputParams->purpose.value & HKS_KEY_PURPOSE_ENCRYPT) == 0) {
                return HKS_ERROR_INVALID_PURPOSE;
            }
            break;
        case HKS_CMD_ID_DECRYPT:
            if ((inputParams->purpose.value & HKS_KEY_PURPOSE_DECRYPT) == 0) {
                return HKS_ERROR_INVALID_PURPOSE;
            }
            break;
        default:
            return HKS_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = HKS_ERROR_INVALID_PADDING;
    switch (alg) {
#ifdef HKS_SUPPORT_RSA_C
        case HKS_ALG_RSA:
            ret = HksCheckValue(inputParams->padding.value, g_rsaCipherPadding, HKS_ARRAY_SIZE(g_rsaCipherPadding));
            break;
#endif
#ifdef HKS_SUPPORT_AES_C
        case HKS_ALG_AES:
            ret = CheckAesPadding(inputParams);
            break;
#endif
#ifdef HKS_SUPPORT_SM4_C
        case HKS_ALG_SM4:
            ret = CheckSm4Padding(inputParams);
            break;
#endif
#ifdef HKS_SUPPORT_SM2_C
        case HKS_ALG_SM2:
            ret = HksCheckValue(inputParams->padding.value, g_sm2CipherPadding, HKS_ARRAY_SIZE(g_sm2CipherPadding));
            break;
#endif
        default:
#if defined(HKS_SUPPORT_DES_C) || defined(HKS_SUPPORT_3DES_C)
            ret = HksCheckCipherMutableParamsByAlg(alg, inputParams);
            if (ret == HKS_ERROR_INVALID_ALGORITHM) {
                return HKS_ERROR_INVALID_ALGORITHM;
            }
#endif
            break;
    }
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_INVALID_PADDING)
    return ret;
}

int32_t HksCheckCipherData(uint32_t cmdId, uint32_t alg, const struct ParamsValues *inputParams,
    const struct HksBlob *inData, const struct HksBlob *outData)
{
    switch (alg) {
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_CRYPT)
        case HKS_ALG_RSA:
            return CheckRsaCipherData(cmdId, inputParams, inData, outData);
#endif
#ifdef HKS_SUPPORT_AES_C
        case HKS_ALG_AES:
            return CheckBlockCipherData(cmdId, inputParams, inData, outData, HKS_ALG_AES);
#endif
#ifdef HKS_SUPPORT_DES_C
        case HKS_ALG_DES:
            return CheckBlockCipherData(cmdId, inputParams, inData, outData, HKS_ALG_DES);
#endif
#ifdef HKS_SUPPORT_3DES_C
        case HKS_ALG_3DES:
            return CheckBlockCipherData(cmdId, inputParams, inData, outData, HKS_ALG_3DES);
#endif
#ifdef HKS_SUPPORT_SM4_C
        case HKS_ALG_SM4:
            return CheckBlockCipherData(cmdId, inputParams, inData, outData, HKS_ALG_SM4);
#endif
#ifdef HKS_SUPPORT_SM2_C
        case HKS_ALG_SM2:
            return HKS_SUCCESS;
#endif
        default:
            return HKS_ERROR_INVALID_ALGORITHM;
    }
}

int32_t HksCheckCipherMaterialParams(uint32_t alg, const struct ParamsValues *inputParams,
    const struct HksParamSet *paramSet)
{
#ifdef HKS_SUPPORT_AES_C
    if (alg == HKS_ALG_AES) {
        uint32_t mode = inputParams->mode.value;
        if (mode == HKS_MODE_CBC) {
            return CheckBlockCipherIvMaterial(paramSet);
        } else if ((mode == HKS_MODE_CCM) || (mode == HKS_MODE_GCM)) {
            return CheckCipherAeMaterial(mode, paramSet);
        }
    }
#endif
#ifdef HKS_SUPPORT_DES_C
    if (alg == HKS_ALG_DES) {
        uint32_t mode = inputParams->mode.value;
        if (mode == HKS_MODE_CBC) {
            return CheckBlockCipherIvMaterial(paramSet);
        }
    }
#endif
#ifdef HKS_SUPPORT_3DES_C
    if (alg == HKS_ALG_3DES) {
        uint32_t mode = inputParams->mode.value;
        if (mode == HKS_MODE_CBC) {
            return CheckBlockCipherIvMaterial(paramSet);
        }
    }
#endif
#ifdef HKS_SUPPORT_SM4_C
    if (alg == HKS_ALG_SM4) {
        uint32_t mode = inputParams->mode.value;
        if (mode == HKS_MODE_CBC || mode == HKS_MODE_CTR || mode == HKS_MODE_CFB || mode == HKS_MODE_OFB) {
            return CheckBlockCipherIvMaterial(paramSet);
        }
    }
#endif
    return HKS_SUCCESS;
}

#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
static int32_t HasValidAuthAccessType(const struct ExpectParams allowAuthAccessTypes,
    uint32_t authAccessType, uint32_t *matchType)
{
    for (uint32_t i = 0; i < allowAuthAccessTypes.valueCnt; i++) {
        if ((authAccessType & allowAuthAccessTypes.values[i]) != 0) {
            *matchType = allowAuthAccessTypes.values[i];
            return HKS_SUCCESS;
        }
    }
    return HKS_ERROR_INVALID_ARGUMENT;
}

static int32_t HksCheckAuthAccessTypeByUserAuthType(uint32_t userAuthType, uint32_t authAccessType)
{
    uint32_t valuesCnt = HKS_ARRAY_SIZE(g_expectAuthAccessParams);
    uint32_t validAuthAccessType = 0;
    uint32_t tempType = 0;
    for (uint32_t i = 0; i < valuesCnt; i++) {
        struct AuthAccessTypeChecker checker = g_expectAuthAccessParams[i];
        if ((checker.userAuthType & userAuthType) != 0 &&
            HasValidAuthAccessType(checker.allowAuthAccessTypes, authAccessType, &tempType) == HKS_SUCCESS) {
            validAuthAccessType |= tempType;
        }
    }
    if ((authAccessType != 0) && (authAccessType == validAuthAccessType)) {
        if ((authAccessType & HKS_AUTH_ACCESS_ALWAYS_VALID) != 0
            && (authAccessType &(~HKS_AUTH_ACCESS_ALWAYS_VALID)) != 0) {
            HKS_LOG_E("auth access type is invalid: ALWAYS_VALID cannot coexist with other type");
            return HKS_ERROR_INVALID_ACCESS_TYPE;
        }
        return HKS_SUCCESS;
    }
    HKS_LOG_E("authAccessType %" LOG_PUBLIC "u is not equal to validAuthAccessType %" LOG_PUBLIC "u or is 0",
        authAccessType, validAuthAccessType);
    return HKS_ERROR_INVALID_ACCESS_TYPE;
}
#endif

int32_t HksCheckUserAuthParams(uint32_t userAuthType, uint32_t authAccessType, uint32_t challengeType)
{
#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
    int32_t ret = HksCheckValue(userAuthType, g_supportUserAuthTypes, HKS_ARRAY_SIZE(g_supportUserAuthTypes));
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_INVALID_AUTH_TYPE)

    ret = HksCheckValue(challengeType, g_userAuthChallengeType, HKS_ARRAY_SIZE(g_userAuthChallengeType));
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_INVALID_CHALLENGE_TYPE)

    return HksCheckAuthAccessTypeByUserAuthType(userAuthType, authAccessType);
#else
    (void)userAuthType;
    (void)authAccessType;
    (void)challengeType;
    return HKS_SUCCESS;
#endif
}

int32_t HksCheckSecureSignParams(uint32_t secureSignType)
{
#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
    return HksCheckValue(secureSignType, g_supportSecureSignType, HKS_ARRAY_SIZE(g_supportSecureSignType));
#else
    (void)secureSignType;
    return HKS_SUCCESS;
#endif
}

/* If the algorithm is ed25519, the plaintext is directly cached, and if the digest is HKS_DIGEST_NONE, the
   hash value has been passed in by the user. So the hash value does not need to be free.
*/
int32_t HksCheckNeedCache(uint32_t alg, uint32_t digest)
{
    if ((alg == HKS_ALG_ED25519) || (digest == HKS_DIGEST_NONE)) {
        HKS_LOG_I("need to cache the data");
        return HKS_SUCCESS;
    }
    return HKS_FAILURE;
}

#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
static int32_t CheckUserAuthKeyInfoValidity(const struct HksParamSet *paramSet,
    const struct KeyInfoParams *params, uint32_t paramsCnt)
{
    for (uint32_t i = 0; i < paramsCnt; i++) {
        if (params[i].needCheck) {
            struct HksParam *param = NULL;
            int32_t ret = HksGetParam(paramSet, params[i].tag, &param);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_SUCCESS, "tag is empty and no need to check!")

            ret = HksCheckValue(param->uint32Param, params[i].values, params[i].valueCnt);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "not support tag %" LOG_PUBLIC "u and value is %" LOG_PUBLIC "u",
                params[i].tag, param->uint32Param)
        }
    }
    return HKS_SUCCESS;
}
#endif

int32_t HksCheckUserAuthKeyInfoValidity(const struct HksParamSet *paramSet)
{
#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
    HKS_IF_NOT_SUCC_LOGE_RETURN(HksCheckParamSet(paramSet, paramSet->paramSetSize),
    HKS_ERROR_INVALID_ARGUMENT, "invalid paramSet!")

    struct HksParam *algParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ALGORITHM, &algParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get alg param failed!")

    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_validKeyInfo); i++) {
        if (algParam->uint32Param == g_validKeyInfo[i].keyAlg) {
            ret = CheckUserAuthKeyInfoValidity(paramSet, g_validKeyInfo[i].params, g_validKeyInfo[i].paramsCnt);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_NOT_SUPPORTED, "not support set key auth purpose!")
        }
    }
    HKS_LOG_I("support set key auth purpose!");
    return ret;
#else
    (void)paramSet;
    return HKS_SUCCESS;
#endif
}