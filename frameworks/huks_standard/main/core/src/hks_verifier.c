/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "hks_verifier.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stddef.h>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type.h"
#include "securec.h"

#define OPENSSL_SUCCESS 1
#define OPENSSL_ERROR 0
#define KEY_DESCRIPTION_OID "1.3.6.1.4.1.2011.2.376.1.3"

#define TLV_VERSION_NEED_SIZE 3

#define ASN_1_TAG_TYPE_SEQ 0x30
#define ASN_1_MIN_VAL_1_EXTRA_LEN_BYTE 0x80
#define ASN_1_TAG_TYPE_1_BYTE_LEN 0x81
#define ASN_1_TAG_TYPE_2_BYTE_LEN 0x82
#define ASN_1_MIN_HEADER_LEN 0x3
#define APPLICATION_ID_RAW_OID_LEN 16
#define APPLICATION_ID_HEADER_LEN 2

struct HksCertInfo {
    uint8_t *data;
    size_t length;
    enum HksCertFormat format;
    X509 *x509;
};

#define HKS_ASN1_DECODE_BYTE(ptr, value) \
do { \
    (value) = (uint32_t)((ptr)[0]); \
    (ptr)++; \
} while (0)

#define HKS_ASN1_DECODE_TWO_BYTE(ptr, value) \
do { \
    (value) = (uint32_t)((ptr)[0] & 0xff) << 8; \
    (ptr)++; \
    (value) |= (uint32_t)((ptr)[0] & 0xff); \
    (ptr)++; \
} while (0)

static uint8_t g_challengeOid[] = {
    0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x02, 0x01, 0x04
};
static uint8_t g_udidOid[] = {
    0x06, 0x0e, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x02, 0x02, 0x04, 0x0a
};
static uint8_t g_snOid[] = {
    0x06, 0x0e, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x02, 0x02, 0x04, 0x03
};
static uint8_t g_secInfoOid[] = {
    0x06, 0x0e, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x02, 0x02, 0x02, 0x05
};
static uint8_t g_versionInfoOid[] = {
    0x06, 0x0e, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x02, 0x02, 0x02, 0x04
};
static uint8_t g_deviceIdOid[] = {
    0x06, 0x0e, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x02, 0x02, 0x04, 0x05
};
static uint8_t g_appIdOid[] = {
    0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x02, 0x01, 0x03
};

static const struct HksParam g_oidParams[] = {
    {
        .tag = HKS_TAG_ATTESTATION_CHALLENGE,
        .blob = {
            .size = sizeof(g_challengeOid),
            .data = g_challengeOid
        }
    }, {
        .tag = HKS_TAG_ATTESTATION_ID_UDID,
        .blob = {
            .size = sizeof(g_udidOid),
            .data = g_udidOid
        }
    }, {
        .tag = HKS_TAG_ATTESTATION_ID_SERIAL,
        .blob = {
            .size = sizeof(g_snOid),
            .data = g_snOid
        }
    }, {
        .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO,
        .blob = {
            .size = sizeof(g_secInfoOid),
            .data = g_secInfoOid
        }
    }, {
        .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO,
        .blob = {
            .size = sizeof(g_versionInfoOid),
            .data = g_versionInfoOid
        }
    }, {
        .tag = HKS_TAG_ATTESTATION_ID_DEVICE,
        .blob = {
            .size = sizeof(g_deviceIdOid),
            .data = g_deviceIdOid
        }
    }, {
        .tag = HKS_TAG_ATTESTATION_APPLICATION_ID,
        .blob = {
            .size = sizeof(g_appIdOid),
            .data = g_appIdOid
        }
    },
};

static int32_t CopyBlobBuffer(const uint8_t *buffer, uint32_t len, struct HksBlob *blob)
{
    if ((blob->data == NULL) || (blob->size < len)) {
        HKS_LOG_E("construct paramSet out blob: invalid blob");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (memcpy_s(blob->data, blob->size, buffer, len) != EOK) {
        HKS_LOG_E("construct paramSet out blob buffer failed");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    blob->size = len;
    return HKS_SUCCESS;
}

static X509 *GetX509FormatCert(const struct HksCertInfo *cert)
{
    X509 *x509 = NULL;

    BIO *bio = BIO_new_mem_buf(cert->data, cert->length);
    HKS_IF_NULL_RETURN(bio, x509)

    if (cert->format == HKS_CERT_DER) {
        x509 = d2i_X509_bio(bio, NULL);
    } else if (cert->format == HKS_CERT_PEM) {
        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    }

    BIO_free(bio);
    return x509;
}

static int32_t TranslateToX509Format(struct HksCertInfo *certs, uint32_t certNum)
{
    for (uint32_t i = 0; i < certNum; ++i) {
        X509 *x509 = GetX509FormatCert(&certs[i]);
        /* if failed, x509 need to be freed by caller function */
        HKS_IF_NULL_LOGE_RETURN(x509, HKS_ERROR_VERIFICATION_FAILED, "load cert chain to x509 failed")

        certs[i].x509 = x509;
    }
    return HKS_SUCCESS;
}

static int32_t VerifySignature(const struct HksCertInfo *cert, const struct HksCertInfo *issuerCert)
{
    EVP_PKEY *pubKey = X509_get_pubkey(issuerCert->x509);
    HKS_IF_NULL_LOGE_RETURN(pubKey, HKS_ERROR_VERIFICATION_FAILED, "get public key from device cert failed")

    int32_t resOpenssl = X509_verify(cert->x509, pubKey);
    if (resOpenssl != OPENSSL_SUCCESS) {
        HKS_LOG_E("verify signature failed");
    }

    EVP_PKEY_free(pubKey);
    return (resOpenssl == OPENSSL_SUCCESS) ? HKS_SUCCESS : HKS_ERROR_VERIFICATION_FAILED;
}

static int32_t VerifyCertChain(const struct HksCertInfo *certs, uint32_t certNum)
{
    int32_t ret = HKS_ERROR_VERIFICATION_FAILED;
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *verifyCtx = X509_STORE_CTX_new();
    STACK_OF(X509) *skCerts = sk_X509_new_null();
    if ((store == NULL) || (verifyCtx == NULL) || (skCerts == NULL)) {
        HKS_LOG_E("verify cert chain init failed");
        goto EXIT;
    }

    // We only verify the validity of the certificate chain, not its legality,
    // so we will add the last cert in the cert chain, instead of the real root cert, into trust store here.
    if (X509_STORE_add_cert(store, certs[certNum - 1].x509) != OPENSSL_SUCCESS) {
        HKS_LOG_E("add root cert failed");
        goto EXIT;
    }

    for (uint32_t i = certNum - 2; i > 0; i--) {
        int opensslRet = sk_X509_push(skCerts, X509_dup(certs[i].x509));
        if (opensslRet <= 0 || (uint32_t)(opensslRet) != certNum - 1 - i) {
            HKS_LOG_E("add cert to chain failed");
            goto EXIT;
        }
    }

    int32_t resOpenssl = X509_STORE_CTX_init(verifyCtx, store, certs[0].x509, skCerts); /* cert 0: add leaf cert */
    if (resOpenssl != OPENSSL_SUCCESS) {
        HKS_LOG_E("init verify ctx failed");
        goto EXIT;
    }

    resOpenssl = X509_verify_cert(verifyCtx);
    if (resOpenssl != OPENSSL_SUCCESS) {
        HKS_LOG_E("verify cert failed");
        goto EXIT;
    }

    ret = VerifySignature(&certs[certNum - 1], &certs[certNum - 1]); /* root ca cert need to be verified by itself */
    HKS_IF_NOT_SUCC_LOGE(ret, "verify root cert failed")

EXIT:
    if (skCerts != NULL) {
        sk_X509_pop_free(skCerts, X509_free);
    }
    if (verifyCtx != NULL) {
        X509_STORE_CTX_free(verifyCtx);
    }
    if (store != NULL) {
        X509_STORE_free(store);
    }
    return ret;
}

static int32_t VerifyAttestationCertChain(struct HksCertInfo *certs, uint32_t certNum)
{
    int32_t ret = TranslateToX509Format(certs, certNum);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "translate to x509 format failed")

    ret = VerifyCertChain(certs, certNum);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "verify attestation cert chain verify cert chain failed")

    /* use device cert's pubkey to verify the attestation cert */
    ret = VerifySignature(&certs[0], &certs[1]); /* 0:attestation cert, 1:device cert */
    HKS_IF_NOT_SUCC_LOGE(ret, "verify attestation cert chain signature failed")

    return ret;
}

static int32_t EncodeTlvAndGetLength(uint8_t **buf, uint32_t *outLength, uint32_t inLen)
{
    uint32_t length = 0; /* length of the payload */

    uint32_t tmp;
    HKS_ASN1_DECODE_BYTE(*buf, tmp); /* get type */
    if ((*buf)[0] < ASN_1_MIN_VAL_1_EXTRA_LEN_BYTE) {
        /* Current byte tells the length */
        HKS_ASN1_DECODE_BYTE(*buf, length);
    } else {
        /* now bit 8 is set */
        uint32_t b;
        HKS_ASN1_DECODE_BYTE(*buf, b);

        switch (b) {
            case ASN_1_TAG_TYPE_1_BYTE_LEN: /* 1 byte length */
                HKS_ASN1_DECODE_BYTE(*buf, length);
                break;
            case ASN_1_TAG_TYPE_2_BYTE_LEN: /* 2 byte length */
                if (inLen < (ASN_1_MIN_HEADER_LEN + 1)) {
                    HKS_LOG_E("invalid data to decode two bytes");
                    return HKS_ERROR_INVALID_ARGUMENT;
                }
                HKS_ASN1_DECODE_TWO_BYTE(*buf, length);
                break;
            default:
                HKS_LOG_E("Object length does not make sense");
                return HKS_ERROR_INVALID_ARGUMENT;
        }
    }
    *outLength = length;
    return HKS_SUCCESS;
}

static int32_t ExtractTlvLength(const uint8_t *in, uint32_t inLen, uint32_t *headSize, uint32_t *outLen)
{
    if ((in == NULL) || (inLen < ASN_1_MIN_HEADER_LEN) || (outLen == NULL)) {
        HKS_LOG_E("invalid tlv data");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    uint8_t *buf = (uint8_t *)in;
    uint32_t length = 0; /* length of the payload */

    int32_t ret = EncodeTlvAndGetLength(&buf, &length, inLen);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    *headSize = buf - in;
    if (*headSize > inLen) {
        HKS_LOG_E("the data is too small, extract failed");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    /* Check that tag length can fit into buffer */
    if (length > (inLen - *headSize)) {
        HKS_LOG_E("data buffer is not big enough to hold %" LOG_PUBLIC "u bytes.", length);
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    *outLen = length;
    return HKS_SUCCESS;
}

static int32_t ExtractTlvData(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    if ((in == NULL) || (inLen < ASN_1_MIN_HEADER_LEN) || (out == NULL) || (outLen == NULL)) {
        HKS_LOG_E("invalid tlv data");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    uint8_t *buf = (uint8_t *)in;
    uint32_t length = 0; /* length of the payload */

    int32_t ret = EncodeTlvAndGetLength(&buf, &length, inLen);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    uint32_t headSize = buf - in;
    if (headSize > inLen) {
        HKS_LOG_E("the data is too small, extract failed");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    /* Check that tag length can fit into buffer */
    if (length > (inLen - headSize)) {
        HKS_LOG_E("data buffer is not big enough to hold %" LOG_PUBLIC "u bytes.", length);
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (memcpy_s(out, *outLen, buf, length) != EOK) {
        HKS_LOG_E("extract tlv data memcpy_s failed");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *outLen = length;
    return HKS_SUCCESS;
}

static int32_t ExtractTlvDataAndHeadSize(const uint8_t *in, uint32_t inLen,
    uint8_t **out, uint32_t *outLen, uint32_t *size)
{
    uint32_t headOffset = 0;
    int32_t ret = ExtractTlvLength(in, inLen, &headOffset, outLen);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "ExtractTlvLength fail!")
    if (size != NULL) {
        *size = headOffset;
    }

    *out = (uint8_t *)HksMalloc(*outLen);
    HKS_IF_NULL_LOGE_RETURN(*out, HKS_ERROR_MALLOC_FAIL, "malloc fail!")

    ret = ExtractTlvData(in, inLen, *out, outLen);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(*out);
        HKS_LOG_E("ExtractTlvData fail!");
    }
    return ret;
}

static ASN1_OBJECT *GetObjByOid(int32_t nid, const char *oid, const char *sn, const char *ln)
{
    int32_t len;
    ASN1_OBJECT *obj = NULL;
    uint8_t *buf = NULL;
    do {
        len = a2d_ASN1_OBJECT(NULL, 0, oid, -1);
        if (len <= 0) {
            HKS_LOG_E("get a2d_ASN1_OBJECT fail, len1 = %" LOG_PUBLIC "d", len);
            return NULL;
        }

        buf = (uint8_t *)HksMalloc(len);
        HKS_IF_NULL_LOGE_RETURN(buf, NULL, "openssl malloc fail")

        len = a2d_ASN1_OBJECT(buf, len, oid, -1);
        if (len <= 0) {
            HKS_LOG_E("get a2d_ASN1_OBJECT fail, len2 = %" LOG_PUBLIC "d", len);
            break;
        }

        obj = ASN1_OBJECT_create(nid, buf, len, sn, ln);
        HKS_IF_NULL_LOGE_BREAK(obj, "ASN1_OBJECT_create fail")
    } while (0);
    HKS_FREE(buf);
    return obj;
}

static int32_t GetKeyDescriptionSeqValue(const struct HksCertInfo *cert, uint8_t **data, uint32_t *len)
{
    int32_t ret = HKS_ERROR_VERIFICATION_FAILED;
    ASN1_OBJECT *obj = GetObjByOid(NID_undef, KEY_DESCRIPTION_OID, "KeyDescription", "KEY DESCRIPTION OID");
    HKS_IF_NULL_LOGE_RETURN(obj, ret, "get obj by oid failed")

    int32_t idx = X509_get_ext_by_OBJ(cert->x509, obj, -1);
    if (idx < 0) {
        HKS_LOG_E("get ext idx by Obj failed");
        goto EXIT;
    }

    X509_EXTENSION *ext = X509_get_ext(cert->x509, idx);
    if (ext == NULL) {
        HKS_LOG_E("X509 get ext by idx failed");
        goto EXIT;
    }

    ASN1_OCTET_STRING *octetStr = X509_EXTENSION_get_data(ext);
    if (octetStr == NULL) {
        HKS_LOG_E("X509 extension get data by ext failed");
        goto EXIT;
    }

    // gain the Extension data of attest cert
    ret = ExtractTlvDataAndHeadSize(octetStr->data, octetStr->length, data, len, NULL);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("gain the extension data failed");
        goto EXIT;
    }

    if (*len >= MAX_ATTEST_EXTENSION_BUF_LEN) {
        (void)memset_s(*data, *len, 0, *len);
        HKS_FREE(*data);
        HKS_LOG_E("the length of extension data is too long");
        ret = HKS_ERROR_INSUFFICIENT_MEMORY;
    }

EXIT:
    ASN1_OBJECT_free(obj);
    return ret;
}

static int32_t ConstructParamSetOut(enum HksTag tag, uint8_t *data, uint32_t len, struct HksParamSet *paramSetOut)
{
    int32_t ret;
    for (uint32_t i = 0; i < paramSetOut->paramsCnt; i++) {
        if ((paramSetOut->params[i].tag == tag) && (GetTagType(tag) == HKS_TAG_TYPE_BYTES)) {
            if (tag == HKS_TAG_ATTESTATION_APPLICATION_ID) {
                // APPLICATION_ID_RAW_OID_LEN + APPLICATION_ID_HEADER_LEN + sizeof(appId)
                uint32_t appIdOffsetSize = APPLICATION_ID_RAW_OID_LEN + APPLICATION_ID_HEADER_LEN;
                ret = CopyBlobBuffer(data + appIdOffsetSize, len - appIdOffsetSize, &(paramSetOut->params[i].blob));
                HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "CopyBlobBuffer failed")
            } else {
                ret = CopyBlobBuffer(data, len, &(paramSetOut->params[i].blob));
                HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "CopyBlobBuffer failed")
            }
            return HKS_SUCCESS;
        }
    }
    return HKS_SUCCESS;
}

static int32_t GetClaimDataParamSet(uint8_t *data, uint32_t len, struct HksParamSet *paramSetOut)
{
    for (uint32_t i = 0; i < sizeof(g_oidParams) / sizeof(g_oidParams[0]); i++) {
        uint32_t offset = TLV_VERSION_NEED_SIZE;
        uint8_t *claimData = NULL;
        uint32_t claimSize = 0;
        uint32_t headSize = 0;

        if ((offset > len) || ((len - offset) < g_oidParams[i].blob.size)) {
            HKS_LOG_E("input param invalid, fail");
            return HKS_ERROR_INVALID_ARGUMENT;
        }

        if (HksMemCmp(g_oidParams[i].blob.data, data + offset, g_oidParams[i].blob.size) == 0) {
            offset += g_oidParams[i].blob.size;
            int32_t ret = ExtractTlvDataAndHeadSize(data + offset, len - offset, &claimData, &claimSize, &headSize);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT, "get cliam count fail")

            if (claimSize >= MAX_ATTEST_CLAIM_BUF_LEN) {
                HKS_LOG_E("the length of claim is too long");
                HKS_FREE(claimData);
                return HKS_ERROR_INSUFFICIENT_MEMORY;
            }

            ret = ConstructParamSetOut(g_oidParams[i].tag, claimData, claimSize, paramSetOut);
            if (ret != HKS_SUCCESS) {
                HKS_LOG_E("ConstructParamSetOut fail");
                HKS_FREE(claimData);
                return HKS_ERROR_INVALID_ARGUMENT;
            }
            HKS_FREE(claimData);
            return HKS_SUCCESS;
        }
    }

    return HKS_SUCCESS;
}

static int32_t FillAttestExtendParamSet(uint8_t *data, uint32_t length,
    uint8_t version, struct HksParamSet *paramSetOut)
{
    if ((data == NULL) || (length < ASN_1_MIN_HEADER_LEN)) {
        HKS_LOG_E("invalid argument data");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    int32_t ret;
    uint32_t headSize;
    uint32_t leftSize = length;
    uint8_t *tmp = data;

    for (headSize = 0; leftSize >= ASN_1_MIN_HEADER_LEN;) {
        uint8_t *value = NULL;
        uint32_t valueLength;
        ret = ExtractTlvDataAndHeadSize(tmp, leftSize, &value, &valueLength, &headSize);
        if (ret != HKS_SUCCESS || valueLength > (leftSize - headSize)
            || leftSize < ASN_1_MIN_HEADER_LEN) {
            HKS_FREE(value);
            HKS_LOG_E("get claim count fail, the length of claim or the value of leftSize can be wrong, too");
            return HKS_ERROR_INVALID_ARGUMENT;
        }

        if (valueLength >= MAX_ATTEST_CLAIM_BUF_LEN) {
            HKS_LOG_E("the length of claim is too long");
            HKS_FREE(value);
            return HKS_ERROR_INSUFFICIENT_MEMORY;
        }

        ret = GetClaimDataParamSet(value, valueLength, paramSetOut);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("GetClaimDataParamSet failed, ret = %" LOG_PUBLIC "d", ret);
            HKS_FREE(value);
            return ret;
        }
        HKS_FREE(value);
        tmp += (valueLength + headSize);
        leftSize -= (valueLength + headSize);
    }
    return HKS_SUCCESS;
}

static int32_t FillAttestExtendInfo(uint8_t *data, uint32_t length, struct HksParamSet *paramSetOut)
{
    if ((data == NULL) || (length < ASN_1_MIN_HEADER_LEN) || (length <= TLV_VERSION_NEED_SIZE)) {
        HKS_LOG_E("invalid argument data");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    uint8_t *version = NULL;
    uint32_t len;
    int32_t ret = ExtractTlvDataAndHeadSize(data, length, &version, &len, NULL);
    if (ret != HKS_SUCCESS || len != sizeof(uint8_t)) {
        HKS_FREE(version);
        HKS_LOG_E("get version fail or length is not equal to sizeof(uint8_t)");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    ret = FillAttestExtendParamSet(data + TLV_VERSION_NEED_SIZE, length - TLV_VERSION_NEED_SIZE,
        *version, paramSetOut);
    HKS_IF_NOT_SUCC_LOGE(ret, "fill attest extend paramSet fail")

    HKS_FREE(version);
    return ret;
}

static int32_t GetParamSetOutInfo(const struct HksCertInfo *certs, struct HksParamSet *paramSetOut)
{
    uint8_t *keyDescription = NULL;
    uint32_t keyDescLen;

    int32_t ret = GetKeyDescriptionSeqValue(&certs[0], &keyDescription, &keyDescLen);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "GetKeyDescriptionSeqValue failed")

    ret = FillAttestExtendInfo(keyDescription, keyDescLen, paramSetOut);
    HKS_IF_NOT_SUCC_LOGE(ret, "fill attest extend info fail")

    (void)memset_s(keyDescription, keyDescLen, 0, keyDescLen);
    HKS_FREE(keyDescription);
    return ret;
}

static int32_t InitCertChainInfo(const struct HksCertChain *certChain, struct HksCertInfo **certs)
{
    int32_t ret = HKS_SUCCESS;

    uint32_t certsInfoLen = sizeof(struct HksCertInfo) * certChain->certsCount;
    struct HksCertInfo *certsInfo = (struct HksCertInfo *)HksMalloc(certsInfoLen);
    HKS_IF_NULL_RETURN(certsInfo, HKS_ERROR_MALLOC_FAIL)

    (void)memset_s(certsInfo, certsInfoLen, 0, certsInfoLen);

    for (uint32_t i = 0; i < certChain->certsCount; ++i) {
        struct HksCertInfo *cert = &(certsInfo[i]);
        cert->data = certChain->certs[i].data;
        cert->length = certChain->certs[i].size;

        if (cert->data[0] == '-') {
            cert->format = HKS_CERT_PEM;
        } else if (cert->data[0] == ASN_1_TAG_TYPE_SEQ) {
            cert->format = HKS_CERT_DER;
        } else {
            HKS_LOG_E("validate cert chain invalid cert format");
            ret = HKS_ERROR_VERIFICATION_FAILED;
            break;
        }
    }

    if (ret != HKS_SUCCESS) {
        HKS_FREE(certsInfo);
        return ret;
    }
    *certs = certsInfo;
    return HKS_SUCCESS;
}

static void FreeCertChainInfo(struct HksCertInfo **certs, uint32_t certNum)
{
    if (*certs != NULL) {
        for (uint32_t i = 0; i < certNum; ++i) {
            if ((*certs)[i].x509 != NULL) {
                X509_free((*certs)[i].x509);
            }
        }
        HKS_FREE(*certs);
    }
}

static int32_t CheckCertChainParams(const struct HksCertChain *certChain)
{
    /* certChain has been checked not null */
    if ((certChain->certs == NULL) || (certChain->certsCount > HKS_MAX_CERT_CHAIN_CNT) ||
        (certChain->certsCount < HKS_MIN_CERT_CHAIN_CNT)) {
        HKS_LOG_E("validate cert chain chain invalid certChain or count");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    for (uint32_t i = 0; i < certChain->certsCount; ++i) {
        if (CheckBlob(&certChain->certs[i]) != HKS_SUCCESS) {
            HKS_LOG_E("certChain entry[%" LOG_PUBLIC "u] invalid", i);
            return HKS_ERROR_INVALID_ARGUMENT;
        }
    }
    return HKS_SUCCESS;
}

static int32_t CheckValidateCertChainParams(const struct HksCertChain *certChain, struct HksParamSet *paramSetOut)
{
    int32_t ret = CheckCertChainParams(certChain);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "certChain invalid, ret = %" LOG_PUBLIC "d", ret)

    /* paramSetOut has been checked not null */
    ret = HksCheckParamSet(paramSetOut, paramSetOut->paramSetSize);
    HKS_IF_NOT_SUCC_LOGE(ret, "paramSetOut invalid, ret = %" LOG_PUBLIC "d", ret)
    return ret;
}

int32_t HksClientValidateCertChain(const struct HksCertChain *certChain, struct HksParamSet *paramSetOut)
{
    int32_t ret = CheckValidateCertChainParams(certChain, paramSetOut);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "certChain params check failed, ret = %" LOG_PUBLIC "d", ret)

    struct HksCertInfo *certsInfo = NULL;
    ret = InitCertChainInfo(certChain, &certsInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get cert chain info failed")
    ret = VerifyAttestationCertChain(certsInfo, certChain->certsCount);
    if (ret != HKS_SUCCESS) {
        FreeCertChainInfo(&certsInfo, certChain->certsCount);
        HKS_LOG_E("VerifyAttestationCertChain failed, ret = %" LOG_PUBLIC "d", ret);
        return ret;
    }

    ret = GetParamSetOutInfo(certsInfo, paramSetOut);
    HKS_IF_NOT_SUCC_LOGE(ret, "VerifyAttestationCertChain failed, ret = %" LOG_PUBLIC "d", ret)

    FreeCertChainInfo(&certsInfo, certChain->certsCount);
    return ret;
}
