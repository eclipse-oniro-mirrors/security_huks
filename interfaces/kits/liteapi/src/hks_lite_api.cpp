/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "hks_lite_api.h"
#include "hks_lite_api_common.h"
#include "hks_type.h"

#include "jsi.h"

namespace OHOS {
namespace ACELite {

void AddInt32PropertyInLite(JSIValue object, const char *name, int32_t value)
{
    JSIValue numberProperty = JSI::CreateNumber(value);
    JSI::SetNamedProperty(object, name, numberProperty);
}

static JSIValue CreateHuksErrCode(void)
{
    JSIValue errorCode = JSI::CreateObject();

    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_PERMISSION_FAIL", HUKS_ERR_CODE_PERMISSION_FAIL);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_NOT_SYSTEM_APP", HUKS_ERR_CODE_NOT_SYSTEM_APP);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_ILLEGAL_ARGUMENT", HUKS_ERR_CODE_ILLEGAL_ARGUMENT);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_NOT_SUPPORTED_API", HUKS_ERR_CODE_NOT_SUPPORTED_API);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_FEATURE_NOT_SUPPORTED", HUKS_ERR_CODE_FEATURE_NOT_SUPPORTED);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT",
        HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT",
        HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_FILE_OPERATION_FAIL", HUKS_ERR_CODE_FILE_OPERATION_FAIL);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_COMMUNICATION_FAIL", HUKS_ERR_CODE_COMMUNICATION_FAIL);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_CRYPTO_FAIL", HUKS_ERR_CODE_CRYPTO_FAIL);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_KEY_AUTH_PERMANENTLY_INVALIDATED",
        HUKS_ERR_CODE_KEY_AUTH_PERMANENTLY_INVALIDATED);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_KEY_AUTH_VERIFY_FAILED", HUKS_ERR_CODE_KEY_AUTH_VERIFY_FAILED);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_KEY_AUTH_TIME_OUT", HUKS_ERR_CODE_KEY_AUTH_TIME_OUT);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_SESSION_LIMIT", HUKS_ERR_CODE_SESSION_LIMIT);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_ITEM_NOT_EXIST", HUKS_ERR_CODE_ITEM_NOT_EXIST);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_EXTERNAL_ERROR", HUKS_ERR_CODE_EXTERNAL_ERROR);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_CREDENTIAL_NOT_EXIST", HUKS_ERR_CODE_CREDENTIAL_NOT_EXIST);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_INSUFFICIENT_MEMORY", HUKS_ERR_CODE_INSUFFICIENT_MEMORY);
    AddInt32PropertyInLite(errorCode, "HUKS_ERR_CODE_CALL_SERVICE_FAILED", HUKS_ERR_CODE_CALL_SERVICE_FAILED);

    return errorCode;
}

static JSIValue CreateHuksKeyPurpose(void)
{
    JSIValue keyPurpose = JSI::CreateObject();

    AddInt32PropertyInLite(keyPurpose, "HUKS_KEY_PURPOSE_ENCRYPT", HKS_KEY_PURPOSE_ENCRYPT);
    AddInt32PropertyInLite(keyPurpose, "HUKS_KEY_PURPOSE_DECRYPT", HKS_KEY_PURPOSE_DECRYPT);
    AddInt32PropertyInLite(keyPurpose, "HUKS_KEY_PURPOSE_SIGN", HKS_KEY_PURPOSE_SIGN);
    AddInt32PropertyInLite(keyPurpose, "HUKS_KEY_PURPOSE_VERIFY", HKS_KEY_PURPOSE_VERIFY);
    AddInt32PropertyInLite(keyPurpose, "HUKS_KEY_PURPOSE_MAC", HKS_KEY_PURPOSE_MAC);

    return keyPurpose;
}

static JSIValue CreateHuksKeyPadding(void)
{
    JSIValue keyPadding = JSI::CreateObject();

    AddInt32PropertyInLite(keyPadding, "HUKS_PADDING_NONE", HKS_PADDING_NONE);
    AddInt32PropertyInLite(keyPadding, "HUKS_PADDING_PKCS7", HKS_PADDING_PKCS7);
    AddInt32PropertyInLite(keyPadding, "HUKS_PADDING_PKCS1_V1_5", HKS_PADDING_PKCS1_V1_5);
    AddInt32PropertyInLite(keyPadding, "HUKS_PADDING_OAEP", HKS_PADDING_OAEP);
    AddInt32PropertyInLite(keyPadding, "HUKS_PADDING_PSS", HKS_PADDING_PSS);
    AddInt32PropertyInLite(keyPadding, "HUKS_PADDING_ISO_IEC_9796_2", HKS_PADDING_ISO_IEC_9796_2);
    AddInt32PropertyInLite(keyPadding, "HUKS_PADDING_ISO_IEC_9797_1", HKS_PADDING_ISO_IEC_9797_1);

    return keyPadding;
}

static JSIValue CreateHuksCipherMode(void)
{
    JSIValue keyCipherMode = JSI::CreateObject();

    AddInt32PropertyInLite(keyCipherMode, "HUKS_MODE_ECB", HKS_MODE_ECB);
    AddInt32PropertyInLite(keyCipherMode, "HUKS_MODE_CBC", HKS_MODE_CBC);
    AddInt32PropertyInLite(keyCipherMode, "HUKS_MODE_CTR", HKS_MODE_CTR);
    AddInt32PropertyInLite(keyCipherMode, "HUKS_MODE_GCM", HKS_MODE_GCM);

    return keyCipherMode;
}

static JSIValue CreateHuksKeySize(void)
{
    JSIValue keySize = JSI::CreateObject();

    AddInt32PropertyInLite(keySize, "HUKS_AES_KEY_SIZE_128", HKS_AES_KEY_SIZE_128);
    AddInt32PropertyInLite(keySize, "HUKS_AES_KEY_SIZE_192", HKS_AES_KEY_SIZE_192);
    AddInt32PropertyInLite(keySize, "HUKS_AES_KEY_SIZE_256", HKS_AES_KEY_SIZE_256);
    AddInt32PropertyInLite(keySize, "HUKS_AES_KEY_SIZE_512", HKS_AES_KEY_SIZE_512);

    AddInt32PropertyInLite(keySize, "HUKS_DES_KEY_SIZE_64", HKS_DES_KEY_SIZE_64);
    AddInt32PropertyInLite(keySize, "HUKS_3DES_KEY_SIZE_128", HKS_3DES_KEY_SIZE_128);
    AddInt32PropertyInLite(keySize, "HUKS_3DES_KEY_SIZE_192", HKS_3DES_KEY_SIZE_192);

    AddInt32PropertyInLite(keySize, "HUKS_RSA_KEY_SIZE_1024", HKS_RSA_KEY_SIZE_1024);
    AddInt32PropertyInLite(keySize, "HUKS_RSA_KEY_SIZE_2048", HKS_RSA_KEY_SIZE_2048);

    return keySize;
}

static JSIValue CreateHuksKeyAlg(void)
{
    JSIValue keyAlg = JSI::CreateObject();

    AddInt32PropertyInLite(keyAlg, "HUKS_ALG_AES", HKS_ALG_AES);
    AddInt32PropertyInLite(keyAlg, "HUKS_ALG_DES", HKS_ALG_DES);
    AddInt32PropertyInLite(keyAlg, "HUKS_ALG_3DES", HKS_ALG_3DES);

    AddInt32PropertyInLite(keyAlg, "HUKS_ALG_HMAC", HKS_ALG_HMAC);
    AddInt32PropertyInLite(keyAlg, "HUKS_ALG_CMAC", HKS_ALG_CMAC);

    AddInt32PropertyInLite(keyAlg, "HUKS_ALG_RSA", HKS_ALG_RSA);

    return keyAlg;
}

static JSIValue CreateHuksKeyFlag(void)
{
    JSIValue keyFlag = JSI::CreateObject();

    AddInt32PropertyInLite(keyFlag, "HUKS_KEY_FLAG_IMPORT_KEY", HKS_KEY_FLAG_IMPORT_KEY);
    AddInt32PropertyInLite(keyFlag, "HUKS_KEY_FLAG_GENERATE_KEY", HKS_KEY_FLAG_GENERATE_KEY);
    AddInt32PropertyInLite(keyFlag, "HUKS_KEY_FLAG_AGREE_KEY", HKS_KEY_FLAG_AGREE_KEY);
    AddInt32PropertyInLite(keyFlag, "HUKS_KEY_FLAG_DERIVE_KEY", HKS_KEY_FLAG_DERIVE_KEY);

    return keyFlag;
}

static JSIValue CreateHuksKeyStorageType(void)
{
    JSIValue keyStorageType = JSI::CreateObject();

    AddInt32PropertyInLite(keyStorageType, "HUKS_STORAGE_TEMP", HKS_STORAGE_TEMP);
    AddInt32PropertyInLite(keyStorageType, "HUKS_STORAGE_PERSISTENT", HKS_STORAGE_PERSISTENT);

    return keyStorageType;
}

static JSIValue CreateHuksTagType(void)
{
    JSIValue tagType = JSI::CreateObject();

    AddInt32PropertyInLite(tagType, "HUKS_TAG_TYPE_INVALID", HKS_TAG_TYPE_INVALID);
    AddInt32PropertyInLite(tagType, "HUKS_TAG_TYPE_INT", HKS_TAG_TYPE_INT);
    AddInt32PropertyInLite(tagType, "HUKS_TAG_TYPE_UINT", HKS_TAG_TYPE_UINT);
    AddInt32PropertyInLite(tagType, "HUKS_TAG_TYPE_ULONG", HKS_TAG_TYPE_ULONG);
    AddInt32PropertyInLite(tagType, "HUKS_TAG_TYPE_BOOL", HKS_TAG_TYPE_BOOL);
    AddInt32PropertyInLite(tagType, "HUKS_TAG_TYPE_BYTES", HKS_TAG_TYPE_BYTES);

    return tagType;
}

static void AddHuksTagPart1(JSIValue tag)
{
    AddInt32PropertyInLite(tag, "HUKS_TAG_INVALID", HKS_TAG_INVALID);

    AddInt32PropertyInLite(tag, "HUKS_TAG_ALGORITHM", HKS_TAG_ALGORITHM);
    AddInt32PropertyInLite(tag, "HUKS_TAG_PURPOSE", HKS_TAG_PURPOSE);
    AddInt32PropertyInLite(tag, "HUKS_TAG_KEY_SIZE", HKS_TAG_KEY_SIZE);
    AddInt32PropertyInLite(tag, "HUKS_TAG_PADDING", HKS_TAG_PADDING);
    AddInt32PropertyInLite(tag, "HUKS_TAG_BLOCK_MODE", HKS_TAG_BLOCK_MODE);
    AddInt32PropertyInLite(tag, "HUKS_TAG_KEY_TYPE", HKS_TAG_KEY_TYPE);
    AddInt32PropertyInLite(tag, "HUKS_TAG_ASSOCIATED_DATA", HKS_TAG_ASSOCIATED_DATA);
    AddInt32PropertyInLite(tag, "HUKS_TAG_NONCE", HKS_TAG_NONCE);
    AddInt32PropertyInLite(tag, "HUKS_TAG_IV", HKS_TAG_IV);

    AddInt32PropertyInLite(tag, "HUKS_TAG_INFO", HKS_TAG_INFO);
    AddInt32PropertyInLite(tag, "HUKS_TAG_PWD", HKS_TAG_PWD);

    AddInt32PropertyInLite(tag, "HUKS_TAG_KEY_GENERATE_TYPE", HKS_TAG_KEY_GENERATE_TYPE);
    AddInt32PropertyInLite(tag, "HUKS_TAG_KEY_ALIAS", HKS_TAG_KEY_ALIAS);

    AddInt32PropertyInLite(tag, "HUKS_TAG_ORIGINATION_EXPIRE_DATETIME", HKS_TAG_ORIGINATION_EXPIRE_DATETIME);

    AddInt32PropertyInLite(tag, "HUKS_TAG_USAGE_EXPIRE_DATETIME", HKS_TAG_USAGE_EXPIRE_DATETIME);

    AddInt32PropertyInLite(tag, "HUKS_TAG_CREATION_DATETIME", HKS_TAG_CREATION_DATETIME);
}

static void AddHuksTagPart2(JSIValue tag)
{
    AddInt32PropertyInLite(tag, "HUKS_TAG_IS_KEY_ALIAS", HKS_TAG_IS_KEY_ALIAS);
    AddInt32PropertyInLite(tag, "HUKS_TAG_KEY_STORAGE_FLAG", HKS_TAG_KEY_STORAGE_FLAG);
    AddInt32PropertyInLite(tag, "HUKS_TAG_KEY_FLAG", HKS_TAG_KEY_FLAG);

    AddInt32PropertyInLite(tag, "HUKS_TAG_SECURE_KEY_ALIAS", HKS_TAG_SECURE_KEY_ALIAS);

    AddInt32PropertyInLite(tag, "HUKS_TAG_KEY_DOMAIN", HKS_TAG_KEY_DOMAIN);

    AddInt32PropertyInLite(tag, "HUKS_TAG_PROCESS_NAME", HKS_TAG_PROCESS_NAME);

    AddInt32PropertyInLite(tag, "HUKS_TAG_KEY", HKS_TAG_KEY);
    AddInt32PropertyInLite(tag, "HUKS_TAG_AE_TAG", HKS_TAG_AE_TAG);
    AddInt32PropertyInLite(tag, "HUKS_TAG_IS_KEY_HANDLE", HKS_TAG_IS_KEY_HANDLE);

    AddInt32PropertyInLite(tag, "HUKS_TAG_OS_VERSION", HKS_TAG_OS_VERSION);
    AddInt32PropertyInLite(tag, "HUKS_TAG_OS_PATCHLEVEL", HKS_TAG_OS_PATCHLEVEL);

    AddInt32PropertyInLite(tag, "HUKS_TAG_SYMMETRIC_KEY_DATA", HKS_TAG_SYMMETRIC_KEY_DATA);
}

static void AddHuksTagPart3(JSIValue tag)
{
    AddInt32PropertyInLite(tag, "HUKS_TAG_DIGEST", HKS_TAG_DIGEST);
    AddInt32PropertyInLite(tag, "HUKS_TAG_RSA_PSS_SALT_LEN_TYPE", HKS_TAG_RSA_PSS_SALT_LEN_TYPE);
    AddInt32PropertyInLite(tag, "HUKS_TAG_IMPORT_KEY_TYPE", HKS_TAG_IMPORT_KEY_TYPE);
}

static JSIValue CreateHuksTag(void)
{
    JSIValue tag = JSI::CreateObject();

    AddHuksTagPart1(tag);
    AddHuksTagPart2(tag);
    AddHuksTagPart3(tag);

    return tag;
}

static JSIValue CreateHuksKeyDigest()
{
    JSIValue keyDigest = JSI::CreateObject();

    AddInt32PropertyInLite(keyDigest, "HUKS_DIGEST_NONE", HKS_DIGEST_NONE);
    AddInt32PropertyInLite(keyDigest, "HUKS_DIGEST_SHA1", HKS_DIGEST_SHA1);
    AddInt32PropertyInLite(keyDigest, "HUKS_DIGEST_SHA256", HKS_DIGEST_SHA256);

    return keyDigest;
}

static JSIValue CreateHuksImportKeyType()
{
    JSIValue importKeyType = JSI::CreateObject();

    AddInt32PropertyInLite(importKeyType, "HUKS_KEY_TYPE_PUBLIC_KEY", HKS_KEY_TYPE_PUBLIC_KEY);
    AddInt32PropertyInLite(importKeyType, "HUKS_KEY_TYPE_PRIVATE_KEY", HKS_KEY_TYPE_PRIVATE_KEY);
    AddInt32PropertyInLite(importKeyType, "HUKS_KEY_TYPE_KEY_PAIR", HKS_KEY_TYPE_KEY_PAIR);

    return importKeyType;
}

static JSIValue CreateHuksRsaPssSaltLenType()
{
    JSIValue rsaPssSaltLenType = JSI::CreateObject();

    AddInt32PropertyInLite(rsaPssSaltLenType, "HUKS_RSA_PSS_SALT_LEN_DIGEST", HKS_RSA_PSS_SALTLEN_DIGEST);
    AddInt32PropertyInLite(rsaPssSaltLenType, "HUKS_RSA_PSS_SALT_LEN_MAX", HKS_RSA_PSS_SALTLEN_MAX);

    return rsaPssSaltLenType;
}

static void InitHuksModuleEnum(JSIValue exports)
{
    JSI::SetNamedProperty(exports, "HuksExceptionErrCode", CreateHuksErrCode());
    JSI::SetNamedProperty(exports, "HuksKeyPurpose", CreateHuksKeyPurpose());
    JSI::SetNamedProperty(exports, "HuksKeyPadding", CreateHuksKeyPadding());
    JSI::SetNamedProperty(exports, "HuksCipherMode", CreateHuksCipherMode());
    JSI::SetNamedProperty(exports, "HuksKeySize", CreateHuksKeySize());
    JSI::SetNamedProperty(exports, "HuksKeyAlg", CreateHuksKeyAlg());
    JSI::SetNamedProperty(exports, "HuksKeyFlag", CreateHuksKeyFlag());
    JSI::SetNamedProperty(exports, "HuksKeyStorageType", CreateHuksKeyStorageType());
    JSI::SetNamedProperty(exports, "HuksTagType", CreateHuksTagType());
    JSI::SetNamedProperty(exports, "HuksTag", CreateHuksTag());
    JSI::SetNamedProperty(exports, "HuksKeyDigest", CreateHuksKeyDigest());
    JSI::SetNamedProperty(exports, "HuksImportKeyType", CreateHuksImportKeyType());
    JSI::SetNamedProperty(exports, "HuksRsaPssSaltLenType", CreateHuksRsaPssSaltLenType());
}

void InitHuksModule(JSIValue exports)
{
    JSI::SetModuleAPI(exports, "generateKeyItem", HksLiteModule::generateKeyItem);
    JSI::SetModuleAPI(exports, "deleteKeyItem", HksLiteModule::deleteKeyItem);
    JSI::SetModuleAPI(exports, "isKeyItemExist", HksLiteModule::isKeyItemExist);
    JSI::SetModuleAPI(exports, "hasKeyItem", HksLiteModule::hasKeyItem);
    JSI::SetModuleAPI(exports, "importKeyItem", HksLiteModule::importKeyItem);
    JSI::SetModuleAPI(exports, "exportKeyItem", HksLiteModule::exportKeyItem);
    JSI::SetModuleAPI(exports, "getKeyProperties", HksLiteModule::getKeyProperties);
    JSI::SetModuleAPI(exports, "importWrappedKeyItem", HksLiteModule::importWrappedKeyItem);

    JSI::SetModuleAPI(exports, "initSession", HksLiteModule::initSession);
    JSI::SetModuleAPI(exports, "updateSession", HksLiteModule::updateSession);
    JSI::SetModuleAPI(exports, "finishSession", HksLiteModule::finishSession);
    JSI::SetModuleAPI(exports, "abortSession", HksLiteModule::abortSession);

    InitHuksModuleEnum(exports);
}
} // namespace ACELite
} // namespace OHOS
