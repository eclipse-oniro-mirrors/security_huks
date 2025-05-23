/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <openssl/rsa.h>
#include "hks_log.h"
#include "hks_rsa_common_mt.h"

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace Huks {
namespace MT {
namespace {
const int SET_SIZE_4096 = 4096;

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const int KEY_SIZE_512 = 512;
const int KEY_SIZE_768 = 768;
const int KEY_SIZE_1024 = 1024;
#endif

const int KEY_SIZE_2048 = 2048;
const int KEY_SIZE_3072 = 3072;

const SignLocalCaseParams HKS_RSA_MT_26500_PARAMS = {
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const SignServiceCaseParams HKS_RSA_MT_26600_PARAMS = {
    .alias = "This is a test auth id for NONE",
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};
#endif

const VerifyLocalCaseParams HKS_RSA_MT_26700_PARAMS = {
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const VerifyServiceCaseParams HKS_RSA_MT_26800_PARAMS = {
    .alias = "This is a test auth id for NONE",
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_512 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .keySize = KEY_SIZE_512,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};
#endif

const SignLocalCaseParams HKS_RSA_MT_26900_PARAMS = {
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const SignServiceCaseParams HKS_RSA_MT_27000_PARAMS = {
    .alias = "This is a test auth id for NONE",
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};
#endif

const VerifyLocalCaseParams HKS_RSA_MT_27100_PARAMS = {
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const VerifyServiceCaseParams HKS_RSA_MT_27200_PARAMS = {
    .alias = "This is a test auth id for NONE",
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_768 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .keySize = KEY_SIZE_768,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};
#endif

const SignLocalCaseParams HKS_RSA_MT_27300_PARAMS = {
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const SignServiceCaseParams HKS_RSA_MT_27400_PARAMS = {
    .alias = "This is a test auth id for NONE",
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};
#endif

const VerifyLocalCaseParams HKS_RSA_MT_27500_PARAMS = {
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const VerifyServiceCaseParams HKS_RSA_MT_27600_PARAMS = {
    .alias = "This is a test auth id for NONE",
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .keySize = KEY_SIZE_1024,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};
#endif

const SignLocalCaseParams HKS_RSA_MT_27700_PARAMS = {
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const SignServiceCaseParams HKS_RSA_MT_27800_PARAMS = {
    .alias = "This is a test auth id for NONE",
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const VerifyLocalCaseParams HKS_RSA_MT_27900_PARAMS = {
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const VerifyServiceCaseParams HKS_RSA_MT_28000_PARAMS = {
    .alias = "This is a test auth id for NONE",
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .keySize = KEY_SIZE_2048,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const SignLocalCaseParams HKS_RSA_MT_28100_PARAMS = {
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const SignServiceCaseParams HKS_RSA_MT_28200_PARAMS = {
    .alias = "This is a test auth id for NONE",
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const VerifyLocalCaseParams HKS_RSA_MT_28300_PARAMS = {
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const VerifyServiceCaseParams HKS_RSA_MT_28400_PARAMS = {
    .alias = "This is a test auth id for NONE",
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .keySize = KEY_SIZE_3072,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const SignLocalCaseParams HKS_RSA_MT_28500_PARAMS = {
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const SignServiceCaseParams HKS_RSA_MT_28600_PARAMS = {
    .alias = "This is a test auth id for NONE",
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const VerifyLocalCaseParams HKS_RSA_MT_28700_PARAMS = {
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = false },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const VerifyServiceCaseParams HKS_RSA_MT_28800_PARAMS = {
    .alias = "This is a test auth id for NONE",
    .params =
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .padding = RSA_PKCS1_PADDING,
    .keyDigest = HKS_DIGEST_NONE,
    .keySize = SET_SIZE_4096,
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};
}  // namespace

class HksRsaNoneWithRsaMt : public HksRsaCommonMt, public testing::Test {
public:
    static void SetUpTestCase(void)
    {
    }

    static void TearDownTestCase(void)
    {
    }
};

/**
 * @tc.number    : HksRsaNoneWithRsaMt26500
 * @tc.name      : HksRsaNoneWithRsaMt26500
 * @tc.desc      : Test huks sign (512/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt26500, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt26500");
    SignLocalTestCase(HKS_RSA_MT_26500_PARAMS);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksRsaNoneWithRsaMt26600
 * @tc.name      : HksRsaNoneWithRsaMt26600
 * @tc.desc      : Test huks sign (512/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt26600, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt26600");
    SignServiceTestCase(HKS_RSA_MT_26600_PARAMS);
}
#endif

/**
 * @tc.number    : HksRsaNoneWithRsaMt26700
 * @tc.name      : HksRsaNoneWithRsaMt26700
 * @tc.desc      : Test huks Verify (512/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt26700, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt26700");
    VerifyLocalTestCase(HKS_RSA_MT_26700_PARAMS);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksRsaNoneWithRsaMt26800
 * @tc.name      : HksRsaNoneWithRsaMt26800
 * @tc.desc      : Test huks Verify (512/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt26800, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt26800");
    VerifyServiceTestCase(HKS_RSA_MT_26800_PARAMS);
}
#endif

/**
 * @tc.number    : HksRsaNoneWithRsaMt26900
 * @tc.name      : HksRsaNoneWithRsaMt26900
 * @tc.desc      : Test huks sign (768/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt26900, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt26900");
    SignLocalTestCase(HKS_RSA_MT_26900_PARAMS);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksRsaNoneWithRsaMt27000
 * @tc.name      : HksRsaNoneWithRsaMt27000
 * @tc.desc      : Test huks sign (768/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt27000, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt27000");
    SignServiceTestCase(HKS_RSA_MT_27000_PARAMS);
}
#endif

/**
 * @tc.number    : HksRsaNoneWithRsaMt27100
 * @tc.name      : HksRsaNoneWithRsaMt27100
 * @tc.desc      : Test huks Verify (768/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt27100, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt27100");
    VerifyLocalTestCase(HKS_RSA_MT_27100_PARAMS);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksRsaNoneWithRsaMt27200
 * @tc.name      : HksRsaNoneWithRsaMt27200
 * @tc.desc      : Test huks Verify (768/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt27200, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt27200");
    VerifyServiceTestCase(HKS_RSA_MT_27200_PARAMS);
}
#endif

/**
 * @tc.number    : HksRsaNoneWithRsaMt27300
 * @tc.name      : HksRsaNoneWithRsaMt27300
 * @tc.desc      : Test huks sign (1024/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt27300, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt27300");
    SignLocalTestCase(HKS_RSA_MT_27300_PARAMS);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksRsaNoneWithRsaMt27400
 * @tc.name      : HksRsaNoneWithRsaMt27400
 * @tc.desc      : Test huks sign (1024/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt27400, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt27400");
    SignServiceTestCase(HKS_RSA_MT_27400_PARAMS);
}
#endif

/**
 * @tc.number    : HksRsaNoneWithRsaMt27500
 * @tc.name      : HksRsaNoneWithRsaMt27500
 * @tc.desc      : Test huks Verify (1024/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt27500, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt27500");
    VerifyLocalTestCase(HKS_RSA_MT_27500_PARAMS);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksRsaNoneWithRsaMt27600
 * @tc.name      : HksRsaNoneWithRsaMt27600
 * @tc.desc      : Test huks Verify (1024/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt27600, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt27600");
    VerifyServiceTestCase(HKS_RSA_MT_27600_PARAMS);
}
#endif

/**
 * @tc.number    : HksRsaNoneWithRsaMt27700
 * @tc.name      : HksRsaNoneWithRsaMt27700
 * @tc.desc      : Test huks sign (2048/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt27700, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt27700");
    SignLocalTestCase(HKS_RSA_MT_27700_PARAMS);
}

/**
 * @tc.number    : HksRsaNoneWithRsaMt27800
 * @tc.name      : HksRsaNoneWithRsaMt27800
 * @tc.desc      : Test huks sign (2048/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt27800, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt27800");
    SignServiceTestCase(HKS_RSA_MT_27800_PARAMS);
}

/**
 * @tc.number    : HksRsaNoneWithRsaMt27900
 * @tc.name      : HksRsaNoneWithRsaMt27900
 * @tc.desc      : Test huks Verify (2048/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt27900, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt27900");
    VerifyLocalTestCase(HKS_RSA_MT_27900_PARAMS);
}

/**
 * @tc.number    : HksRsaNoneWithRsaMt28000
 * @tc.name      : HksRsaNoneWithRsaMt28000
 * @tc.desc      : Test huks Verify (2048/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt28000, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt28000");
    VerifyServiceTestCase(HKS_RSA_MT_28000_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksRsaNoneWithRsaMt28100
 * @tc.name      : HksRsaNoneWithRsaMt28100
 * @tc.desc      : Test huks sign (3072/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt28100, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt28100");
    SignLocalTestCase(HKS_RSA_MT_28100_PARAMS);
}

/**
 * @tc.number    : HksRsaNoneWithRsaMt28200
 * @tc.name      : HksRsaNoneWithRsaMt28200
 * @tc.desc      : Test huks sign (3072/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt28200, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt28200");
    SignServiceTestCase(HKS_RSA_MT_28200_PARAMS);
}

/**
 * @tc.number    : HksRsaNoneWithRsaMt28300
 * @tc.name      : HksRsaNoneWithRsaMt28300
 * @tc.desc      : Test huks Verify (3072/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt28300, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt28300");
    VerifyLocalTestCase(HKS_RSA_MT_28300_PARAMS);
}

/**
 * @tc.number    : HksRsaNoneWithRsaMt28400
 * @tc.name      : HksRsaNoneWithRsaMt28400
 * @tc.desc      : Test huks Verify (3072/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt28400, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt28400");
    VerifyServiceTestCase(HKS_RSA_MT_28400_PARAMS);
}

/**
 * @tc.number    : HksRsaNoneWithRsaMt28500
 * @tc.name      : HksRsaNoneWithRsaMt28500
 * @tc.desc      : Test huks sign (4096/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt28500, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt28500");
    SignLocalTestCase(HKS_RSA_MT_28500_PARAMS);
}

/**
 * @tc.number    : HksRsaNoneWithRsaMt28600
 * @tc.name      : HksRsaNoneWithRsaMt28600
 * @tc.desc      : Test huks sign (4096/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt28600, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt28600");
    SignServiceTestCase(HKS_RSA_MT_28600_PARAMS);
}

/**
 * @tc.number    : HksRsaNoneWithRsaMt28700
 * @tc.name      : HksRsaNoneWithRsaMt28700
 * @tc.desc      : Test huks Verify (4096/NONEwithRSA/TEMP)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt28700, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt28700");
    VerifyLocalTestCase(HKS_RSA_MT_28700_PARAMS);
}

/**
 * @tc.number    : HksRsaNoneWithRsaMt28800
 * @tc.name      : HksRsaNoneWithRsaMt28800
 * @tc.desc      : Test huks Verify (4096/NONEwithRSA/PERSISTENT)
 */
HWTEST_F(HksRsaNoneWithRsaMt, HksRsaNoneWithRsaMt28800, TestSize.Level1)
{
    HKS_LOG_E(" Enter HksRsaNoneWithRsaMt28800");
    VerifyServiceTestCase(HKS_RSA_MT_28800_PARAMS);
}
#endif
}  // namespace MT
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS