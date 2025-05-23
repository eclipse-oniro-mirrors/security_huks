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

#ifndef HKS_RSA_COMMON_TEST_COMMON_H
#define HKS_RSA_COMMON_TEST_COMMON_H

#include <string>
#include "hks_three_stage_test_common.h"
namespace Unittest::RsaCipher {
static const uint32_t RSA_COMMON_SIZE = 1024;
static const uint32_t RSA_FLEX_KEY_SIZE_1536 = 1536;
static const uint32_t RSA_INVALID_FLEX_KEY_SIZE_1540 = 1540;
static const std::string g_inData_5   = "RSA_5";
static const std::string g_inData_12  = "RSA_12_ttttt";
static const std::string g_inData_14  = "RSA_14_ttttttt";
static const std::string g_inData_20  = "RSA_20_ttttttttttttt";
static const std::string g_inData_32  = "RSA_32_ttttttttttttttttttttttttt";
static const std::string g_inData_64  = "RSA_64_ttttttttttttttttttttttttttttttttttttttttttttttttttttttttt";
static const std::string g_inData_96  = "RSA_96_ttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttt";
static const std::string g_inData_128 = "RSA_128_tttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt";
static const std::string g_inData_192 = "RSA_192_tttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt";
static const std::string g_inData_256 = "RSA_256_tttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt";
static const std::string g_inData_384 = "RSA_384_tttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt";
static const std::string g_inData_512 = "RSA_512_tttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
                                        "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt";

static struct HksBlob inData_96 = {
    g_inData_96.length(),
    const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData_96.c_str()))
};
static struct HksBlob inData_192 = {
    g_inData_192.length(),
    const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData_192.c_str()))
};

int32_t HksRsaCipherTestCase(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet, const struct HksBlob *inData);
int32_t HksRsaCipherTestCaseAbnormal(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet, const struct HksBlob *inData);
int32_t HksRsaCipherTestEncrypt(const struct HksBlob *keyAlias, const struct HksParamSet *encryptParamSet,
    const struct HksBlob *inData, struct HksBlob *cipherText);
int32_t HksRsaCipherTestEncryptAbnormal(const struct HksBlob *keyAlias, const struct HksParamSet *encryptParamSet,
    const struct HksBlob *inData, struct HksBlob *cipherText);
int32_t HksRsaCipherTestDecrypt(const struct HksBlob *keyAlias, const struct HksParamSet *decryptParamSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText, const struct HksBlob *inData);
int32_t HksRsaCipherTest(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet, uint32_t purpose,
    const struct HksBlob *inData, struct HksBlob *outData);
} // namespace Unittest::RsaCipher
#endif // HKS_RSA_COMMON_TEST_COMMON_H
