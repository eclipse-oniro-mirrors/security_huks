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

#ifndef HKS_SM2_SIGN_VERIFY_TEST_H
#define HKS_SM2_SIGN_VERIFY_TEST_H

#include <string>
#include <vector>
#include "hks_in_data_array_after_hash_test_common.h"
#include "hks_three_stage_test_common.h"
namespace Unittest::Sm2SignVerify {
#ifdef _USE_OPENSSL_
static const std::string g_inData = "Hks_SM2_Sign_Verify_Test_0000000000000000000000000000000000000000000000000000000"
                                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";
static const uint32_t SM2_COMMON_SIZE = 1024;

struct GenerateKeyCaseParam {
    uint32_t id;
    int32_t result;
    std::vector<struct HksParam> params;
};

int HksSm2SignVerifyTest001(void);

int HksSm2SignVerifyTest002(void);

int HksSm2SignVerifyTest003(void);
#endif
}
#endif // HKS_SM2_SIGN_VERIFY_TEST_H

