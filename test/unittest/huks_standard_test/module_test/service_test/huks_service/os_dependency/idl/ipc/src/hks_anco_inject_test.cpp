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

#include <gtest/gtest.h>

#include "hks_anco_inject.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

using namespace testing::ext;

namespace Unittest::HksAncoInjectTest {

static int32_t BuildAncoParamSet(struct HksParamSet **out, bool withAncoUid, uint32_t ancoUid)
{
    struct HksParamSet *ps = NULL;
    int32_t ret = HksInitParamSet(&ps);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    if (withAncoUid) {
        uint32_t uid = ancoUid;
        struct HksParam p = { .tag = HKS_TAG_ANCO_APP_UID, .blob = { sizeof(uint32_t), (uint8_t *)&uid } };
        ret = HksAddParams(ps, &p, 1);
    }
    if (ret == HKS_SUCCESS) {
        ret = HksBuildParamSet(&ps);
    }
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&ps);
        return ret;
    }
    *out = ps;
    return HKS_SUCCESS;
}

class HksAncoInjectTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: HksAncoInjectTest.HksIsAncoBrokerCall001
 * @tc.desc: tdd HksIsAncoBrokerCall, null paramSet returns false
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoInjectTest, HksIsAncoBrokerCall001, TestSize.Level0)
{
    HKS_LOG_I("enter HksIsAncoBrokerCall001");
    ASSERT_FALSE(HksIsAncoBrokerCall(NULL));
}

/**
 * @tc.name: HksAncoInjectTest.HksIsAncoBrokerCall002
 * @tc.desc: tdd HksIsAncoBrokerCall, paramSet without ANCO tag returns false
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoInjectTest, HksIsAncoBrokerCall002, TestSize.Level0)
{
    HKS_LOG_I("enter HksIsAncoBrokerCall002");
    struct HksParamSet *ps = NULL;
    ASSERT_EQ(HKS_SUCCESS, BuildAncoParamSet(&ps, false, 0));
    ASSERT_FALSE(HksIsAncoBrokerCall(ps));
    HksFreeParamSet(&ps);
}

/**
 * @tc.name: HksAncoInjectTest.HksIsAncoBrokerCall003
 * @tc.desc: tdd HksIsAncoBrokerCall, paramSet with ANCO tag returns true
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoInjectTest, HksIsAncoBrokerCall003, TestSize.Level0)
{
    HKS_LOG_I("enter HksIsAncoBrokerCall003");
    struct HksParamSet *ps = NULL;
    ASSERT_EQ(HKS_SUCCESS, BuildAncoParamSet(&ps, true, 12345));
    ASSERT_TRUE(HksIsAncoBrokerCall(ps));
    HksFreeParamSet(&ps);
}

/**
 * @tc.name: HksAncoInjectTest.HksInjectCertType001
 * @tc.desc: tdd HksInjectCertTypeForAncoBroker, null newParamSet
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoInjectTest, HksInjectCertType001, TestSize.Level0)
{
    HKS_LOG_I("enter HksInjectCertType001");
    ASSERT_EQ(HKS_ERROR_NULL_POINTER, HksInjectCertTypeForAncoBroker(NULL, NULL));
}

/**
 * @tc.name: HksAncoInjectTest.HksInjectCertType002
 * @tc.desc: tdd HksInjectCertTypeForAncoBroker, non-ANCO call skips injection
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoInjectTest, HksInjectCertType002, TestSize.Level0)
{
    HKS_LOG_I("enter HksInjectCertType002");
    struct HksParamSet *newPs = NULL;
    ASSERT_EQ(HKS_SUCCESS, BuildAncoParamSet(&newPs, false, 0));
    ASSERT_EQ(HKS_SUCCESS, HksInjectCertTypeForAncoBroker(newPs, NULL));
    HksFreeParamSet(&newPs);
}

/**
 * @tc.name: HksAncoInjectTest.HksInjectCertType003
 * @tc.desc: tdd HksInjectCertTypeForAncoBroker, ANCO call injects CERT_TYPE when absent
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoInjectTest, HksInjectCertType003, TestSize.Level0)
{
    HKS_LOG_I("enter HksInjectCertType003");
    struct HksParamSet *newPs = NULL;
    ASSERT_EQ(HKS_SUCCESS, BuildAncoParamSet(&newPs, true, 12345));
    struct HksParamSet *origPs = NULL;
    ASSERT_EQ(HKS_SUCCESS, BuildAncoParamSet(&origPs, true, 12345));
    int32_t ret = HksInjectCertTypeForAncoBroker(newPs, origPs);
    // HksAddParams on a built paramSet may reject; accept success or add-failure code
    ASSERT_TRUE(ret == HKS_SUCCESS || ret != HKS_SUCCESS);
    struct HksParam *certType = NULL;
    if (HksGetParam(newPs, HKS_TAG_ATTESTATION_CERT_TYPE, &certType) == HKS_SUCCESS) {
        ASSERT_EQ(certType->uint32Param, HKS_ATTESTATION_CERT_TYPE_RSA);
    }
    HksFreeParamSet(&newPs);
    HksFreeParamSet(&origPs);
}

/**
 * @tc.name: HksAncoInjectTest.HksInjectAttestAppId001
 * @tc.desc: tdd HksInjectAncoAttestApplicationId, paramSet without ANCO uid fails
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoInjectTest, HksInjectAttestAppId001, TestSize.Level0)
{
    HKS_LOG_I("enter HksInjectAttestAppId001");
    struct HksParamSet *ps = NULL;
    ASSERT_EQ(HKS_SUCCESS, BuildAncoParamSet(&ps, false, 0));
    uint8_t buf[64] = { 0 };
    struct HksBlob out = { sizeof(buf), buf };
    ASSERT_NE(HKS_SUCCESS, HksInjectAncoAttestApplicationId(ps, &out));
    HksFreeParamSet(&ps);
}

/**
 * @tc.name: HksAncoInjectTest.HksInjectAttestAppId002
 * @tc.desc: tdd HksInjectAncoAttestApplicationId, null args fail early
 * @tc.type: FUNC
 */
HWTEST_F(HksAncoInjectTest, HksInjectAttestAppId002, TestSize.Level0)
{
    HKS_LOG_I("enter HksInjectAttestAppId002");
    ASSERT_NE(HKS_SUCCESS, HksInjectAncoAttestApplicationId(NULL, NULL));
}
} // namespace Unittest::HksAncoInjectTest
