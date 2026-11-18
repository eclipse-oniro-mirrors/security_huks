/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "hks_permission_check.h"
#include "hks_log.h"

using namespace testing::ext;
namespace Unittest::HksPermissionCheckTest {
class HksPermissionCheckTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksPermissionCheckTest::SetUpTestCase(void)
{
}

void HksPermissionCheckTest::TearDownTestCase(void)
{
}

void HksPermissionCheckTest::SetUp()
{
}

void HksPermissionCheckTest::TearDown()
{
}

/**
 * @tc.name: HksPermissionCheckTest.HksPermissionCheckTest001
 * @tc.desc: tdd SensitivePermissionCheck
 * @tc.type: FUNC
 */
HWTEST_F(HksPermissionCheckTest, HksPermissionCheckTest001, TestSize.Level0)
{
    const char permission[] = "test_permission";
    int32_t ret = SensitivePermissionCheck(permission);
    EXPECT_EQ(ret, HKS_ERROR_NO_PERMISSION);
}

/**
 * @tc.name: HksPermissionCheckTest.HksPermissionCheckTest002
 * @tc.desc: tdd SystemApiPermissionCheck
 * @tc.type: FUNC
 */
HWTEST_F(HksPermissionCheckTest, HksPermissionCheckTest002, TestSize.Level0)
{
    int32_t ret = SystemApiPermissionCheck(0);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksPermissionCheckTest.HksPermissionCheckTest003
 * @tc.desc: tdd HksCheckAcrossAccountsPermission
 * @tc.type: FUNC
 */
HWTEST_F(HksPermissionCheckTest, HksPermissionCheckTest003, TestSize.Level0)
{
    int32_t ret = HksCheckAcrossAccountsPermission(nullptr, 0);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

#ifdef HKS_UKEY_EXTENSION_CRYPTO
/**
 * @tc.name: HksPermissionCheckTest.IsTrustedUkeySaCaller
 * @tc.desc: tdd HksIsTrustedUkeySaCaller with known and unknown uids
 * @tc.type: FUNC
 */
HWTEST_F(HksPermissionCheckTest, IsTrustedUkeySaCaller, TestSize.Level0)
{
    HKS_LOG_I("enter IsTrustedUkeySaCaller");
    EXPECT_TRUE(HksIsTrustedUkeySaCaller(3515));
    EXPECT_TRUE(HksIsTrustedUkeySaCaller(7058));
    EXPECT_FALSE(HksIsTrustedUkeySaCaller(12345));
    EXPECT_FALSE(HksIsTrustedUkeySaCaller(0));
}

/**
 * @tc.name: HksPermissionCheckTest.CheckUkeyCertCallerNull
 * @tc.desc: tdd CheckUkeyCertCaller with null processInfo returns INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksPermissionCheckTest, CheckUkeyCertCallerNull, TestSize.Level0)
{
    HKS_LOG_I("enter CheckUkeyCertCallerNull");
    EXPECT_EQ(CheckUkeyCertCaller(nullptr), HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksPermissionCheckTest.CheckUkeyCertCallerUntrusted
 * @tc.desc: tdd CheckUkeyCertCaller with untrusted uid returns NO_PERMISSION
 * @tc.type: FUNC
 */
HWTEST_F(HksPermissionCheckTest, CheckUkeyCertCallerUntrusted, TestSize.Level0)
{
    HKS_LOG_I("enter CheckUkeyCertCallerUntrusted");
    struct HksProcessInfo info = HKS_PROCESS_INFO_INIT_VALUE;
    info.uidInt = 12345;
    EXPECT_EQ(CheckUkeyCertCaller(&info), HKS_ERROR_NO_PERMISSION);
}

/**
 * @tc.name: HksPermissionCheckTest.CheckUkeyCertCallerTrusted
 * @tc.desc: tdd CheckUkeyCertCaller with trusted uid returns SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksPermissionCheckTest, CheckUkeyCertCallerTrusted, TestSize.Level0)
{
    HKS_LOG_I("enter CheckUkeyCertCallerTrusted");
    struct HksProcessInfo info = HKS_PROCESS_INFO_INIT_VALUE;
    info.uidInt = 3515;
    EXPECT_EQ(CheckUkeyCertCaller(&info), HKS_SUCCESS);
}

/**
 * @tc.name: HksPermissionCheckTest.HksCheckUkeyPermission
 * @tc.desc: tdd HksCheckUkeyPermission with non-granted permission
 * @tc.type: FUNC
 */
HWTEST_F(HksPermissionCheckTest, HksCheckUkeyPermission, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckUkeyPermission");
    EXPECT_EQ(HksCheckUkeyPermission("test_ukey_permission"), HKS_ERROR_NO_PERMISSION);
}

/**
 * @tc.name: HksPermissionCheckTest.CheckUkeyAuthPinType
 * @tc.desc: tdd CheckUkeyAuthPinType
 * @tc.type: FUNC
 */
HWTEST_F(HksPermissionCheckTest, CheckUkeyAuthPinType, TestSize.Level0)
{
    HKS_LOG_I("enter CheckUkeyAuthPinType");
    int32_t ret = CheckUkeyAuthPinType();
    EXPECT_TRUE(ret == HKS_SUCCESS || ret == HKS_ERROR_NOT_SYSTEM_APP ||
        ret == HKS_ERROR_INVALID_ACCESS_TYPE);
}
#endif
}
