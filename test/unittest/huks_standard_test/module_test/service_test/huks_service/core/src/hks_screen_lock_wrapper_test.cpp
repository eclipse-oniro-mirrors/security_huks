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

#include "screen_lock_wrapper.h"
#include "hks_type.h"

using namespace testing::ext;
namespace Unittest::HksScreenLockWrapperTest {
class HksScreenLockWrapperTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksScreenLockWrapperTest::SetUpTestCase(void)
{
}

void HksScreenLockWrapperTest::TearDownTestCase(void)
{
}

void HksScreenLockWrapperTest::SetUp()
{
}

void HksScreenLockWrapperTest::TearDown()
{
}

/**
 * @tc.name: HksScreenLockWrapperTest.HksScreenLockWrapperTest001
 * @tc.desc: test IsDeviceLocked with null pointer
 * @tc.type: FUNC
 */
HWTEST_F(HksScreenLockWrapperTest, HksScreenLockWrapperTest001, TestSize.Level0)
{
    int32_t ret = IsDeviceLocked(0, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "IsDeviceLocked should return invalid argument";
}

/**
 * @tc.name: HksScreenLockWrapperTest.HksScreenLockWrapperTest002
 * @tc.desc: test IsDeviceLocked with valid pointer
 * @tc.type: FUNC
 */
HWTEST_F(HksScreenLockWrapperTest, HksScreenLockWrapperTest002, TestSize.Level0)
{
    bool isDeviceLocked = false;
    int32_t ret = IsDeviceLocked(100, &isDeviceLocked);
    EXPECT_EQ(ret, HKS_SUCCESS) << "IsDeviceLocked should return success";
    EXPECT_EQ(isDeviceLocked, true) << "isDeviceLocked should be true";
}
}