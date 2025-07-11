/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "hks_curve25519_test.h"

#include "file_ex.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_curve25519.h"

using namespace testing::ext;
namespace {
class HksCurve25519Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksCurve25519Test::SetUpTestCase(void)
{
}

void HksCurve25519Test::TearDownTestCase(void)
{
}

void HksCurve25519Test::SetUp()
{
}

void HksCurve25519Test::TearDown()
{
    std::system("find /data/service/el1/public/huks_service -user root -delete");
}

/**
 * @tc.name: HksCurve25519Test.HksCurve25519Test001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksCurve25519Test, HksCurve25519Test001, TestSize.Level0)
{
    ASSERT_TRUE(TestCurve25519All() == 0);
}

/**
 * @tc.name: HksCurve25519Test.HksCurve25519Test002
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksCurve25519Test, HksCurve25519Test002, TestSize.Level0)
{
    ASSERT_TRUE(TestEd25519SignTeeVerifyLocal() == 0);
}

/**
 * @tc.name: HksCurve25519Test.HksCurve25519Test003
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksCurve25519Test, HksCurve25519Test003, TestSize.Level0)
{
    ASSERT_TRUE(TestCurve25519SignWrong() == 0);
}

/**
 * @tc.name: HksCurve25519Test.HksCurve25519Test004
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksCurve25519Test, HksCurve25519Test004, TestSize.Level0)
{
    ASSERT_TRUE(TestCurve25519verifyWrong() == 0);
}
}