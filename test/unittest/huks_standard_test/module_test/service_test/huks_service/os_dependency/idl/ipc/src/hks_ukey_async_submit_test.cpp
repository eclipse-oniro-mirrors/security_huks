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

#include "hks_ukey_async_submit.h"
#include "hks_log.h"
#include "huks_service_ipc_interface_code.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace Hks {
class HksUkeyAsyncSubmitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksUkeyAsyncSubmitTest::SetUpTestCase(void)
{
}

void HksUkeyAsyncSubmitTest::TearDownTestCase(void)
{
}

void HksUkeyAsyncSubmitTest::SetUp()
{
}

void HksUkeyAsyncSubmitTest::TearDown()
{
}

/**
 * @tc.name: HksUkeyAsyncSubmitTest.IsUkeyStandardMsgCodeNonUkey
 * @tc.desc: tdd HksIsUkeyStandardMsgCode with non-standard codes returns false
 * @tc.type: FUNC
 */
HWTEST_F(HksUkeyAsyncSubmitTest, IsUkeyStandardMsgCodeNonUkey, TestSize.Level0)
{
    HKS_LOG_I("enter IsUkeyStandardMsgCodeNonUkey");
    struct HksBlob srcData = { 0, nullptr };
    EXPECT_FALSE(HksIsUkeyStandardMsgCode(HKS_MSG_SIGN, srcData));
    EXPECT_FALSE(HksIsUkeyStandardMsgCode(HKS_MSG_VERIFY, srcData));
    EXPECT_FALSE(HksIsUkeyStandardMsgCode(HKS_MSG_EXT_AUTH_UKEY_PIN, srcData));
    EXPECT_FALSE(HksIsUkeyStandardMsgCode(HKS_MSG_MAX, srcData));
}

/**
 * @tc.name: HksUkeyAsyncSubmitTest.IsUkeyStandardMsgCodeEmptyData
 * @tc.desc: tdd HksIsUkeyStandardMsgCode with standard codes but empty srcData returns false
 * @tc.type: FUNC
 */
HWTEST_F(HksUkeyAsyncSubmitTest, IsUkeyStandardMsgCodeEmptyData, TestSize.Level0)
{
    HKS_LOG_I("enter IsUkeyStandardMsgCodeEmptyData");
    struct HksBlob srcData = { 0, nullptr };
    EXPECT_FALSE(HksIsUkeyStandardMsgCode(HKS_MSG_GEN_KEY, srcData));
    EXPECT_FALSE(HksIsUkeyStandardMsgCode(HKS_MSG_EXPORT_PUBLIC_KEY, srcData));
    EXPECT_FALSE(HksIsUkeyStandardMsgCode(HKS_MSG_IMPORT_WRAPPED_KEY, srcData));
    EXPECT_FALSE(HksIsUkeyStandardMsgCode(HKS_MSG_INIT, srcData));
    EXPECT_FALSE(HksIsUkeyStandardMsgCode(HKS_MSG_UPDATE, srcData));
    EXPECT_FALSE(HksIsUkeyStandardMsgCode(HKS_MSG_FINISH, srcData));
    EXPECT_FALSE(HksIsUkeyStandardMsgCode(HKS_MSG_ABORT, srcData));
}
} // namespace Hks
} // namespace Security
} // namespace OHOS