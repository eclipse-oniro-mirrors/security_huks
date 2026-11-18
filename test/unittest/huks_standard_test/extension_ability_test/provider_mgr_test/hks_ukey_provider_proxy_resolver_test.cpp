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

#include "hks_ukey_provider_proxy_resolver.h"
#include "hks_ukey_common.h"
#include "hks_error_code.h"
#include "ihuks_access_ext_base.h"
#include "iremote_object.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace Huks {

class HksProviderProxyResolverTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void HksProviderProxyResolverTest::SetUpTestCase(void) {}
void HksProviderProxyResolverTest::TearDownTestCase(void) {}
void HksProviderProxyResolverTest::SetUp() {}
void HksProviderProxyResolverTest::TearDown() {}

/**
 * @tc.name: HksProviderProxyResolverTest.HksProviderProxyResolverTest001
 * @tc.desc: HksGetProviderProxyResolver returns a non-null singleton resolver.
 * @tc.type: FUNC
 */
HWTEST_F(HksProviderProxyResolverTest, HksProviderProxyResolverTest001, TestSize.Level0)
{
    auto resolver = HksGetProviderProxyResolver();
    EXPECT_NE(resolver, nullptr);
}

/**
 * @tc.name: HksProviderProxyResolverTest.HksProviderProxyResolverTest002
 * @tc.desc: GetProxy with a provider that is not registered returns not-exist.
 * @tc.type: FUNC
 */
HWTEST_F(HksProviderProxyResolverTest, HksProviderProxyResolverTest002, TestSize.Level0)
{
    auto resolver = HksGetProviderProxyResolver();
    ASSERT_NE(resolver, nullptr);

    ProviderInfo info{};
    info.m_providerName = "nonexistent.provider";
    info.m_bundleName = "nonexistent.bundle";
    info.m_abilityName = "nonexistent.ability";
    info.m_userid = 0;

    sptr<IHuksAccessExtBase> proxy = nullptr;
    int32_t ret = resolver->GetProxy(info, proxy);
    EXPECT_NE(ret, HKS_SUCCESS);
    EXPECT_EQ(proxy, nullptr);
}

} // namespace Huks
} // namespace Security
} // namespace OHOS
