/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "hks_storage_test.h"

#include <gtest/gtest.h>
#include <cstring>

#include "file_ex.h"
#include "hks_log.h"
#include "hks_type_inner.h"
#include "hks_param.h"

#include "base/security/huks/services/huks_standard/huks_service/main/hks_storage/src/hks_storage_utils.c"
#include "base/security/huks/services/huks_standard/huks_service/main/hks_storage/include/hks_storage.h"

using namespace testing::ext;
namespace Unittest::HksStorageTest {
class HksStorageTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksStorageTest::SetUpTestCase(void)
{
}

void HksStorageTest::TearDownTestCase(void)
{
}

void HksStorageTest::SetUp()
{
}

void HksStorageTest::TearDown()
{
}

/**
 * @tc.name: HksStorageTest.HksStorageTest001
 * @tc.desc: tdd ResumeInvalidCharacter with #
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest001");
    const char input = '#';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
    ASSERT_EQ(outPut, ':');
}

/**
 * @tc.name: HksStorageTest.HksStorageTest002
 * @tc.desc: tdd ResumeInvalidCharacter with $
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest002");
    const char input = '$';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
    ASSERT_EQ(outPut, '<');
}

/**
 * @tc.name: HksStorageTest.HksStorageTest003
 * @tc.desc: tdd ResumeInvalidCharacter with %
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest003");
    const char input = '%';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
    ASSERT_EQ(outPut, '>');
}

/**
 * @tc.name: HksStorageTest.HksStorageTest004
 * @tc.desc: tdd ResumeInvalidCharacter with &
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest004");
    const char input = '&';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
    ASSERT_EQ(outPut, '?');
}

/**
 * @tc.name: HksStorageTest.HksStorageTest005
 * @tc.desc: tdd ResumeInvalidCharacter with (
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest005");
    const char input = '(';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
    ASSERT_EQ(outPut, '\\');
}

/**
 * @tc.name: HksStorageTest.HksStorageTest006
 * @tc.desc: tdd ResumeInvalidCharacter with )
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest006");
    const char input = ')';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
    ASSERT_EQ(outPut, '|');
}

/**
 * @tc.name: HksStorageTest.HksStorageTest007
 * @tc.desc: tdd HksGetKeyCountByProcessName with null path, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest007");
    struct HksStoreFileInfo fileInfo = {};
    uint32_t fileCount = 0;
    int32_t ret = HksGetKeyCountByProcessName(&fileInfo, &fileCount);
    ASSERT_EQ(HKS_ERROR_NULL_POINTER, ret);
}

/**
 * @tc.name: HksStorageTest.HksStorageTest008
 * @tc.desc: tdd HksGetKeyCountByProcessName with null fileCount, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest008");
    struct HksStoreFileInfo fileInfo = {};
    int32_t ret = HksGetKeyCountByProcessName(&fileInfo, nullptr);
    ASSERT_EQ(HKS_ERROR_NULL_POINTER, ret);
}

/**
 * @tc.name: HksStorageTest.HksStorageTest009
 * @tc.desc: tdd HksGetKeyAliasByProcessName with null path, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest009");
    struct HksStoreFileInfo fileInfo = {};
    struct HksKeyInfo keyInfoList[1] = {};
    uint32_t listCount = 1;
    int32_t ret = HksGetKeyAliasByProcessName(&fileInfo, keyInfoList, &listCount);
    ASSERT_EQ(HKS_ERROR_NULL_POINTER, ret);
}

/**
 * @tc.name: HksStorageTest.HksStorageTest010
 * @tc.desc: tdd HksStoreIsKeyBlobExist with non-existent key, expect HKS_ERROR_NOT_EXIST
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest010");
    struct HksStoreFileInfo fileInfo = {};
    int32_t ret = HksStoreIsKeyBlobExist(&fileInfo);
    ASSERT_EQ(HKS_ERROR_NOT_EXIST, ret);
}

/**
 * @tc.name: HksStorageTest.HksStorageTest011
 * @tc.desc: tdd HksStoreGetKeyBlob with non-existent key, expect HKS_ERROR_NOT_EXIST
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest011");
    struct HksStoreInfo fileInfoPath = { .path = nullptr, .fileName = const_cast<char *>("alias") };
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    material.userIdPath = const_cast<char *>("999");
    material.uidPath = const_cast<char *>("123");
    struct HksBlob keyBlob = { .size = 0, .data = nullptr };
    int32_t ret = HksStoreGetKeyBlob(&fileInfoPath, &material, &keyBlob);
    ASSERT_EQ(HKS_ERROR_NOT_EXIST, ret);
}

/**
 * @tc.name: HksStorageTest.HksStorageTest012
 * @tc.desc: tdd HksStoreGetKeyBlobSize with non-existent key, expect HKS_ERROR_NOT_EXIST
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest012");
    struct HksStoreInfo fileInfoPath = { .path = nullptr, .fileName = const_cast<char *>("alias") };
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    material.userIdPath = const_cast<char *>("999");
    material.uidPath = const_cast<char *>("123");
    uint32_t keyBlobSize = 0;
    int32_t ret = HksStoreGetKeyBlobSize(&fileInfoPath, &material, &keyBlobSize);
    ASSERT_EQ(HKS_ERROR_NOT_EXIST, ret);
}

/**
 * @tc.name: HksStorageTest.HksStorageTest013
 * @tc.desc: tdd HksStoreDeleteKeyBlob with non-existent key, expect HKS_ERROR_NOT_EXIST
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest013");
    struct HksStoreFileInfo fileInfo = {};
    fileInfo.mainPath.path = nullptr;
    fileInfo.mainPath.fileName = const_cast<char *>("alias");
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    material.userIdPath = const_cast<char *>("999");
    material.uidPath = const_cast<char *>("123");
    int32_t ret = HksStoreDeleteKeyBlob(&fileInfo, &material);
    ASSERT_EQ(HKS_ERROR_NOT_EXIST, ret);
}
}
