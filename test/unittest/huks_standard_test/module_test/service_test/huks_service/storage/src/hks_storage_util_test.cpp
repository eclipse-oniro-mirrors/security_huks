/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#undef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
#define HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL

#undef HKS_ENABLE_LITE_HAP
#define HKS_ENABLE_LITE_HAP

#undef HKS_USE_RKC_IN_STANDARD
#define HKS_USE_RKC_IN_STANDARD

#undef HKS_KEY_STORE_LITE_HAP
#define HKS_KEY_STORE_LITE_HAP "/data/lite/hap"

#undef HKS_CONFIG_RKC_STORE_PATH
#define HKS_CONFIG_RKC_STORE_PATH "/data"

#include <gtest/gtest.h>
#include <cstring>

#include "file_ex.h"
#include "hks_log.h"
#include "hks_type_inner.h"
#include "hks_param.h"

#include "hks_storage_utils.h"

#include "base/security/huks/services/huks_standard/huks_service/main/hks_storage/src/hks_storage_utils.c"

using namespace testing::ext;
namespace Unittest::HksStorageUtilTest {
class HksStorageUtilTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksStorageUtilTest::SetUpTestCase(void)
{
}

void HksStorageUtilTest::TearDownTestCase(void)
{
}

void HksStorageUtilTest::SetUp()
{
}

void HksStorageUtilTest::TearDown()
{
    std::system("find /data/service/el1/public/huks_service -user root -delete");
    std::system("find /data/service/el2/100/huks_service -user root -delete");
    std::system("find /data/service/el4/100/huks_service -user root -delete");
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest001
 * @tc.desc: test HksGetFileInfo with full DE_PATH
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest001");
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    material.keyAliasPath = const_cast<char *>("alias");
    material.storageTypePath = const_cast<char *>("key");
    material.uidPath = const_cast<char *>("123");
    material.userIdPath = const_cast<char *>("999");
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    int32_t ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(strlen(fileInfo.mainPath.fileName), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.fileName, material.keyAliasPath, strlen(material.keyAliasPath)));

    const char *expectPath =
        HKS_KEY_STORE_PATH "/999/123/key";
    ASSERT_EQ(strlen(fileInfo.mainPath.path), strlen(expectPath)) << fileInfo.mainPath.path;
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.path, expectPath, strlen(expectPath)));
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest002
 * @tc.desc: test HksGetFileInfo with DE_PATH without user id
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest002");
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    material.keyAliasPath = const_cast<char *>("alias");
    material.storageTypePath = const_cast<char *>("key");
    material.uidPath = const_cast<char *>("222");
    material.userIdPath = const_cast<char *>("");
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    int32_t ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(strlen(fileInfo.mainPath.fileName), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.fileName, material.keyAliasPath, strlen(material.keyAliasPath)));

    const char *expectPath =
        HKS_KEY_STORE_PATH "/222/key";
    ASSERT_EQ(strlen(fileInfo.mainPath.path), strlen(expectPath)) << fileInfo.mainPath.path;
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.path, expectPath, strlen(expectPath)));

    material.developerId = const_cast<char *>("test_developer");
    material.assetAccessGroup = const_cast<char *>("test_group");
    ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest003
 * @tc.desc: test HksGetFileInfo with CE_PATH
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest003");
    struct HksStoreMaterial material = { CE_PATH, 0 };
    material.keyAliasPath = const_cast<char *>("alias");
    material.storageTypePath = const_cast<char *>("key");
    material.uidPath = const_cast<char *>("333");
    material.userIdPath = const_cast<char *>("100");
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    int32_t ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(strlen(fileInfo.mainPath.fileName), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.fileName, material.keyAliasPath, strlen(material.keyAliasPath)));

    const char *expectPath =
        HKS_CE_ROOT_PATH "/100/" HKS_STORE_SERVICE_PATH "/333/key";
    ASSERT_EQ(strlen(fileInfo.mainPath.path), strlen(expectPath)) << fileInfo.mainPath.path;
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.path, expectPath, strlen(expectPath)));

    material.developerId = const_cast<char *>("test_developer");
    material.assetAccessGroup = const_cast<char *>("test_group");
    ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest004
 * @tc.desc: test HksGetFileInfo with ECE_PATH
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest004");
    struct HksStoreMaterial material = { ECE_PATH, 0 };
    material.keyAliasPath = const_cast<char *>("alias");
    material.storageTypePath = const_cast<char *>("key");
    material.uidPath = const_cast<char *>("444");
    material.userIdPath = const_cast<char *>("100");
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    int32_t ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(strlen(fileInfo.mainPath.fileName), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.fileName, material.keyAliasPath, strlen(material.keyAliasPath)));

    const char *expectPath =
        HKS_ECE_ROOT_PATH "/100/" HKS_STORE_SERVICE_PATH "/444/key";
    ASSERT_EQ(strlen(fileInfo.mainPath.path), strlen(expectPath)) << fileInfo.mainPath.path;
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.path, expectPath, strlen(expectPath)));

    material.developerId = const_cast<char *>("test_developer");
    material.assetAccessGroup = const_cast<char *>("test_group");
    ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

#ifdef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest005
 * @tc.desc: test HksGetFileInfo with TMP_PATH
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest005");
    struct HksStoreMaterial material = { TMP_PATH, 0 };
    material.keyAliasPath = const_cast<char *>("alias");
    material.storageTypePath = const_cast<char *>("key");
    material.uidPath = const_cast<char *>("555");
    material.userIdPath = const_cast<char *>("555");
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    int32_t ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(strlen(fileInfo.mainPath.fileName), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.fileName, material.keyAliasPath, strlen(material.keyAliasPath)));

    const char *expectPath =
        HKS_KEY_STORE_TMP_PATH "/555/555/key";
    ASSERT_EQ(strlen(fileInfo.mainPath.path), strlen(expectPath)) << fileInfo.mainPath.path;
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.path, expectPath, strlen(expectPath)));

    material.developerId = const_cast<char *>("test_developer");
    material.assetAccessGroup = const_cast<char *>("test_group");
    ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);
}
#endif

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest006
 * @tc.desc: test HksGetFileInfo with LITE_HAP_PATH
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest006");
    struct HksStoreMaterial material = { LITE_HAP_PATH, 0 };
    material.keyAliasPath = const_cast<char *>("alias");
    material.storageTypePath = const_cast<char *>("key");
    material.uidPath = const_cast<char *>("hks_client");
    material.userIdPath = const_cast<char *>("");
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    int32_t ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(strlen(fileInfo.mainPath.fileName), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.fileName, material.keyAliasPath, strlen(material.keyAliasPath)));

    const char *expectPath =
        HKS_KEY_STORE_LITE_HAP "/hks_client/key";
    ASSERT_EQ(strlen(fileInfo.mainPath.path), strlen(expectPath)) << fileInfo.mainPath.path;
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.path, expectPath, strlen(expectPath)));

    material.developerId = const_cast<char *>("test_developer");
    material.assetAccessGroup = const_cast<char *>("test_group");
    ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest007
 * @tc.desc: test HksGetFileInfo with RKC_IN_STANDARD_PATH
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest007");
    struct HksStoreMaterial material = { RKC_IN_STANDARD_PATH, 0 };
    material.keyAliasPath = const_cast<char *>("alias");
    material.storageTypePath = const_cast<char *>("key");
    material.uidPath = const_cast<char *>("hks_client");
    material.userIdPath = const_cast<char *>("0");
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    int32_t ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(strlen(fileInfo.mainPath.fileName), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.fileName, material.keyAliasPath, strlen(material.keyAliasPath)));

    const char *expectPath =
        HKS_KEY_RKC_PATH "/hks_client/key";
    ASSERT_EQ(strlen(fileInfo.mainPath.path), strlen(expectPath)) << fileInfo.mainPath.path;
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.path, expectPath, strlen(expectPath)));

    material.developerId = const_cast<char *>("test_developer");
    material.assetAccessGroup = const_cast<char *>("test_group");
    ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest008
 * @tc.desc: test ConstructPlainName with int data and too small buffer, expect HKS_ERROR_INSUFFICIENT_MEMORY
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest008");
    int value = 123;
    struct HksBlob blob = { .size = sizeof(int), .data = (uint8_t *)&value };
    char name[1] = { 0 };
    int32_t ret = ConstructPlainName(&blob, name, 1);
    ASSERT_EQ(HKS_ERROR_INSUFFICIENT_MEMORY, ret);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest009
 * @tc.desc: test ConstructPlainName with too small nameLen, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest009");
    uint8_t data[] = { 'a', 'b', 'c' };
    struct HksBlob blob = { .size = sizeof(data), .data = data };
    char name[2] = { 0 };
    int32_t ret = ConstructPlainName(&blob, name, 1);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest010
 * @tc.desc: test ConstructPlainName with buffer overflow, expect HKS_ERROR_INSUFFICIENT_DATA
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest010");
    uint8_t data[] = { 'a', 'b', 'c', 'd', 'e' };
    struct HksBlob blob = { .size = sizeof(data), .data = data };
    char name[3] = { 0 };
    int32_t ret = ConstructPlainName(&blob, name, 3);
    ASSERT_EQ(HKS_ERROR_INSUFFICIENT_DATA, ret);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest011
 * @tc.desc: test ConstructName with too small nameLen, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest011");
    uint8_t data[] = { 'a' };
    struct HksBlob blob = { .size = sizeof(data), .data = data };
    char name[2] = { 0 };
    int32_t ret = ConstructName(&blob, name, 1);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest012
 * @tc.desc: test ConstructName with buffer overflow, expect HKS_ERROR_INSUFFICIENT_DATA
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest012");
    uint8_t data[] = { 'a', 'b', 'c', 'd', 'e' };
    struct HksBlob blob = { .size = sizeof(data), .data = data };
    char name[4] = { 0 };
    int32_t ret = ConstructName(&blob, name, 4);
    ASSERT_EQ(HKS_ERROR_INSUFFICIENT_DATA, ret);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest013
 * @tc.desc: test ConstructBlob with incomplete encoded char, expect HKS_ERROR_INVALID_KEY_FILE
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest013");
    const char *src = "+";
    uint8_t buf[4] = { 0 };
    struct HksBlob blob = { .size = sizeof(buf), .data = buf };
    int32_t ret = ConstructBlob(src, &blob);
    ASSERT_EQ(HKS_ERROR_INVALID_KEY_FILE, ret);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest014
 * @tc.desc: test ConstructBlob with too small blob, expect HKS_ERROR_BUFFER_TOO_SMALL
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest014");
    const char *src = "abc";
    uint8_t buf[1] = { 0 };
    struct HksBlob blob = { .size = sizeof(buf), .data = buf };
    int32_t ret = ConstructBlob(src, &blob);
    ASSERT_EQ(HKS_ERROR_BUFFER_TOO_SMALL, ret);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest015
 * @tc.desc: test ConstructBlob with null blob data, expect HKS_ERROR_INSUFFICIENT_MEMORY
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest015");
    const char *src = "ab";
    struct HksBlob blob = { .size = 4, .data = nullptr };
    int32_t ret = ConstructBlob(src, &blob);
    ASSERT_EQ(HKS_ERROR_INSUFFICIENT_MEMORY, ret);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest016
 * @tc.desc: test GetPath with empty path, expect HKS_ERROR_INTERNAL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest016, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest016");
    char target[32] = { 0 };
    int32_t ret = GetPath("", "name", target, sizeof(target), HKS_STORAGE_BAK_FLAG_FLASE);
    ASSERT_EQ(HKS_ERROR_INTERNAL_ERROR, ret);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest017
 * @tc.desc: test GetPath with too small targetPath for name, expect HKS_ERROR_BAD_STATE
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest017, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest017");
    char target[4] = { 0 };
    int32_t ret = GetPath("a", "name", target, 4, HKS_STORAGE_BAK_FLAG_FLASE);
    ASSERT_EQ(HKS_ERROR_BAD_STATE, ret);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest018
 * @tc.desc: test GetPath with too small targetPath for bak suffix, expect HKS_ERROR_BAD_STATE
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest018, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest018");
    char target[7] = { 0 };
    int32_t ret = GetPath("a", "b", target, 7, HKS_STORAGE_BAK_FLAG_TRUE);
    ASSERT_EQ(HKS_ERROR_BAD_STATE, ret);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest019
 * @tc.desc: test RecordKeyOperation with invalid operation, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest019, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest019");
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    material.userIdPath = const_cast<char *>("999");
    material.uidPath = const_cast<char *>("123");
    const char *keyAlias = "alias";
    int32_t ret = RecordKeyOperation(100, &material, keyAlias);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest020
 * @tc.desc: test FileNameListInit with zero keyCount, expect HKS_ERROR_BUFFER_TOO_SMALL
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest020, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest020");
    struct HksFileEntry *fileNameList = nullptr;
    int32_t ret = FileNameListInit(&fileNameList, 0);
    ASSERT_EQ(HKS_ERROR_BUFFER_TOO_SMALL, ret);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest021
 * @tc.desc: test CheckSpecificUserIdAndStorageLevel with null paramSet, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest021, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest021");
    struct HksProcessInfo processInfo = {};
    int32_t ret = CheckSpecificUserIdAndStorageLevel(&processInfo, nullptr);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest022
 * @tc.desc: test CheckSpecificUserIdAndStorageLevel with DE level and negative specificUserId,
 *           expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest022, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest022");
    struct HksParam params[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = -1 },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = HksAddParams(paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(HKS_SUCCESS, ret);

    struct HksProcessInfo processInfo = {};
    ret = CheckSpecificUserIdAndStorageLevel(&processInfo, paramSet);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest023
 * @tc.desc: test CheckSpecificUserIdAndStorageLevel with CE level only and small userIdInt,
 *           expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest023, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest023");
    struct HksParam params[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = HksAddParams(paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(HKS_SUCCESS, ret);

    struct HksProcessInfo processInfo = {};
    processInfo.userIdInt = 99;
    ret = CheckSpecificUserIdAndStorageLevel(&processInfo, paramSet);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest024
 * @tc.desc: test HksGetFileInfo with ../ in keyAliasPath, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest024, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest024");
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    material.keyAliasPath = const_cast<char *>("../evil");
    material.storageTypePath = const_cast<char *>("key");
    material.uidPath = const_cast<char *>("123");
    material.userIdPath = const_cast<char *>("999");
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    int32_t ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}
}
