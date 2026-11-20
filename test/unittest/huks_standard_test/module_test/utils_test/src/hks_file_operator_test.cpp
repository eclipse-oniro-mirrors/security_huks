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

#include "hks_file_operator_test.h"

#include <gtest/gtest.h>
#include <unistd.h>

#include "hks_file_operator.h"

#include "file_ex.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_type.h"

#include "securec.h"

using namespace testing::ext;
namespace Unittest::HksFileOperatorTest {
class HksFileOperatorTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksFileOperatorTest::SetUpTestCase(void)
{
}

void HksFileOperatorTest::TearDownTestCase(void)
{
}

void HksFileOperatorTest::SetUp()
{
}

void HksFileOperatorTest::TearDown()
{
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest001
 * @tc.desc: tdd HksFileSize, with NULL input, expect 0
 * @tc.type: FUNC
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest001");
    int32_t ret = HksFileSize(nullptr, nullptr);
    ASSERT_EQ(ret, 0) << "HksFileSize failed, ret = " << ret;
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest002
 * @tc.desc: tdd HksFileWrite, with NULL input, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest002");
    int32_t ret = HksFileWrite(nullptr, nullptr, 0, nullptr, 0);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFileWrite failed, ret = " << ret;
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest003
 * @tc.desc: tdd HksFileRead, with NULL input, expect 0
 * @tc.type: FUNC
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest003");
    int32_t ret = HksFileRead(nullptr, nullptr, 0, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFileRead failed, ret = " << ret;
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest006
 * @tc.desc: tdd HksRemoveDir, with NULL input, expect HKS_FAILURE
 * @tc.type: FUNC
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest006");
    int32_t ret = HksRemoveDir(nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksRemoveDir failed, ret = " << ret;
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest008
 * @tc.desc: tdd HksMakeDir, with NULL input, expect HKS_ERROR_MAKE_DIR_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest008");
    int32_t ret = HksMakeDir(nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksMakeDir failed, ret = " << ret;
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest009
 * @tc.desc: tdd HksIsDirExist, with NULL input, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest009");
    int32_t ret = HksIsDirExist(nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksIsDirExist failed, ret = " << ret;
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest010
 * @tc.desc: tdd HksIsFileExist, with NULL input, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest010");
    int32_t ret = HksIsFileExist(nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksIsFileExist failed, ret = " << ret;
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest011
 * @tc.desc: tdd HksIsFileExist, with NULL input, expect HKS_ERROR_INTERNAL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest011");
    const char *path = "1";
    const uint32_t fileNameSize = 600;
    char *fileName = (char *)HksMalloc(fileNameSize);
    (void)memset_s(fileName, fileNameSize, 1, fileNameSize);
    int32_t ret = HksIsFileExist(path, fileName);
    ASSERT_EQ(ret, HKS_ERROR_INTERNAL_ERROR) << "HksIsFileExist failed, ret = " << ret;
    HKS_FREE(fileName);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest012
 * @tc.desc: tdd HksFileRemove, with NULL input, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest012");
    int32_t ret = HksFileRemove(nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFileRemove failed, ret = " << ret;
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest013
 * @tc.desc: tdd HksFileRemove, with NULL input, expect HKS_ERROR_INTERNAL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest013");
    const char *path = "1";
    const uint32_t fileNameSize = 600;
    char *fileName = (char *)HksMalloc(fileNameSize);
    (void)memset_s(fileName, fileNameSize, 1, fileNameSize);
    int32_t ret = HksFileRemove(path, fileName);
    ASSERT_EQ(ret, HKS_ERROR_INTERNAL_ERROR) << "HksFileRemove failed, ret = " << ret;
    HKS_FREE(fileName);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest014
 * @tc.desc: tdd HksMakeDir 已存在目录, expect HKS_ERROR_ALREADY_EXISTS
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest014");
    ASSERT_EQ(HksMakeDir("/data/local/tmp"), HKS_ERROR_ALREADY_EXISTS);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest015
 * @tc.desc: tdd HksMakeDir 非法父目录, expect HKS_ERROR_MAKE_DIR_FAIL
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest015");
    ASSERT_EQ(HksMakeDir("/data/local/tmp/no_such_parent_xyz/sub"), HKS_ERROR_MAKE_DIR_FAIL);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest016
 * @tc.desc: tdd HksFileRead 带 ../, expect HKS_ERROR_INVALID_ARGUMENT
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest016, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest016");
    uint8_t data[16] = { 0 };
    struct HksBlob blob = { .size = sizeof(data), .data = data };
    uint32_t size = 0;
    ASSERT_EQ(HksFileRead(nullptr, "../test", 0, &blob, &size), HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest017
 * @tc.desc: tdd HksFileWrite 带 ../, expect HKS_ERROR_INVALID_ARGUMENT
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest017, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest017");
    uint8_t data[4] = { 0 };
    ASSERT_EQ(HksFileWrite(nullptr, "../test", 0, data, sizeof(data)), HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest018
 * @tc.desc: tdd HksFileRead 不存在文件, expect HKS_ERROR_NOT_EXIST
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest018, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest018");
    uint8_t data[16] = { 0 };
    struct HksBlob blob = { .size = sizeof(data), .data = data };
    uint32_t size = 0;
    ASSERT_EQ(HksFileRead("/data/local/tmp", "hks_no_such_file_xyz", 0, &blob, &size), HKS_ERROR_NOT_EXIST);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest019
 * @tc.desc: tdd HksFileRemove 目录, expect HKS_ERROR_INVALID_ARGUMENT
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest019, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest019");
    ASSERT_EQ(HksFileRemove("/data/local", "tmp"), HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest020
 * @tc.desc: tdd HksRemoveDir 文件(非目录), expect HKS_FAILURE
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest020, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest020");
    const char *fileName = "hks_op_remove_dir_test.txt";
    uint8_t data[4] = { 0 };
    (void)HksFileWrite("/data/local/tmp", fileName, 0, data, sizeof(data));
    char fullName[512] = { 0 };
    (void)HksGetFileName("/data/local/tmp", fileName, fullName, sizeof(fullName));
    ASSERT_EQ(HksRemoveDir(fullName), HKS_FAILURE);
    (void)HksFileRemove("/data/local/tmp", fileName);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest021
 * @tc.desc: tdd HksDeleteDir 文件, expect HKS_ERROR_OPEN_FILE_FAIL
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest021, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest021");
    const char *fileName = "hks_op_delete_dir_test.txt";
    uint8_t data[4] = { 0 };
    (void)HksFileWrite("/data/local/tmp", fileName, 0, data, sizeof(data));
    char fullName[512] = { 0 };
    (void)HksGetFileName("/data/local/tmp", fileName, fullName, sizeof(fullName));
    ASSERT_EQ(HksDeleteDir(fullName), HKS_ERROR_OPEN_FILE_FAIL);
    (void)HksFileRemove("/data/local/tmp", fileName);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest022
 * @tc.desc: tdd GetDeviceValidSize 非法分区, expect 0
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest022, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest022");
    ASSERT_EQ(GetDeviceValidSize("/no_such_partition_xyz"), 0);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest023
 * @tc.desc: tdd HksGetFileName 带 path, expect HKS_SUCCESS
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest023, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest023");
    char fullName[512] = { 0 };
    ASSERT_EQ(HksGetFileName("/data/local/tmp", "test.txt", fullName, sizeof(fullName)), HKS_SUCCESS);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest024
 * @tc.desc: tdd HksIsDirExist ../, expect HKS_ERROR_INVALID_ARGUMENT
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest024, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest024");
    ASSERT_EQ(HksIsDirExist("../test"), HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest025
 * @tc.desc: tdd HksOpenDir 合法目录, expect 非空
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest025, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest025");
    void *dir = HksOpenDir("/data/local/tmp");
    ASSERT_NE(dir, nullptr);
    (void)HksCloseDir(dir);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest026
 * @tc.desc: tdd HksIsFileExist 路径父目录为普通文件, expect HKS_ERROR_NOT_EXIST
 * @tc.type: FUNC
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest026, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest026");
    const char *fileName = "hks_op_file_parent.txt";
    uint8_t data[4] = { 0 };
    (void)HksFileWrite("/data/local/tmp", fileName, 0, data, sizeof(data));
    char fullName[512] = { 0 };
    (void)HksGetFileName("/data/local/tmp", fileName, fullName, sizeof(fullName));
    ASSERT_EQ(HksIsFileExist(fullName, "sub"), HKS_ERROR_NOT_EXIST);
    (void)HksFileRemove("/data/local/tmp", fileName);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest027
 * @tc.desc: tdd HksFileWrite 父目录不存在, expect HKS_ERROR_OPEN_FILE_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest027, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest027");
    uint8_t data[4] = { 0 };
    ASSERT_EQ(HksFileWrite("/data/local/tmp/hks_no_such_parent_xyz", "f.txt", 0, data, sizeof(data)),
        HKS_ERROR_OPEN_FILE_FAIL);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest028
 * @tc.desc: tdd HksGetFileName path 长度超过 buffer, expect HKS_ERROR_INTERNAL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest028, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest028");
    char longPath[200] = { 0 };
    (void)memset_s(longPath, sizeof(longPath), 'a', sizeof(longPath) - 1);
    char fullName[16] = { 0 };
    ASSERT_EQ(HksGetFileName(longPath, "f.txt", fullName, sizeof(fullName)), HKS_ERROR_INTERNAL_ERROR);
}

/**
 * @tc.name: HksFileOperatorTest.HksFileOperatorTest029
 * @tc.desc: tdd HksRemoveDir 删除包含普通文件的目录, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksFileOperatorTest, HksFileOperatorTest029, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileOperatorTest029");
    const char *dirName = "hks_op_remove_dir_test_dir";
    const char *innerFile = "inner.txt";
    const uint8_t data[4] = { 0 };
    char fullDir[512] = { 0 };
    (void)HksGetFileName("/data/local/tmp", dirName, fullDir, sizeof(fullDir));
    (void)HksDeleteDir(fullDir);
    ASSERT_EQ(HksMakeDir(fullDir), HKS_SUCCESS);
    ASSERT_EQ(HksFileWrite(fullDir, innerFile, 0, data, sizeof(data)), HKS_SUCCESS);
    ASSERT_EQ(HksRemoveDir(fullDir), HKS_SUCCESS);
    ASSERT_EQ(HksIsFileExist(fullDir, innerFile), HKS_ERROR_NOT_EXIST);
    (void)HksDeleteDir(fullDir);
}
}
