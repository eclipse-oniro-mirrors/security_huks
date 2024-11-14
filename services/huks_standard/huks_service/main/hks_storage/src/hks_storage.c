/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "hks_type_enum.h"
#ifndef _CUT_AUTHENTICATE_

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_storage.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hks_file_operator.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_storage_file_lock.h"
#include "hks_template.h"
#include "huks_access.h"
#include "securec.h"
#include "hks_storage_utils.h"

#ifdef HKS_SUPPORT_THREAD
static HksStorageFileLock *CreateStorageFileLock(const char *path, const char *fileName)
{
    char *fullPath = (char *)HksMalloc(HKS_MAX_FILE_NAME_LEN);
    HKS_IF_NULL_RETURN(fullPath, NULL)

    int32_t ret = HksGetFileName(path, fileName, fullPath, HKS_MAX_FILE_NAME_LEN);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get full path failed, ret = %" LOG_PUBLIC "d.", ret);
        HKS_FREE(fullPath);
        return NULL;
    }

    HksStorageFileLock *lock = HksStorageFileLockCreate(fullPath);
    HKS_FREE(fullPath);
    return lock;
}
#endif

int32_t HksStorageWriteFile(
    const char *path, const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len)
{
#ifdef HKS_SUPPORT_THREAD
    HksStorageFileLock *lock = CreateStorageFileLock(path, fileName);
    HksStorageFileLockWrite(lock);
    int32_t ret = HksFileWrite(path, fileName, offset, buf, len);
    HksStorageFileUnlockWrite(lock);
    HksStorageFileLockRelease(lock);
    return ret;
#else
    return HksFileWrite(path, fileName, offset, buf, len);
#endif
}

static int32_t HksStorageReadFile(
    const char *path, const char *fileName, uint32_t offset, struct HksBlob *blob, uint32_t *size)
{
#ifdef HKS_SUPPORT_THREAD
    HksStorageFileLock *lock = CreateStorageFileLock(path, fileName);
    HksStorageFileLockRead(lock);
    int32_t ret = HksFileRead(path, fileName, offset, blob, size);
    HksStorageFileUnlockRead(lock);
    HksStorageFileLockRelease(lock);
#else
    int32_t ret = HksFileRead(path, fileName, offset, blob, size);
#endif
    return ret;
}

#ifdef HKS_ENABLE_CLEAN_FILE
static int32_t CleanFile(const char *path, const char *fileName)
{
    uint32_t size = HksFileSize(path, fileName);
    if (size == 0 || size > HKS_MAX_FILE_SIZE) {
        HKS_LOG_E("get file size failed, ret = %" LOG_PUBLIC "u.", size);
        return HKS_ERROR_FILE_SIZE_FAIL;
    }

    int32_t ret = HKS_SUCCESS;
    uint8_t *buf;
    do {
        buf = (uint8_t *)HksMalloc(size);
        if (buf == NULL) {
            HKS_LOG_E("malloc buf failed!");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        (void)memset_s(buf, size, 0, size);
        ret = HksStorageWriteFile(path, fileName, 0, buf, size);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "write file 0 failed!")

        (void)memset_s(buf, size, 1, size);
        ret = HksStorageWriteFile(path, fileName, 0, buf, size);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "write file 1 failed!")

        struct HksBlob bufBlob = { .size = size, .data = buf };
        ret = HuksAccessGenerateRandom(NULL, &bufBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "fill buf random failed!")

        ret = HksStorageWriteFile(path, fileName, 0, buf, size);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "write file random failed!")
    } while (0);

    HKS_FREE(buf);

    return ret;
}
#endif

static int32_t HksStorageRemoveFile(const char *path, const char *fileName)
{
    int32_t ret;
#ifdef HKS_ENABLE_CLEAN_FILE
    ret = CleanFile(path, fileName);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("clean file failed!");
    }
#endif
#ifdef HKS_SUPPORT_THREAD
    HksStorageFileLock *lock = CreateStorageFileLock(path, fileName);
    HksStorageFileLockWrite(lock);
    ret = HksFileRemove(path, fileName);
    HksStorageFileUnlockWrite(lock);
    HksStorageFileLockRelease(lock);
#else
    ret = HksFileRemove(path, fileName);
#endif
    return ret;
}

static int32_t CopyKeyBlobFromSrc(const char *srcPath, const char *srcFileName,
    const char *destPath, const char *destFileName)
{
    uint32_t size = HksFileSize(srcPath, srcFileName);
    if (size == 0) {
        HKS_LOG_E("get file size failed, ret = %" LOG_PUBLIC "u.", size);
        return HKS_ERROR_FILE_SIZE_FAIL;
    }

    uint8_t *buffer = (uint8_t *)HksMalloc(size);
    HKS_IF_NULL_RETURN(buffer, HKS_ERROR_MALLOC_FAIL)

    (void)memset_s(buffer, size, 0, size);

    struct HksBlob blob = { .size = size, .data = buffer };

    int32_t ret;
    do {
        ret = HksStorageReadFile(srcPath, srcFileName, 0, &blob, &size);
        if (ret != HKS_SUCCESS) {
            if (ret == HKS_ERROR_NO_PERMISSION) {
                HKS_LOG_E("Check Permission failed, ret = %" LOG_PUBLIC "d.", ret);
                break;
            }
            HKS_LOG_E("read file failed, ret = %" LOG_PUBLIC "d.", ret);
            ret = HKS_ERROR_READ_FILE_FAIL;
            break;
        }

        ret = HksStorageWriteFile(destPath, destFileName, 0, buffer, size);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "file write destPath failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    HKS_FREE(buffer);
    return ret;
}

static int32_t GetKeyBlobFromFile(const char *path, const char *fileName, struct HksBlob *keyBlob)
{
    uint32_t size = HksFileSize(path, fileName);
    if (size == 0) {
        return HKS_ERROR_FILE_SIZE_FAIL;
    }

    if (keyBlob->size < size) {
        return HKS_ERROR_INSUFFICIENT_DATA;
    }

    int32_t ret = HksStorageReadFile(path, fileName, 0, keyBlob, &size);
    if (ret != HKS_SUCCESS) {
        if (ret == HKS_ERROR_NO_PERMISSION) {
            HKS_LOG_E("Check Permission failed, ret = %" LOG_PUBLIC "d.", ret);
            return ret;
        }
        HKS_LOG_E("read file failed, ret = %" LOG_PUBLIC "d.", ret);
        return HKS_ERROR_READ_FILE_FAIL;
    }
    keyBlob->size = size;
    return HKS_SUCCESS;
}

static int32_t DeleteKeyBlob(const struct HksStoreFileInfo *fileInfo)
{
    int32_t isMainFileExist = HksIsFileExist(fileInfo->mainPath.path, fileInfo->mainPath.fileName);
    int32_t ret = HKS_SUCCESS;
#ifdef SUPPORT_STORAGE_BACKUP
    int32_t isBakFileExist = HksIsFileExist(fileInfo->bakPath.path, fileInfo->bakPath.fileName);
    if ((isMainFileExist != HKS_SUCCESS) && (isBakFileExist != HKS_SUCCESS)) {
        return HKS_ERROR_NOT_EXIST;
    }

    if (isBakFileExist == HKS_SUCCESS) {
        ret = HksStorageRemoveFile(fileInfo->bakPath.path, fileInfo->bakPath.fileName);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "delete key remove bakfile failed, ret = %" LOG_PUBLIC "d.", ret)
    }
#endif
    if (isMainFileExist == HKS_SUCCESS) {
        ret = HksStorageRemoveFile(fileInfo->mainPath.path, fileInfo->mainPath.fileName);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "delete key remove file failed, ret = %" LOG_PUBLIC "d.", ret)
    } else {
        return HKS_ERROR_NOT_EXIST;
    }

    return ret;
}

static int32_t GetKeyBlob(const struct HksStoreInfo *fileInfoPath, struct HksBlob *keyBlob)
{
    int32_t isFileExist = HksIsFileExist(fileInfoPath->path, fileInfoPath->fileName);
    HKS_IF_NOT_SUCC_RETURN(isFileExist, HKS_ERROR_NOT_EXIST)

    int32_t ret = GetKeyBlobFromFile(fileInfoPath->path, fileInfoPath->fileName, keyBlob);
    return ret;
}

static int32_t GetKeyBlobSize(const struct HksStoreInfo *fileInfoPath, uint32_t *keyBlobSize)
{
    int32_t isFileExist = HksIsFileExist(fileInfoPath->path, fileInfoPath->fileName);
    HKS_IF_NOT_SUCC_RETURN(isFileExist, HKS_ERROR_NOT_EXIST)

    uint32_t size = HksFileSize(fileInfoPath->path, fileInfoPath->fileName);
    if (size == 0) {
        return HKS_ERROR_FILE_SIZE_FAIL;
    }
    *keyBlobSize = size;
    return HKS_SUCCESS;
}

static int32_t IsKeyBlobExist(const struct HksStoreFileInfo *fileInfo)
{
    int32_t isMainFileExist = HksIsFileExist(fileInfo->mainPath.path, fileInfo->mainPath.fileName);
#ifndef SUPPORT_STORAGE_BACKUP
    HKS_IF_NOT_SUCC_RETURN(isMainFileExist, HKS_ERROR_NOT_EXIST)
#else
    if (isMainFileExist != HKS_SUCCESS) {
        int32_t isBakFileExist = HksIsFileExist(fileInfo->bakPath.path, fileInfo->bakPath.fileName);
        HKS_IF_NOT_SUCC_LOGE_RETURN(isBakFileExist, HKS_ERROR_NOT_EXIST, "hks mainkey and backupkey not exist")

        if (CopyKeyBlobFromSrc(fileInfo->bakPath.path, fileInfo->bakPath.fileName,
            fileInfo->mainPath.path, fileInfo->mainPath.fileName) != HKS_SUCCESS) {
                HKS_LOG_E("hks copy bak key to main key failed");
            }
    }
#endif
    return HKS_SUCCESS;
}

int32_t HksStoreKeyBlob(const struct HksStoreFileInfo *fileInfo, const struct HksBlob *keyBlob)
{
    int32_t ret;
    do {
        ret = RecordKeyOperation(KEY_OPERATION_SAVE, fileInfo->mainPath.path, fileInfo->mainPath.fileName);
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = HksStorageWriteFile(fileInfo->mainPath.path, fileInfo->mainPath.fileName, 0,
            keyBlob->data, keyBlob->size);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks save main key blob failed, ret = %" LOG_PUBLIC "d.", ret)

#ifdef SUPPORT_STORAGE_BACKUP
        if (HksStorageWriteFile(fileInfo->bakPath.path, fileInfo->bakPath.fileName, 0,
            keyBlob->data, keyBlob->size) != HKS_SUCCESS) {
                HKS_LOG_E("hks save backup key blob failed");
            }
#endif
    } while (0);

    return ret;
}

int32_t HksStoreDeleteKeyBlob(const struct HksStoreFileInfo *fileInfo)
{
    int32_t ret;
    do {
        ret = RecordKeyOperation(KEY_OPERATION_DELETE, fileInfo->mainPath.path, fileInfo->mainPath.fileName);
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = DeleteKeyBlob(fileInfo);
    } while (0);

    return ret;
}

int32_t HksStoreIsKeyBlobExist(const struct HksStoreFileInfo *fileInfo)
{
    int32_t ret;
    do {
        ret = IsKeyBlobExist(fileInfo);
        HKS_IF_NOT_SUCC_LOGE(ret, "check is key exist, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    return ret;
}

int32_t HksStoreGetKeyBlob(const struct HksStoreInfo *fileInfoPath, struct HksBlob *keyBlob)
{
    int32_t ret;
    do {
        ret = RecordKeyOperation(KEY_OPERATION_GET, fileInfoPath->path, fileInfoPath->fileName);
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = GetKeyBlob(fileInfoPath, keyBlob);
        HKS_IF_NOT_SUCC_LOGE(ret, "hks get keyblob failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    return ret;
}

int32_t HksStoreGetKeyBlobSize(const struct HksStoreInfo *fileInfoPath, uint32_t *keyBlobSize)
{
    int32_t ret;
    do {
        ret = GetKeyBlobSize(fileInfoPath, keyBlobSize);
        HKS_IF_NOT_SUCC_LOGE(ret, "hks get keyblob size failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    return ret;
}

static int32_t GetFileCount(const char *path, uint32_t *fileCount)
{
    if ((path == NULL) || (fileCount == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    void *dir = HksOpenDir(path);
    if (dir == NULL) {
        HKS_LOG_W("can't open directory");
        *fileCount = 0;
        return HKS_SUCCESS;
    }

    uint32_t count = 0;
    struct HksFileDirentInfo dire = {{0}};
    int32_t ret = HksGetDirFile(dir, &dire);
    while (ret == HKS_SUCCESS) {
        count++;
        ret = HksGetDirFile(dir, &dire);
    }
    (void)HksCloseDir(dir);
    *fileCount = count;

    return HKS_SUCCESS;
}

static int32_t GetFileNameList(const char *path, struct HksFileEntry *fileNameList, uint32_t *fileCount)
{
    if ((path == NULL) || (fileCount == NULL) || (fileNameList == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    void *dir = HksOpenDir(path);
    if (dir == NULL) {
        HKS_LOG_W("can't open directory");
        *fileCount = 0;
        return HKS_SUCCESS;
    }

    struct HksFileDirentInfo dire = {{0}};
    int32_t ret = HksGetDirFile(dir, &dire);
    uint32_t count = 0;
    while (ret == HKS_SUCCESS) {
        count++;
        uint32_t nameLen = strlen(dire.fileName);
        if ((*fileCount < count) || (fileNameList[count - 1].fileNameLen < (nameLen + 1))) {
            HKS_LOG_E("the input params are wrong and too small");
            break;
        }

        if (strncpy_s(fileNameList[count - 1].fileName, fileNameList[count - 1].fileNameLen,
            dire.fileName, nameLen) != EOK) {
            HKS_LOG_E("failed to copy the string");
            break;
        }
        fileNameList[count - 1].fileName[nameLen] = '\0';
        ret = HksGetDirFile(dir, &dire);
    }
    (void)HksCloseDir(dir);
    *fileCount = count;

    return HKS_SUCCESS;
}

static int32_t GetAndCheckFileCount(const char *path, uint32_t *fileCount, const uint32_t *inputCount)
{
    int32_t ret = GetFileCount(path, fileCount);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get storage file count, ret = %" LOG_PUBLIC "d.", ret)

    if (*inputCount < *fileCount) {
        HKS_LOG_E("listCount space not enough");
        ret = HKS_ERROR_BUFFER_TOO_SMALL;
    }

    return ret;
}

static int32_t GetKeyAliasByProcessName(const struct HksStoreFileInfo *fileInfo, struct HksKeyInfo *keyInfoList,
    uint32_t *listCount)
{
    uint32_t fileCount;
    int32_t ret = GetAndCheckFileCount(fileInfo->mainPath.path, &fileCount, listCount);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    if (fileCount == 0) {
        *listCount = 0;
        return HKS_SUCCESS;
    }

    struct HksFileEntry *fileNameList = NULL;
    ret = FileNameListInit(&fileNameList, fileCount);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "init file name list failed.")

    uint32_t realFileCount = fileCount;
    do {
        ret = GetFileNameList(fileInfo->mainPath.path, fileNameList, &realFileCount);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get file name list failed, ret = %" LOG_PUBLIC "d", ret)

        for (uint32_t i = 0; i < realFileCount; ++i) {
            ret = ConstructBlob(fileNameList[i].fileName, &(keyInfoList[i].alias));
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "construct blob failed, ret = %" LOG_PUBLIC "d", ret)
        }
    } while (0);

    FileNameListFree(&fileNameList, fileCount);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    *listCount = realFileCount;
    return ret;
}

int32_t HksGetKeyAliasByProcessName(const struct HksStoreFileInfo *fileInfo, struct HksKeyInfo *keyInfoList,
    uint32_t *listCount)
{
    int32_t ret;
    do {
        ret = GetKeyAliasByProcessName(fileInfo, keyInfoList, listCount);
        HKS_IF_NOT_SUCC_LOGE(ret, "get key alias by processName failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    return ret;
}

int32_t HksGetKeyCountByProcessName(const struct HksStoreFileInfo *fileInfo, uint32_t *fileCount)
{
    int32_t ret;
    do {
        ret = GetFileCount(fileInfo->mainPath.path, fileCount);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get storage file count failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    return ret;
}

static int32_t DestroyType(const char *storePath, const char *typePath, uint32_t bakFlag)
{
    char *destroyPath = (char *)HksMalloc(HKS_MAX_FILE_NAME_LEN);
    HKS_IF_NULL_RETURN(destroyPath, HKS_ERROR_MALLOC_FAIL)

    (void)memset_s(destroyPath, HKS_MAX_FILE_NAME_LEN, 0, HKS_MAX_FILE_NAME_LEN);

    int32_t ret = GetPath(storePath, typePath, destroyPath, HKS_MAX_FILE_NAME_LEN, bakFlag);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Get Path failed! ret = 0x%" LOG_PUBLIC "X", ret);
        HKS_FREE(destroyPath);
        return ret;
    }

    ret = HksIsDirExist(destroyPath);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(destroyPath);
        return HKS_SUCCESS;
    }

    ret = HksRemoveDir(destroyPath);
    HKS_IF_NOT_SUCC_LOGE(ret, "Destroy dir failed! ret = 0x%" LOG_PUBLIC "X", ret)

    HKS_FREE(destroyPath);
    return ret;
}

static int32_t StoreDestroy(const char *processNameEncoded, uint32_t bakFlag)
{
    char *rootPath = NULL;
    if (bakFlag == HKS_STORAGE_BAK_FLAG_TRUE) {
        rootPath = HKS_KEY_STORE_BAK_PATH;
    } else {
        rootPath = HKS_KEY_STORE_PATH;
    }

    char *storePath = (char *)HksMalloc(HKS_MAX_FILE_NAME_LEN);
    HKS_IF_NULL_RETURN(storePath, HKS_ERROR_MALLOC_FAIL)

    int32_t ret = GetPath(rootPath, processNameEncoded, storePath, HKS_MAX_FILE_NAME_LEN, bakFlag);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Get Path failed! ret = 0x%" LOG_PUBLIC "X", ret);
        HKS_FREE(storePath);
        return ret;
    }

    ret = DestroyType(storePath, HKS_KEY_STORE_ROOT_KEY_PATH, bakFlag);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("Destroy info dir failed! ret = 0x%" LOG_PUBLIC "X", ret); /* continue delete */
    }

    ret = DestroyType(storePath, HKS_KEY_STORE_KEY_PATH, bakFlag);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("Destroy key dir failed! ret = 0x%" LOG_PUBLIC "X", ret); /* continue delete */
    }

    HKS_FREE(storePath);
    return HKS_SUCCESS;
}

int32_t HksStoreDestroy(const struct HksBlob *processName)
{
    char *name = (char *)HksMalloc(HKS_MAX_FILE_NAME_LEN);
    HKS_IF_NULL_RETURN(name, HKS_ERROR_MALLOC_FAIL)

    int32_t ret;
    do {
        ret = ConstructName(processName, name, HKS_MAX_FILE_NAME_LEN);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Construct process name failed! ret = 0x%" LOG_PUBLIC "X.", ret)

        ret = StoreDestroy(name, HKS_STORAGE_BAK_FLAG_FLASE);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Hks destroy dir failed! ret = 0x%" LOG_PUBLIC "X.", ret)

#ifdef SUPPORT_STORAGE_BACKUP
        ret = StoreDestroy(name, HKS_STORAGE_BAK_FLAG_TRUE);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Hks destroy back dir failed! ret = 0x%" LOG_PUBLIC "X.", ret)
#endif
    } while (0);

    HKS_FREE(name);
    return ret;
}

#ifdef HKS_ENABLE_SMALL_TO_SERVICE
int32_t HksIsOldKeyPathCleared(uint32_t *keyCount)
{
    return GetFileCount(HKS_KEY_STORE_PATH "/hks_client/key", keyCount);
}
#endif

#ifdef HKS_ENABLE_EVENT_DELETE
#ifdef L2_STANDARD
static void DeleteUserIdMainPathAndBakPath(const char *userData, const char *deDataPath, const char *ceOrEceDataPath)
{
    char dePath[HKS_MAX_DIRENT_FILE_LEN] = "";
    int32_t offset = sprintf_s(dePath, HKS_MAX_DIRENT_FILE_LEN, "%s/%s",
        deDataPath, userData);
    if (offset > 0) {
        HKS_LOG_I("delete path: %" LOG_PUBLIC "s", dePath);
        (void)HksDeleteDir(dePath);
    } else {
        HKS_LOG_E("get de path failed");
    }

    char cePath[HKS_MAX_DIRENT_FILE_LEN] = "";
    offset = sprintf_s(cePath, HKS_MAX_DIRENT_FILE_LEN, "%s/%s/%s",
        HKS_CE_ROOT_PATH, userData, ceOrEceDataPath);
    if (offset > 0) {
        HKS_LOG_I("delete path: %" LOG_PUBLIC "s", cePath);
        (void)HksDeleteDir(cePath);
    } else {
        HKS_LOG_E("get ce path failed");
    }

    char ecePath[HKS_MAX_DIRENT_FILE_LEN] = "";
    offset = sprintf_s(ecePath, HKS_MAX_DIRENT_FILE_LEN, "%s/%s/%s",
        HKS_ECE_ROOT_PATH, userData, ceOrEceDataPath);
    if (offset > 0) {
        HKS_LOG_I("delete path: %" LOG_PUBLIC "s", ecePath);
        (void)HksDeleteDir(ecePath);
    } else {
        HKS_LOG_E("get ece path failed");
    }
}

static void DeleteUserIdPath(const struct HksBlob *userId)
{
    int32_t ret;
    char *userData = NULL;
    do {
        userData = (char *)HksMalloc(HKS_MAX_FILE_NAME_LEN);
        HKS_IF_NULL_LOGE_BREAK(userData, "malloc user data failed")

        ret = ConstructPlainName(userId, userData, HKS_MAX_FILE_NAME_LEN);
        HKS_IF_NOT_SUCC_BREAK(ret, "construct user id name failed, ret = %" LOG_PUBLIC "d", ret)

        (void)DeleteUserIdMainPathAndBakPath(userData, HKS_KEY_STORE_PATH, HKS_STORE_SERVICE_PATH);
#ifdef SUPPORT_STORAGE_BACKUP
        (void)DeleteUserIdMainPathAndBakPath(userData, HKS_KEY_STORE_BAK_PATH, HKS_STORE_SERVICE_BAK_PATH);
#endif
    } while (0);
    HKS_FREE(userData);
    return;
}

static void DeleteUidMainPathAndBakPath(const char *userData, const char *uidData,
    const char *deDataPath, const char *ceOrEceDataPath)
{
    char dePath[HKS_MAX_DIRENT_FILE_LEN] = "";
    int32_t offset = sprintf_s(dePath, HKS_MAX_DIRENT_FILE_LEN, "%s/%s/%s",
        deDataPath, userData, uidData);
    if (offset > 0) {
        HKS_LOG_I("delete path: %" LOG_PUBLIC "s", dePath);
        (void)HksDeleteDir(dePath);
    } else {
        HKS_LOG_E("get de path failed");
    }

    char cePath[HKS_MAX_DIRENT_FILE_LEN] = "";
    offset = sprintf_s(cePath, HKS_MAX_DIRENT_FILE_LEN, "%s/%s/%s/%s",
        HKS_CE_ROOT_PATH, userData, ceOrEceDataPath, uidData);
    if (offset > 0) {
        HKS_LOG_I("delete path: %" LOG_PUBLIC "s", cePath);
        (void)HksDeleteDir(cePath);
    } else {
        HKS_LOG_E("get ce path failed");
    }

    char ecePath[HKS_MAX_DIRENT_FILE_LEN] = "";
    offset = sprintf_s(ecePath, HKS_MAX_DIRENT_FILE_LEN, "%s/%s/%s/%s",
        HKS_ECE_ROOT_PATH, userData, ceOrEceDataPath, uidData);
    if (offset > 0) {
        HKS_LOG_I("delete path: %" LOG_PUBLIC "s", ecePath);
        (void)HksDeleteDir(ecePath);
    } else {
        HKS_LOG_E("get ece path failed");
    }
}

static void DeleteUidPath(const struct HksProcessInfo *processInfo)
{
    int32_t ret;
    char *userData = NULL;
    char *uidData = NULL;
    do {
        userData = (char *)HksMalloc(HKS_MAX_FILE_NAME_LEN);
        HKS_IF_NULL_LOGE_BREAK(userData, "malloc user data failed")

        uidData = (char *)HksMalloc(HKS_MAX_FILE_NAME_LEN);
        HKS_IF_NULL_LOGE_BREAK(uidData, "malloc uid data failed")

        ret = ConstructPlainName(&processInfo->userId, userData, HKS_MAX_FILE_NAME_LEN);
        HKS_IF_NOT_SUCC_BREAK(ret, "construct user id name failed, ret = %" LOG_PUBLIC "d", ret)

        ret = ConstructPlainName(&processInfo->processName, uidData, HKS_MAX_FILE_NAME_LEN);
        HKS_IF_NOT_SUCC_BREAK(ret, "construct uid name failed, ret = %" LOG_PUBLIC "d", ret)

        (void)DeleteUidMainPathAndBakPath(userData, uidData, HKS_KEY_STORE_PATH, HKS_STORE_SERVICE_PATH);
#ifdef SUPPORT_STORAGE_BACKUP
        (void)DeleteUidMainPathAndBakPath(userData, uidData, HKS_KEY_STORE_BAK_PATH, HKS_STORE_SERVICE_BAK_PATH);
#endif
    } while (0);
    HKS_FREE(userData);
    HKS_FREE(uidData);
    return;
}
#endif

void HksServiceDeleteUserIDKeyAliasFile(const struct HksBlob *userId)
{
    char *userData = NULL;
    int32_t ret;
    do {
        userData = (char *)HksMalloc(HKS_MAX_FILE_NAME_LEN);
        HKS_IF_NULL_LOGE_BREAK(userData, "malloc user data failed")

        // construct non-plain name for de path
        ret = ConstructName(userId, userData, HKS_MAX_FILE_NAME_LEN);
        HKS_IF_NOT_SUCC_BREAK(ret, "construct user id name failed, ret = %" LOG_PUBLIC "d", ret)

        char userProcess[HKS_MAX_DIRENT_FILE_LEN] = "";
        int32_t offset = sprintf_s(userProcess, HKS_MAX_DIRENT_FILE_LEN, "%s/%s", HKS_KEY_STORE_PATH, userData);
        if (offset < 0) {
            HKS_LOG_E("concatenate UserIdPath failed.");
            ret = HKS_ERROR_BUFFER_TOO_SMALL;
            break;
        }

        // ignore these results for ensure to clear data as most as possible
        ret = HksDeleteDir(userProcess);
        HKS_IF_NOT_SUCC_LOGE(ret, "delete de path: %" LOG_PUBLIC "s failed, ret = %" LOG_PUBLIC "d", userProcess, ret)
#ifdef L2_STANDARD
        (void)DeleteUserIdPath(userId);
#endif
    } while (0);
    HKS_FREE(userData);
}

void HksServiceDeleteUIDKeyAliasFile(const struct HksProcessInfo *processInfo)
{
    char *userData = NULL;
    char *uidData = NULL;
    int32_t ret;
    do {
        userData = (char *)HksMalloc(HKS_MAX_FILE_NAME_LEN);
        HKS_IF_NULL_LOGE_BREAK(userData, "malloc user data failed")

        // construct non-plain name for de path, and skip user path for user 0
        if (processInfo->userIdInt != 0) {
            ret = ConstructName(&processInfo->userId, userData, HKS_MAX_FILE_NAME_LEN);
            HKS_IF_NOT_SUCC_BREAK(ret, "construct user id name failed, ret = %" LOG_PUBLIC "d", ret)
        }

        uidData = (char *)HksMalloc(HKS_MAX_FILE_NAME_LEN);
        if (uidData == NULL) {
            HKS_LOG_E("malloc user data failed");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        ret = ConstructName(&processInfo->processName, uidData, HKS_MAX_FILE_NAME_LEN);
        HKS_IF_NOT_SUCC_BREAK(ret, "construct uid name failed, ret = %" LOG_PUBLIC "d", ret)

        char userProcess[HKS_MAX_DIRENT_FILE_LEN] = "";
        int32_t offset = sprintf_s(userProcess, HKS_MAX_DIRENT_FILE_LEN, "%s/%s/%s",
            HKS_KEY_STORE_PATH, userData, uidData);
        if (offset < 0) {
            HKS_LOG_E("concatenate uidPath failed.");
            ret = HKS_ERROR_BUFFER_TOO_SMALL;
            break;
        }

        HKS_LOG_I("delete path : %" LOG_PUBLIC "s", userProcess);

        // ignore these results for ensure to clear data as most as possible
        ret = HksDeleteDir(userProcess);
        HKS_IF_NOT_SUCC_LOGE(ret, "delete de path: %" LOG_PUBLIC "s failed, ret = %" LOG_PUBLIC "d", userProcess, ret)
#ifdef L2_STANDARD
        (void)DeleteUidPath(processInfo);
#endif
    } while (0);
    HKS_FREE(userData);
    HKS_FREE(uidData);
}

static int32_t GetHksKeyAliasSet(const struct HksFileEntry *fileNameList, const uint32_t fileCount,
    struct HksKeyAliasSet **outData)
{
    if (fileCount == 0) {
        return HKS_SUCCESS;
    }

    int32_t ret;
    struct HksKeyAliasSet *tempAliasSet = (struct HksKeyAliasSet *)(HksMalloc(sizeof(struct HksKeyAliasSet)));
    HKS_IF_NULL_LOGE_RETURN(tempAliasSet, HKS_ERROR_MALLOC_FAIL, "malloc key alias set failed")
    tempAliasSet->aliasesCnt = fileCount;

    do {
        tempAliasSet->aliases = (struct HksBlob *)HksMalloc(fileCount * sizeof(struct HksBlob));
        if (tempAliasSet->aliases == NULL) {
            HKS_LOG_E("malloc aliases fail");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        for (uint32_t i = 0; i < fileCount; i++) {
            uint32_t size = strlen(fileNameList[i].fileName);
            tempAliasSet->aliases[i].size = size;
            tempAliasSet->aliases[i].data = (uint8_t *)HksMalloc(size);
            if (tempAliasSet->aliases[i].data == NULL) {
                HKS_LOG_E("malloc alias %" LOG_PUBLIC "d fail", i);
                ret = HKS_ERROR_MALLOC_FAIL;
                break;
            }

            ret = ConstructBlob(fileNameList[i].fileName, &(tempAliasSet->aliases[i]));
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "construct blob failed, ret = %" LOG_PUBLIC "d", ret)
        }
    } while (0);

    if (ret != HKS_SUCCESS) {
        HksFreeKeyAliasSet(tempAliasSet);
        return ret;
    }

    *outData = tempAliasSet;
    return ret;
}

static int32_t GetHksFileEntry(const struct HksStoreFileInfo *fileInfo, struct HksFileEntry **fileNameList,
    uint32_t *fileCnt)
{
    uint32_t fileCount;
    int32_t ret = GetFileCount(fileInfo->mainPath.path, &fileCount);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get storage file count, ret = %" LOG_PUBLIC "d.", ret)
    if (fileCount == 0) {
        return HKS_SUCCESS;
    }
    if (fileCount > HKS_MAX_KEY_ALIAS_COUNT) {
        HKS_LOG_E("file count too long, count = %" LOG_PUBLIC "u.", fileCount);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    struct HksFileEntry *tempFileNameList = NULL;
    uint32_t realfileCount = fileCount;
    do {
        ret = FileNameListInit(&tempFileNameList, fileCount);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init file name list failed, ret = %" LOG_PUBLIC "d", ret)
        ret = GetFileNameList(fileInfo->mainPath.path, tempFileNameList, &realfileCount);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get file name list failed, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    // case: do GetFileNameList， maybe realfileCount < fileCount
    if (ret != HKS_SUCCESS || realfileCount < fileCount) {
        FileNameListFree(&tempFileNameList, fileCount);
        return ret;
    }

    *fileCnt = fileCount;
    *fileNameList = tempFileNameList;
    return ret;
}

int32_t HksListAliasesByProcessName(const struct HksStoreFileInfo *fileInfo, struct HksKeyAliasSet **outData)
{
    int32_t ret;
    struct HksFileEntry *fileNameList = NULL;
    uint32_t fileCnt;
    do {
        ret = GetHksFileEntry(fileInfo, &fileNameList, &fileCnt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get file entry failed, ret = %" LOG_PUBLIC "d.", ret)

        // case success and has data
        if (fileNameList != NULL) {
            ret = GetHksKeyAliasSet(fileNameList, fileCnt, outData);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get key alias set failed, ret = %" LOG_PUBLIC "d.", ret)
        }
    } while (0);

    if (fileNameList != NULL) {
        FileNameListFree(&fileNameList, fileCnt);
    }
    return ret;
}

#endif

int32_t HksStoreRenameKeyAlias(const struct HksStoreFileInfo *oldFileInfo,
    const struct HksStoreFileInfo *newFileInfo, bool isCopy)
{
    int32_t ret;
    do {
        ret = CopyKeyBlobFromSrc(oldFileInfo->mainPath.path, oldFileInfo->mainPath.fileName,
            newFileInfo->mainPath.path, newFileInfo->mainPath.fileName);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks copy old key blob failed, ret = %" LOG_PUBLIC "d.", ret)
#ifdef SUPPORT_STORAGE_BACKUP
        ret = CopyKeyBlobFromSrc(oldFileInfo->bakPath.path, oldFileInfo->bakPath.fileName,
            newFileInfo->bakPath.path, newFileInfo->bakPath.fileName);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_I("Copy the old backup key failed, try to copy the new main key");
            ret = CopyKeyBlobFromSrc(newFileInfo->mainPath.path, newFileInfo->mainPath.fileName,
                newFileInfo->bakPath.path, newFileInfo->bakPath.fileName);
            if (ret != HKS_SUCCESS) {
                HKS_LOG_E("rename back key failed, try to delet the new main key. ret = %" LOG_PUBLIC "d.", ret);
                ret = HksStoreDeleteKeyBlob(newFileInfo);
                HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "delet the new key failed, ret = %" LOG_PUBLIC "d.", ret)
                ret = HKS_ERROR_CORRUPT_FILE;
                break;
            }
        }
#endif
        if (!isCopy) {
            ret = HksStoreDeleteKeyBlob(oldFileInfo);
            if (ret != HKS_SUCCESS) {
                HKS_LOG_I("Delete the old key failed, need to delete the new key");
                ret = HksStoreDeleteKeyBlob(newFileInfo);
                HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks delete new key blob failed, ret = %" LOG_PUBLIC "d.", ret)
                ret = HKS_ERROR_REMOVE_FILE_FAIL;
            }
        }
    } while (0);
    return ret;
}

#endif /* _CUT_AUTHENTICATE_ */
