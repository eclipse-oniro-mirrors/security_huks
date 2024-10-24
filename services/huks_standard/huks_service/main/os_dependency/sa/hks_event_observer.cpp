/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hks_event_observer.h"

#include "common_event_support.h"
#include "rwlock.h"
#ifdef HAS_OS_ACCOUNT_PART
#include "os_account_manager.h"
#endif
#include "hks_client_service.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_plugin_adapter.h"
#include "hks_type_inner.h"
#include "hks_template.h"
#include "hks_upgrade.h"
#include "hks_upgrade_lock.h"

#include "securec.h"

#define USER_ID_ROOT                  "0"
#ifndef HAS_OS_ACCOUNT_PART
constexpr static int UID_TRANSFORM_DIVISOR = 200000;
static void GetOsAccountIdFromUid(int uid, int &osAccountId)
{
    osAccountId = uid / UID_TRANSFORM_DIVISOR;
}
#endif // HAS_OS_ACCOUNT_PART

static void GetProcessInfo(int userId, int uid, struct HksProcessInfo *processInfo)
{
    uint32_t userSize = sizeof(userId);
    if (userId == 0) {
        userSize = strlen(USER_ID_ROOT);
    }
    uint8_t *userData = static_cast<uint8_t *>(HksMalloc(userSize));
    if (userData == nullptr) {
        HKS_LOG_E("user id malloc failed.");
        return;
    }
    if (userId == 0) {
        (void)memcpy_s(userData, userSize, USER_ID_ROOT, userSize);
    } else {
        (void)memcpy_s(userData, userSize, &userId, userSize);
    }
    processInfo->userId.size = userSize;
    processInfo->userId.data = userData;
    processInfo->userIdInt = userId;

    uint32_t uidSize = sizeof(uid);
    uint8_t *uidData = static_cast<uint8_t *>(HksMalloc(uidSize));
    if (uidData == nullptr) {
        HKS_LOG_E("uid malloc failed.");
        HKS_FREE(userData);
        processInfo->userId.data = nullptr;
        return;
    }
    (void)memcpy_s(uidData, uidSize, &uid, uidSize);
    processInfo->processName.size = uidSize;
    processInfo->processName.data = uidData;
}

static void GetUserId(int userId, struct HksBlob *userIdBlob)
{
    uint32_t userIdSize = sizeof(userId);
    uint8_t *userIdData = static_cast<uint8_t *>(HksMalloc(userIdSize));
    if (userIdData == nullptr) {
        HKS_LOG_E("uid malloc failed.");
        return;
    }
    (void)memcpy_s(userIdData, userIdSize, &userId, userIdSize);
    userIdBlob->size = userIdSize;
    userIdBlob->data = userIdData;
}

namespace OHOS {
namespace Security {
namespace Hks {
std::shared_ptr<SystemEventSubscriber> SystemEventObserver::systemEventSubscriber_ = nullptr;
std::shared_ptr<SystemEventSubscriber> SystemEventObserver::backUpEventSubscriber_ = nullptr;
const static std::string RESTORE_EVENT_NAME = "COMMON_EVENT_RESTORE_START";
const int32_t BACKUP_UID = 1089;

void SystemEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    struct HksProcessInfo processInfo = { { 0, nullptr }, { 0, nullptr } };

    auto want = data.GetWant();
    constexpr const char* UID = "uid";
    std::string action = want.GetAction();

    // judge whether is upgrading, wait for upgrade finished
    if (HksWaitIfPowerOnUpgrading() != HKS_SUCCESS) {
        HKS_LOG_E("wait on upgrading failed.");
        return;
    }
    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> readGuard(g_upgradeOrRequestLock);

    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED ||
        action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED) {
        int uid = want.GetIntParam(UID, -1);
        int userId = -1;
#ifdef HAS_OS_ACCOUNT_PART
        OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
#else // HAS_OS_ACCOUNT_PART
        GetOsAccountIdFromUid(uid, userId);
#endif // HAS_OS_ACCOUNT_PART
        HKS_LOG_I("HksService package removed: uid is %" LOG_PUBLIC "d userId is %" LOG_PUBLIC "d", uid, userId);

        GetProcessInfo(userId, uid, &processInfo);
        HksServiceDeleteProcessInfo(&processInfo);
    } else if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        int userId = data.GetCode();
        HKS_LOG_I("HksService user removed: userId is %" LOG_PUBLIC "d", userId);

        GetUserId(userId, &(processInfo.userId));
        HksServiceDeleteProcessInfo(&processInfo);
    } else if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) {
        HKS_LOG_I("the credential-encrypted storage has become unlocked");
        int userId = data.GetCode();
        HKS_LOG_I("user %" LOG_PUBLIC "d unlocked.", userId);
        HksUpgradeOnUserUnlock(userId);
    }

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
    HksPluginOnReceiveEvent(&data);
}

SystemEventObserver::~SystemEventObserver()
{
    UnSubscribeEvent();
}

bool SystemEventObserver::SubscribeSystemEvent()
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    systemEventSubscriber_ = std::make_shared<SystemEventSubscriber>(subscriberInfo);

    HKS_IF_NULL_LOGE_RETURN(systemEventSubscriber_, false, "huks system subscriber nullptr")

    return OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(systemEventSubscriber_);
}

bool SystemEventObserver::SubscribeBackUpEvent()
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(RESTORE_EVENT_NAME);
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetPublisherUid(BACKUP_UID);
    backUpEventSubscriber_ = std::make_shared<SystemEventSubscriber>(subscriberInfo);

    HKS_IF_NULL_LOGE_RETURN(backUpEventSubscriber_, false, "huks Backup subscriber nullptr")

    return OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(backUpEventSubscriber_);
}

bool SystemEventObserver::SubscribeEvent()
{
    return SubscribeSystemEvent() && SubscribeBackUpEvent();
}

bool SystemEventObserver::DoUnSubscribe(std::shared_ptr<SystemEventSubscriber> subscriber)
{
    HKS_IF_NULL_LOGE_RETURN(subscriber, false, "huks system subscriber nullptr");
    return OHOS::EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber);
}

bool SystemEventObserver::UnSubscribeEvent()
{
    return DoUnSubscribe(systemEventSubscriber_) && DoUnSubscribe(backUpEventSubscriber_);
}
} // namespace Hks
} // namespace Security
} // namespace OHOS
