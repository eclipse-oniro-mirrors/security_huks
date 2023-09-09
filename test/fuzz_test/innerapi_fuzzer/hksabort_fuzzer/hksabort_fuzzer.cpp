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
#include "hksabort_fuzzer.h"

#include <securec.h>

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_type.h"
#include "hks_param.h"

const int BLOB_SIZE = 10;

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
    {
        uint8_t *myData = static_cast<uint8_t *>(HksMalloc(sizeof(uint8_t) * size));

        if (data == nullptr || size <= (sizeof(struct HksParamSet) + BLOB_SIZE)) {
            return false;
        }

        if (myData == nullptr) {
            return false;
        }

        (void)memcpy_s(myData, size, data, size);

        struct HksBlob handle = { BLOB_SIZE, myData };
        struct HksParamSet *paramSet = reinterpret_cast<struct HksParamSet *>(myData + BLOB_SIZE);
        paramSet->paramSetSize = size - BLOB_SIZE;

        (void)HksAbort(&handle, paramSet);

        HksFree(myData);
        return true;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}