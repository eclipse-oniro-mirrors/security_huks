/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "hkssetstorage_fuzzer.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (alias.size() == 0) {
        alias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t dataSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 4096);
    std::vector<uint8_t> dataBuf = fdp.ConsumeBytes<uint8_t>(dataSize);
    if (dataBuf.size() == 0) {
        dataBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob data = { static_cast<uint32_t>(dataBuf.size()), dataBuf.data() };

    return HksSetStorage(&keyAlias, ps.s, &data);
}

}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    struct HksBlob keyAlias = { 13, reinterpret_cast<uint8_t *>(const_cast<char *>("fuzz_setstor")) };
    WrapParamSet ps = BuildFixedParamSet({});
    struct HksBlob data = { 5, reinterpret_cast<uint8_t *>(const_cast<char *>("hello")) };
    int32_t ret = HksSetStorage(&keyAlias, ps.s, &data);
    printf("fuzz_setstorage init: HksSetStorage ret=%d\n", ret);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);
    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}
