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

#include "hksgetstorage_fuzzer.h"

#include "hks_fuzz_util.h"

constexpr int STORAGE_BUF_SIZE = 4096;

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

    std::vector<uint8_t> outBuf(STORAGE_BUF_SIZE, 0);
    struct HksBlob data = { STORAGE_BUF_SIZE, outBuf.data() };

    return HksGetStorage(&keyAlias, ps.s, &data);
}

}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    struct HksBlob keyAlias = { 13, reinterpret_cast<uint8_t *>(const_cast<char *>("fuzz_getstor")) };
    WrapParamSet ps = BuildFixedParamSet({});
    struct HksBlob data = { 0, nullptr };
    int32_t ret = HksGetStorage(&keyAlias, ps.s, &data);
    printf("fuzz_getstorage init: HksGetStorage ret=%d\n", ret);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);
    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}
