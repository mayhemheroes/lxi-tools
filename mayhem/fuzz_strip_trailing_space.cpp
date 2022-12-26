#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" void strip_trailing_space(char *line);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    char* line = strdup(provider.ConsumeRandomLengthString().c_str());

    strip_trailing_space(line);

    free(line);
    return 0;
}
