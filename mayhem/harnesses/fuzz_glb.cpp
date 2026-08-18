// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
//
// mayhem/harnesses/fuzz_glb.cpp -- libFuzzer harness for glTF-SDK's GLB binary container reader.
//
// A GLB file is a 12-byte header (magic "glTF", version, total length) followed by a JSON chunk
// and an optional BIN chunk, each itself length-prefixed and type-tagged
// (GLTFSDK/Source/GLBResourceReader.cpp:Init()). This harness feeds the raw fuzzer bytes to
// GLBResourceReader over an in-memory std::istringstream (no temp files -- SPEC 6.2 item 13),
// which parses that chunked framing (including the 64-bit-computed length-sum checks added to
// guard against 32-bit overflow) and extracts the embedded JSON manifest. It then deserializes
// that JSON exactly like fuzz_gltf and walks the resulting Document -- additionally exercising
// accessors whose buffer.uri is empty/`data:,` (GLBResourceReader::GetBinaryStream), which read
// straight from the GLB's own embedded BIN chunk instead of an external file or a base64 URI --
// a code path fuzz_gltf's plain-JSON input can never reach.
//
// See mayhem/harnesses/fuzz_common.h for the shared no-filesystem plumbing, the walk's bounding
// rationale, and why GLTFException/std::exception is the expected (not masked) outcome here.
#include "fuzz_common.h"

#include <GLTFSDK/Deserialize.h>
#include <GLTFSDK/GLBResourceReader.h>

#include <memory>
#include <sstream>
#include <string>

using namespace MayhemFuzz;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0 || size > kMaxInputSize)
    {
        return 0;
    }

    try
    {
        auto glbStream = std::make_shared<std::istringstream>(
            std::string(reinterpret_cast<const char*>(data), size),
            std::ios::in | std::ios::binary);

        GLBResourceReader reader(std::make_shared<NullStreamReader>(), glbStream);

        Document document = Deserialize(reader.GetJson());
        WalkDocument(document, reader);
    }
    catch (const std::exception&)
    {
        // Expected: bad magic/version, a truncated/oversized chunk, a length-sum mismatch, a
        // JSON/schema violation in the embedded manifest, or std::bad_alloc from a pathological
        // declared size.
    }

    return 0;
}
