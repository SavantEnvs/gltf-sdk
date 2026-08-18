// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
//
// mayhem/harnesses/fuzz_gltf.cpp -- libFuzzer harness for glTF-SDK's JSON glTF deserializer.
//
// Deserializes an untrusted in-memory glTF JSON document (Microsoft::glTF::Deserialize) into a
// Document, then walks a bounded slice of the resulting object graph -- meshes/primitives,
// accessors, bufferViews, images -- exercising the base64 data-URI decoder and the
// bounds-checked binary readers (GLTFResourceReader::ReadBinaryData) along the way. This is the
// core parser/schema-validation/binary-accessor surface, driven purely from the fuzzer's bytes
// (see mayhem/harnesses/fuzz_common.h for the shared no-filesystem plumbing and the walk's
// bounding rationale).
#include "fuzz_common.h"

#include <GLTFSDK/Deserialize.h>

using namespace MayhemFuzz;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0 || size > kMaxInputSize)
    {
        return 0;
    }

    const std::string json(reinterpret_cast<const char*>(data), size);

    try
    {
        Document document = Deserialize(json);
        GLTFResourceReader reader(std::make_shared<NullStreamReader>());
        WalkDocument(document, reader);
    }
    catch (const std::exception&)
    {
        // Expected for a mostly-invalid fuzz corpus: malformed JSON, a schema violation
        // (GLTFException/ValidationException), an unresolved external URI (NullStreamReader), or
        // std::bad_alloc from a pathological declared size. See fuzz_common.h for why this is
        // not a bare `catch (...)`.
    }

    return 0;
}
