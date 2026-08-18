// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
//
// mayhem/harnesses/fuzz_common.h -- shared, filesystem-free plumbing for the glTF-SDK fuzz
// harnesses (fuzz_gltf.cpp, fuzz_glb.cpp).
//
// NullStreamReader: glTF-SDK is decoupled from all file I/O via IStreamReader (see
// GLTFSDK/Inc/GLTFSDK/IStreamReader.h and the sample in GLTFSDK.Samples/Deserialize). A fuzzed
// glTF/GLB blob is a single buffer with no companion files on disk (no /mayhem writes either --
// the image is read-only during coverage collection, SPEC 6.2 item 13), so any external URI
// (a relative .bin/.png filename) simply cannot be resolved. Throwing is the correct, EXPECTED
// behavior here -- it is exactly what a real embedder does when asked to load a glTF whose
// referenced side-car file is missing. Base64 `data:` URIs and (for fuzz_glb) the embedded GLB
// BIN chunk are both handled by glTF-SDK WITHOUT ever calling GetInputStream, so this still lets
// the harness reach the binary-accessor-read code paths.
//
// WalkDocument: after Deserialize() succeeds, exercises a bounded, NON-recursive slice of the
// object graph -- flat IndexedContainers only (meshes/primitives, accessors, bufferViews,
// images). Document has no parent/child node-graph walk here on purpose: a scene's node
// hierarchy can be attacker-shaped into a cycle, and libFuzzer cannot interrupt a stuck
// iteration (SPEC 6b), so a naive recursive walk over document.nodes would risk turning one
// malformed input into a hung campaign. The containers used below are plain vectors with no
// cross-references walked recursively, so there is no such hazard, and each container is capped
// at kMaxElementsWalked so a document declaring thousands of meshes/accessors cannot dominate a
// whole run. An individual element's declared byteLength/count is deliberately NOT capped --
// std::bad_alloc or an ASan allocation-size-too-big abort on a single pathological
// accessor/bufferView is a real finding (SPEC 6b: never mask crashes/OOMs), not a hang.
//
// GLTFException (and std::exception generally, e.g. bad_alloc) is the EXPECTED outcome for a
// mostly-invalid fuzz corpus and is caught by both harnesses. Neither harness uses a bare
// `catch (...)` -- sanitizer aborts never unwind as a C++ exception, so ASan/UBSan findings
// still surface.
#pragma once

#include <GLTFSDK/Constants.h>
#include <GLTFSDK/Document.h>
#include <GLTFSDK/GLTFResourceReader.h>
#include <GLTFSDK/IStreamReader.h>

#include <cstdint>
#include <stdexcept>

namespace MayhemFuzz
{
    using namespace Microsoft::glTF;

    // Absurdly generous upper bound for a glTF JSON/GLB fuzz input -- large enough that no real
    // seed or mutation is ever rejected, small enough to keep one iteration's cost bounded.
    constexpr size_t kMaxInputSize = 8 * 1024 * 1024; // 8 MiB

    // Per-container cap on how many elements WalkDocument visits (see header comment above).
    constexpr size_t kMaxElementsWalked = 512;

    class NullStreamReader : public IStreamReader
    {
    public:
        std::shared_ptr<std::istream> GetInputStream(const std::string& filename) const override
        {
            throw std::runtime_error("fuzz harness has no filesystem access: " + filename);
        }
    };

    // Reads an accessor's binary data through the type-checked overload that matches its
    // declared componentType (calling the wrong instantiation just throws
    // "does not match accessor ComponentType" without touching the real read path).
    inline void ReadAccessorBytes(const Document& document, const GLTFResourceReader& reader, const Accessor& accessor)
    {
        switch (accessor.componentType)
        {
        case COMPONENT_BYTE:
            (void)reader.ReadBinaryData<int8_t>(document, accessor);
            break;
        case COMPONENT_UNSIGNED_BYTE:
            (void)reader.ReadBinaryData<uint8_t>(document, accessor);
            break;
        case COMPONENT_SHORT:
            (void)reader.ReadBinaryData<int16_t>(document, accessor);
            break;
        case COMPONENT_UNSIGNED_SHORT:
            (void)reader.ReadBinaryData<uint16_t>(document, accessor);
            break;
        case COMPONENT_UNSIGNED_INT:
            (void)reader.ReadBinaryData<uint32_t>(document, accessor);
            break;
        case COMPONENT_FLOAT:
            (void)reader.ReadBinaryData<float>(document, accessor);
            break;
        default:
            break; // unknown/unsupported componentType -- nothing meaningful to read
        }
    }

    inline void WalkDocument(const Document& document, const GLTFResourceReader& reader)
    {
        size_t n = 0;
        for (const auto& mesh : document.meshes.Elements())
        {
            if (++n > kMaxElementsWalked) break;

            for (const auto& primitive : mesh.primitives)
            {
                std::string accessorId;
                if (primitive.TryGetAttributeAccessorId(ACCESSOR_POSITION, accessorId))
                {
                    ReadAccessorBytes(document, reader, document.accessors.Get(accessorId));
                }

                if (!primitive.indicesAccessorId.empty())
                {
                    ReadAccessorBytes(document, reader, document.accessors.Get(primitive.indicesAccessorId));
                }
            }
        }

        n = 0;
        for (const auto& accessor : document.accessors.Elements())
        {
            if (++n > kMaxElementsWalked) break;
            ReadAccessorBytes(document, reader, accessor);
        }

        n = 0;
        for (const auto& bufferView : document.bufferViews.Elements())
        {
            if (++n > kMaxElementsWalked) break;
            (void)reader.ReadBinaryData<uint8_t>(document, bufferView);
        }

        n = 0;
        for (const auto& image : document.images.Elements())
        {
            if (++n > kMaxElementsWalked) break;
            (void)reader.ReadBinaryData(document, image);
        }
    }
}
