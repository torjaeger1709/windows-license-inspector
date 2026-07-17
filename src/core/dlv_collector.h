#pragma once
#include <string>
#include <vector>
#include <utility>
#include "common/types.h"

namespace LicenseInspector::Core {

struct EditionAlias {
    std::wstring  token;
    EditionFamily family;
};

class SemanticNormalizer {
public:
    static EditionFamily parseEditionFamilyByTokens(const std::wstring& raw);
    static std::wstring  normalizeEdition(const std::wstring& rawName, const std::wstring& rawDesc);
    static std::wstring  normalizeChannel(const std::wstring& rawDesc, const std::wstring& rawChannel);
    static std::wstring  normalizeStatus(const std::wstring& rawStatus);

    static NormalizedLicenseData normalizeWmi(const std::wstring& name, const std::wstring& desc, 
                                              const std::wstring& status, const std::wstring& pKey, 
                                              const std::wstring& kmsHost);
    static NormalizedLicenseData normalizeDlv(const std::wstring& rawText, bool success);
};

class DlvCollector {
public:
    static std::pair<std::wstring, CollectorProvenance> executeSafePipe();

    static CollectorConsensus crossValidate(const NormalizedLicenseData& wmi, const NormalizedLicenseData& dlv,
                                            const CollectorProvenance& wmiProv, const CollectorProvenance& dlvProv);
};

} // namespace LicenseInspector::Core
