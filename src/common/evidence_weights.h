#pragma once
#include <string>

namespace LicenseInspector {

// Forward declaration if needed before inclusion
struct FindingResult;

namespace Weights {

    class WeightResolver {
    public:
        static int resolve(const FindingResult& finding);
        static int resolve(const std::wstring& checkId, int ageDays = -1);
    };

    inline int WeightResolver::resolve(const std::wstring& checkId, int ageDays) {
        (void)checkId;
        (void)ageDays;
        return 0;
    }

} // namespace Weights
} // namespace LicenseInspector
