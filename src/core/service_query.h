#pragma once
#include <string>
#include <vector>
#include <windows.h>
#include "../common/types.h"

namespace LicenseInspector {
namespace Core {

    struct ServiceStatusInfo {
        bool         exists      = false;
        bool         running     = false;
        DWORD        startType   = 0; 
        std::wstring binaryPath;
        std::wstring serviceName;
        std::wstring displayName;
    };

    class ServiceQuery {
    public:
        static CollectorResult<ServiceStatusInfo> queryService(const std::wstring& serviceName);
        static std::vector<CollectorResult<ServiceStatusInfo>> checkSuspiciousServices(const std::vector<std::wstring>& targetNames);
    };

} // namespace Core
} // namespace LicenseInspector
