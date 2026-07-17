#include "service_query.h"
#include <windows.h>
#include <winsvc.h>
#include <chrono>
#include <vector>

namespace LicenseInspector {
namespace Core {

    CollectorResult<ServiceStatusInfo> ServiceQuery::queryService(const std::wstring& serviceName) {
        auto startTime = std::chrono::high_resolution_clock::now();
        std::wstring collectorName = L"ServiceCollector";

        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCM) {
            DWORD err = GetLastError();
            auto endTime = std::chrono::high_resolution_clock::now();
            double ms = std::chrono::duration<double, std::milli>(endTime - startTime).count();
            if (err == ERROR_ACCESS_DENIED) {
                return CollectorResult<ServiceStatusInfo>::accessDenied(EvidenceReliability::VERIFIED, collectorName, L"OpenSCManagerW Access Denied");
            }
            return CollectorResult<ServiceStatusInfo>::notFound(EvidenceReliability::VERIFIED, collectorName, ms);
        }

        SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
        if (!hService) {
            DWORD err = GetLastError();
            CloseServiceHandle(hSCM);
            auto endTime = std::chrono::high_resolution_clock::now();
            double ms = std::chrono::duration<double, std::milli>(endTime - startTime).count();
            if (err == ERROR_ACCESS_DENIED) {
                return CollectorResult<ServiceStatusInfo>::accessDenied(EvidenceReliability::VERIFIED, collectorName, L"OpenServiceW Access Denied for " + serviceName);
            }
            return CollectorResult<ServiceStatusInfo>::notFound(EvidenceReliability::VERIFIED, collectorName, ms);
        }

        ServiceStatusInfo info;
        info.exists = true;
        info.serviceName = serviceName;

        SERVICE_STATUS_PROCESS ssp = {};
        DWORD bytesNeeded = 0;
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded)) {
            info.running = (ssp.dwCurrentState == SERVICE_RUNNING);
        }

        QueryServiceConfigW(hService, nullptr, 0, &bytesNeeded);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && bytesNeeded > 0) {
            std::vector<BYTE> buffer(bytesNeeded);
            LPQUERY_SERVICE_CONFIGW pConfig = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());
            if (QueryServiceConfigW(hService, pConfig, bytesNeeded, &bytesNeeded)) {
                info.startType = pConfig->dwStartType;
                if (pConfig->lpBinaryPathName) info.binaryPath = pConfig->lpBinaryPathName;
                if (pConfig->lpDisplayName) info.displayName = pConfig->lpDisplayName;
            }
        }

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);

        auto endTime = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        return CollectorResult<ServiceStatusInfo>::success(std::move(info), EvidenceReliability::VERIFIED, collectorName, ms);
    }

    std::vector<CollectorResult<ServiceStatusInfo>> ServiceQuery::checkSuspiciousServices(const std::vector<std::wstring>& targetNames) {
        std::vector<CollectorResult<ServiceStatusInfo>> results;
        for (const auto& name : targetNames) {
            auto res = queryService(name);
            if (res.verificationStatus == VerificationStatus::FOUND || res.verificationStatus == VerificationStatus::ACCESS_DENIED) {
                results.push_back(std::move(res));
            }
        }
        return results;
    }

} // namespace Core
} // namespace LicenseInspector
