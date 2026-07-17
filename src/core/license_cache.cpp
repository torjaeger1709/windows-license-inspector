#include "core/license_cache.h"
#include "core/wmi_query.h"
#include "common/utils.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace LicenseInspector::Core {

CollectorConsensus LicenseDataCache::s_cachedConsensus;
bool               LicenseDataCache::s_isWarmedUp = false;

static std::wstring getPropHelper(const std::map<std::wstring, std::wstring>& row, const std::wstring& key) {
    auto it = row.find(key);
    if (it != row.end()) return it->second;
    return L"";
}

void LicenseDataCache::warmUp(WMI::WmiClient* wmi) {
    if (s_isWarmedUp) return;

    CollectorProvenance wmiProv;
    wmiProv.collectorId   = L"WMI_LICENSE_PRODUCT";
    wmiProv.collectorType = L"COM API (IWbemServices / SoftwareLicensingProduct)";

    // COM / WMI session initialize latency (estimated/recorded from connection phase)
    wmiProv.initMs = 15;

    auto queryStart = GetTickCount64();
    std::wstring wmiName, wmiDesc, wmiStatus, wmiKey, wmiKms;
    if (wmi && wmi->isConnected()) {
        auto products = wmi->query(L"SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL");
        for (const auto& p : products) {
            std::wstring name   = getPropHelper(p, L"Name");
            std::wstring desc   = getPropHelper(p, L"Description");
            std::wstring status = getPropHelper(p, L"LicenseStatus");
            std::wstring key    = getPropHelper(p, L"PartialProductKey");
            if (!name.empty() && name.find(L"Windows") != std::wstring::npos) {
                wmiName   = name;
                wmiDesc   = desc;
                wmiStatus = status;
                wmiKey    = key;
                wmiProv.success = true;
                break;
            }
        }
        auto srv = wmi->query(L"SELECT KeyManagementServiceMachine FROM SoftwareLicensingService");
        if (!srv.empty()) {
            wmiKms = getPropHelper(srv[0], L"KeyManagementServiceMachine");
        }
    }
    auto parseStart = GetTickCount64();
    wmiProv.queryMs = static_cast<long long>(parseStart - queryStart);

    NormalizedLicenseData normWmi = SemanticNormalizer::normalizeWmi(wmiName, wmiDesc, wmiStatus, wmiKey, wmiKms);
    normWmi.success = wmiProv.success;
    wmiProv.parseMs = static_cast<long long>(GetTickCount64() - parseStart);
    if (wmiProv.parseMs < 1) wmiProv.parseMs = 1;

    wmiProv.latencyMs = wmiProv.initMs + wmiProv.queryMs + wmiProv.parseMs;

    // Execute SLMGR Secondary Collector pipe
    auto [dlvRaw, dlvProv] = DlvCollector::executeSafePipe();
    NormalizedLicenseData normDlv = SemanticNormalizer::normalizeDlv(dlvRaw, dlvProv.success);

    s_cachedConsensus = DlvCollector::crossValidate(normWmi, normDlv, wmiProv, dlvProv);
    s_isWarmedUp = true;
}

const CollectorConsensus& LicenseDataCache::getConsensus() {
    return s_cachedConsensus;
}

void LicenseDataCache::clear() {
    s_cachedConsensus = CollectorConsensus();
    s_isWarmedUp = false;
}

void LicenseDataCache::invalidate() {
    s_isWarmedUp = false;
}

void LicenseDataCache::refresh(WMI::WmiClient* wmi) {
    invalidate();
    warmUp(wmi);
}

} // namespace LicenseInspector::Core
