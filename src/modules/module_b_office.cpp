#include "modules/module_b_office.h"
#include "core/registry_query.h"
#include "common/utils.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace LicenseInspector::ModuleB {

static std::wstring licenseStatusDescription(const std::wstring& statusStr) {
    try {
        int s = std::stoi(statusStr);
        switch (s) {
            case 0: return L"Unlicensed (0)";
            case 1: return L"Licensed - Genuine (1)";
            case 2: return L"OOB Grace - In-box evaluation period (2)";
            case 3: return L"OOT Grace - KMS server unreachable (3)";
            case 4: return L"NonGenuine Grace - Validation failed (4)";
            case 5: return L"Notification mode - Watermark active (5)";
            case 6: return L"Extended Grace - Continued after validation fail (6)";
            default: return L"Unknown status (" + statusStr + L")";
        }
    } catch (...) {
        return L"Unknown (" + statusStr + L")";
    }
}

std::vector<FindingResult> queryOfficeWmi(WMI::WmiClient& wmiCimv2) {
    constexpr auto ID       = L"B1";
    constexpr auto CATEGORY = L"Office 16 WMI License Status";

    (void)wmiCimv2;
    std::vector<FindingResult> results;
    static const std::vector<std::wstring> namespaces = {
        L"ROOT\\OfficeSoftwareProtectionPlatform",
        L"ROOT\\Microsoft\\Office\\16",
    };

    std::unique_ptr<WMI::WmiClient> officeWmi;
    for (const auto& ns : namespaces) {
        try {
            auto client = std::make_unique<WMI::WmiClient>(ns);
            if (client->isConnected()) {
                officeWmi = std::move(client);
                break;
            }
        } catch (...) {}
    }

    if (!officeWmi || !officeWmi->isConnected()) {
        auto c2rProduct = Registry::readString(HKEY_LOCAL_MACHINE,
            LR"(SOFTWARE\Microsoft\Office\ClickToRun\Configuration)",
            L"ProductReleaseIds");
        auto c2rVersion = Registry::readString(HKEY_LOCAL_MACHINE,
            LR"(SOFTWARE\Microsoft\Office\ClickToRun\Configuration)",
            L"VersionToReport");

        std::wstring detail = L"Office WMI namespace not available. ";
        if (c2rProduct) detail += L"C2R Product=" + *c2rProduct + L" ";
        if (c2rVersion) detail += L"Version=" + *c2rVersion;
        if (!c2rProduct && !c2rVersion)
            detail += L"Office may not be installed or is not Office 16.";

        results.push_back(FindingResult::unavailable(ID, CATEGORY, detail));
        return results;
    }

    const std::wstring wql =
        L"SELECT Name, LicenseStatus, GracePeriodRemaining, ProductKeyChannel, "
        L"PartialProductKey FROM OfficeSoftwareProtectionProduct "
        L"WHERE PartialProductKey IS NOT NULL";

    auto rows = officeWmi->query(wql);

    if (rows.empty()) {
        auto allRows = officeWmi->query(
            L"SELECT Name, LicenseStatus FROM OfficeSoftwareProtectionProduct");
        std::wstring detail = allRows.empty()
            ? L"WMI connected successfully, but no Office products found."
            : L"Found " + std::to_wstring(allRows.size()) +
              L" Office product(s) without PartialProductKey (unactivated or trial).";
        results.push_back(FindingResult::unavailable(ID, CATEGORY, detail));
        return results;
    }


    for (const auto& row : rows) {
        std::wstring name, statusStr, graceStr, channel, partialKey;
        if (auto it = row.find(L"Name");                 it != row.end()) name       = it->second;
        if (auto it = row.find(L"LicenseStatus");        it != row.end()) statusStr  = it->second;
        if (auto it = row.find(L"GracePeriodRemaining"); it != row.end()) graceStr   = it->second;
        if (auto it = row.find(L"ProductKeyChannel");    it != row.end()) channel    = it->second;
        if (auto it = row.find(L"PartialProductKey");    it != row.end()) partialKey = it->second;

        if (name.empty()) continue;

        std::wstring statusDesc = licenseStatusDescription(statusStr);
        std::wstring value = L"Key: xxxxx-" + partialKey +
                             L"  |  Channel: " + channel +
                             L"  |  Status: " + statusDesc;

        int statusInt = -1;
        try { statusInt = std::stoi(statusStr); } catch (...) {}

        std::wstring chanUpper = channel;
        std::transform(chanUpper.begin(), chanUpper.end(), chanUpper.begin(), ::towupper);

        bool isKms = chanUpper.find(L"VOLUME_KMSCLIENT") != std::wstring::npos ||
                     chanUpper.find(L"VOLUME:GVLK")      != std::wstring::npos;

        if (isKms && statusInt == 3) {
            std::wstring detail =
                L"Office KMS license is in OOT Grace (KMS server unreachable or subscription refresh needed).";
            results.push_back(FindingResult(ID, CATEGORY, detail, value, Severity::WARNING, true, true, FindingType::LICENSE_STATE, ForensicSource::LICENSE_STATE, EvidenceImpact::INFO_ONLY, EvidenceQuality::INFO_ONLY, EvidenceReliability::STRONG));
        }
        else if (statusInt == 4 || statusInt == 5 || statusInt == 6) {
            std::wstring detail =
                L"Office license is in NOTIFICATION/UNLICENSED state. "
                L"Activation pending or subscription expired.";
            results.push_back(FindingResult(ID, CATEGORY, detail, value, Severity::WARNING, true, true, FindingType::LICENSE_STATE, ForensicSource::LICENSE_STATE, EvidenceImpact::INFO_ONLY, EvidenceQuality::INFO_ONLY, EvidenceReliability::STRONG));
        }
        else if (isKms && statusInt == 1) {
            std::wstring detail =
                L"Office activated via KMS channel (VOLUME_KMSCLIENT). "
                L"Legitimate in corporate/educational domain environments.";
            results.push_back(FindingResult(ID, CATEGORY, detail, value, Severity::INFO, false, true, FindingType::LICENSE_STATE, ForensicSource::LICENSE_STATE, EvidenceImpact::INFO_ONLY, EvidenceQuality::INFO_ONLY, EvidenceReliability::STRONG));
        }
        else if (statusInt == 1) {
            std::wstring detail = L"Office license appears genuine. " + statusDesc;
            std::wstring catName = std::wstring(CATEGORY) + L" - " + name;
            results.push_back(FindingResult::clean(ID, catName, detail, FindingType::LICENSE_STATE));
            results.back().value = value;
        }
        else if (statusInt == 2) {
            std::wstring detail =
                L"Office is in Out-of-Box grace period. "
                L"Activation required within 30 days.";
            results.push_back(FindingResult(ID, CATEGORY, detail, value, Severity::INFO, false, true, FindingType::LICENSE_STATE, ForensicSource::LICENSE_STATE, EvidenceImpact::INFO_ONLY, EvidenceQuality::INFO_ONLY, EvidenceReliability::STRONG));
        }
        else {
            std::wstring detail = L"Office license status: " + statusDesc;
            results.push_back(FindingResult(ID, CATEGORY, detail, value, Severity::INFO, false, true, FindingType::LICENSE_STATE, ForensicSource::LICENSE_STATE, EvidenceImpact::INFO_ONLY, EvidenceQuality::INFO_ONLY, EvidenceReliability::STRONG));
        }
    }

    return results;
}

std::vector<FindingResult> parseOsppVbs() {
    constexpr auto ID       = L"B2";
    constexpr auto CATEGORY = L"Office 16 OSPP.VBS License Parser";

    std::vector<FindingResult> results;
    std::vector<std::wstring> candidatePaths;

    auto msiRoot = Registry::readString(HKEY_LOCAL_MACHINE,
        LR"(SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot)",
        L"Path");
    if (msiRoot && !msiRoot->empty()) {
        std::wstring p = *msiRoot;
        if (p.back() != L'\\') p += L'\\';
        candidatePaths.push_back(p + L"OSPP.VBS");
    }

    auto c2rPath = Registry::readString(HKEY_LOCAL_MACHINE,
        LR"(SOFTWARE\Microsoft\Office\ClickToRun\Configuration)",
        L"InstallationPath");
    if (c2rPath && !c2rPath->empty()) {
        std::wstring p = *c2rPath;
        if (p.back() != L'\\') p += L'\\';
        candidatePaths.push_back(p + L"root\\Office16\\OSPP.VBS");
    }

    candidatePaths.insert(candidatePaths.end(), {
        L"C:\\Program Files\\Microsoft Office\\Office16\\OSPP.VBS",
        L"C:\\Program Files (x86)\\Microsoft Office\\Office16\\OSPP.VBS",
        L"C:\\Program Files\\Microsoft Office\\root\\Office16\\OSPP.VBS",
        L"C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\OSPP.VBS",
        L"C:\\Program Files\\Common Files\\Microsoft Shared\\OfficeSoftwareProtectionPlatform\\OSPP.VBS",
        L"C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OfficeSoftwareProtectionPlatform\\OSPP.VBS",
    });

    std::wstring osppVbsPath;
    for (const auto& p : candidatePaths) {
        if (Utils::pathExists(p)) {
            osppVbsPath = p;
            break;
        }
    }

    if (osppVbsPath.empty()) {
        std::wstring searched;
        for (size_t i = 0; i < std::min(candidatePaths.size(), size_t(3)); ++i)
            searched += L"\n           " + candidatePaths[i];

        std::wstring detail =
            L"OSPP.VBS not found. Searched paths include:" + searched +
            L"\n           If you use Office Click-to-Run (2021/365), "
            L"check installed Office folder.";
        results.push_back(FindingResult::unavailable(ID, CATEGORY, detail));
        return results;
    }

    std::wstring cmdLine =
        L"cscript.exe //Nologo \"" + osppVbsPath + L"\" /dstatus";

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength              = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle       = TRUE;   

    HANDLE hReadPipe  = nullptr;
    HANDLE hWritePipe = nullptr;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        results.push_back(FindingResult::unavailable(ID, CATEGORY,
            L"Failed to create stdout pipe for cscript.exe."));
        return results;
    }
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {};
    si.cb          = sizeof(STARTUPINFOW);
    si.hStdOutput  = hWritePipe;
    si.hStdError   = hWritePipe;   
    si.dwFlags     = STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi = {};
    BOOL created = CreateProcessW(
        nullptr,
        cmdLine.data(),             
        nullptr,                   
        nullptr,                
        TRUE,                      
        CREATE_NO_WINDOW,          
        nullptr,                   
        nullptr,                   
        &si,
        &pi
    );

    CloseHandle(hWritePipe);

    if (!created) {
        CloseHandle(hReadPipe);
        results.push_back(FindingResult::unavailable(ID, CATEGORY,
            L"CreateProcess for cscript.exe failed. cscript.exe may not be available."));
        return results;
    }

    std::string rawOutput;
    {
        char buffer[4096];
        DWORD bytesRead = 0;
        while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)
               && bytesRead > 0)
        {
            buffer[bytesRead] = '\0';
            rawOutput += buffer;
        }
    }

    WaitForSingleObject(pi.hProcess, 10000);  
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    if (rawOutput.empty()) {
        results.push_back(FindingResult::unavailable(ID, CATEGORY,
            L"OSPP.VBS produced no output. Ensure Office 16 is properly installed."));
        return results;
    }

    std::wstring output = Utils::strToWstr(rawOutput);
    auto lines          = Utils::splitString(output, L'\n');

    std::wstring licenseName, licenseDesc, licenseStatus, partialKey,
                 remainingGrace, kmsServer;

    for (const auto& rawLine : lines) {
        std::wstring line = Utils::trim(rawLine);
        if (line.empty()) continue;

        auto extractAfter = [&](const std::wstring& prefix) -> std::wstring {
            if (Utils::containsIgnoreCase(line, prefix)) {
                size_t pos = line.find(L':');
                if (pos != std::wstring::npos && pos + 1 < line.size())
                    return Utils::trim(line.substr(pos + 1));
            }
            return L"";
        };

        if (Utils::containsIgnoreCase(line, L"LICENSE NAME"))
            licenseName = extractAfter(L":");
        else if (Utils::containsIgnoreCase(line, L"LICENSE DESCRIPTION"))
            licenseDesc = extractAfter(L":");
        else if (Utils::containsIgnoreCase(line, L"LICENSE STATUS"))
            licenseStatus = extractAfter(L":");
        else if (Utils::containsIgnoreCase(line, L"Last 5 characters"))
            partialKey = extractAfter(L":");
        else if (Utils::containsIgnoreCase(line, L"REMAINING GRACE"))
            remainingGrace = extractAfter(L":");
        else if (Utils::containsIgnoreCase(line, L"KMS machine name"))
            kmsServer = extractAfter(L":");
    }

    bool isKmsClient  = Utils::containsIgnoreCase(licenseDesc, L"VOLUME_KMSCLIENT") ||
                        Utils::containsIgnoreCase(licenseDesc, L"KMS");
    bool isRetail     = Utils::containsIgnoreCase(licenseDesc, L"RETAIL");
    bool isLicensed   = Utils::containsIgnoreCase(licenseStatus, L"LICENSED");
    bool isNotGenuine = Utils::containsIgnoreCase(licenseStatus, L"NOTIFICATION") ||
                        Utils::containsIgnoreCase(licenseStatus, L"UNLICENSED");

    std::wstring value =
        L"Key: xxxxx-" + partialKey +
        L"  |  " + licenseDesc +
        L"  |  Grace: " + remainingGrace;

    if (!licenseName.empty()) {
        std::wregex graceDaysRegex(LR"((\d+)\s+day)", std::regex_constants::icase);
        std::wsmatch graceDaysMatch;
        int graceDays = -1;
        if (std::regex_search(remainingGrace, graceDaysMatch, graceDaysRegex)) {
            try { graceDays = std::stoi(graceDaysMatch[1].str()); } catch (...) {}
        }

        if (isNotGenuine) {
            results.push_back(FindingResult(
                ID, CATEGORY,
                L"Office is in UNLICENSED, NOTIFICATION, or GRACE state (Activation pending or subscription expired).",
                value, Severity::WARNING, true, true, FindingType::LICENSE_STATE, ForensicSource::LICENSE_STATE, EvidenceImpact::INFO_ONLY, EvidenceQuality::INFO_ONLY, EvidenceReliability::VERIFIED
            ));
        } else if (isKmsClient && !kmsServer.empty()) {
            bool kmsServerBad = Utils::isPrivateOrLoopbackIP(kmsServer) ||
                                  Utils::isSuspiciousKmsHost(kmsServer);
            if (kmsServerBad) {
                results.push_back(FindingResult(
                    ID, CATEGORY,
                    L"Office KMS activated via suspicious/rogue server: " + kmsServer,
                    value + L"  |  KMS: " + kmsServer,
                    Severity::TAMPERING, true, true, FindingType::FORENSIC_EVIDENCE, ForensicSource::NETWORK_SERVER, EvidenceImpact::HIGH, EvidenceQuality::HIGH, EvidenceReliability::VERIFIED
                ));
            } else {
                results.push_back(FindingResult(
                    ID, CATEGORY,
                    L"Office activated via KMS. Server: " + kmsServer +
                    L". Legitimate in corporate environments.",
                    value + L"  |  KMS: " + kmsServer,
                    Severity::INFO, false, true, FindingType::LICENSE_STATE, ForensicSource::LICENSE_STATE, EvidenceImpact::INFO_ONLY, EvidenceQuality::INFO_ONLY, EvidenceReliability::VERIFIED
                ));
            }
        } else if (isKmsClient && kmsServer.empty() && isLicensed) {
            results.push_back(FindingResult(
                ID, CATEGORY,
                L"Office KMS channel active but no KMS server registered. "
                L"May indicate a local KMS emulator or cached activation.",
                value, Severity::WARNING, true, true, FindingType::FORENSIC_EVIDENCE, ForensicSource::CORE_LICENSING_HOOK, EvidenceImpact::MEDIUM, EvidenceQuality::MEDIUM, EvidenceReliability::VERIFIED
            ));
        } else if (isRetail && isLicensed) {
            FindingResult r = FindingResult::clean(ID, CATEGORY,
                L"Office activated via RETAIL channel. Appears genuine.", FindingType::LICENSE_STATE);
            r.value = value;
            results.push_back(r);
        } else if (graceDays >= 0 && graceDays < 7) {
            results.push_back(FindingResult(
                ID, CATEGORY,
                L"Office grace period critically low (" + std::to_wstring(graceDays) +
                L" days). May expire soon.",
                value, Severity::WARNING, true, true, FindingType::LICENSE_STATE, ForensicSource::LICENSE_STATE, EvidenceImpact::INFO_ONLY, EvidenceQuality::INFO_ONLY, EvidenceReliability::VERIFIED
            ));
        } else {
            results.push_back(FindingResult(
                ID, CATEGORY,
                L"OSPP.VBS parsed successfully. License: " + licenseName,
                value, Severity::INFO, false, true, FindingType::LICENSE_STATE, ForensicSource::LICENSE_STATE, EvidenceImpact::INFO_ONLY, EvidenceQuality::INFO_ONLY, EvidenceReliability::VERIFIED
            ));
        }
    } else {
        results.push_back(FindingResult::unavailable(ID, CATEGORY,
            L"OSPP.VBS: 'No installed product keys detected'. "
            L"This system likely uses a Click-to-Run Digital License (Microsoft Account entitlement). "
            L"See Check B3 for Digital License details."));
    }

    return results;
}

std::vector<FindingResult> checkOfficeDigitalLicense() {
    constexpr auto ID       = L"B3";
    constexpr auto CATEGORY = L"Office Click-to-Run / Digital License Check";

    std::vector<FindingResult> results;

    auto productIds   = Registry::readString(HKEY_LOCAL_MACHINE,
        LR"(SOFTWARE\Microsoft\Office\ClickToRun\Configuration)", L"ProductReleaseIds");
    auto version      = Registry::readString(HKEY_LOCAL_MACHINE,
        LR"(SOFTWARE\Microsoft\Office\ClickToRun\Configuration)", L"VersionToReport");
    auto platform     = Registry::readString(HKEY_LOCAL_MACHINE,
        LR"(SOFTWARE\Microsoft\Office\ClickToRun\Configuration)", L"Platform");
    auto updateCh     = Registry::readString(HKEY_LOCAL_MACHINE,
        LR"(SOFTWARE\Microsoft\Office\ClickToRun\Configuration)", L"UpdateChannel");

    if (!productIds || productIds->empty()) {
        results.push_back(FindingResult::unavailable(ID, CATEGORY,
            L"Click-to-Run configuration not found. "
            L"Office may not be installed or uses traditional MSI architecture."));
        return results;
    }

    auto digitalLicIds = Registry::readString(HKEY_CURRENT_USER,
        LR"(SOFTWARE\Microsoft\Office\16.0\Common\Licensing)",
        L"NextUserLicensingLicenseIds");
    auto deviceEntitle = Registry::readDWord(HKEY_CURRENT_USER,
        LR"(SOFTWARE\Microsoft\Office\16.0\Common\Licensing)",
        L"DeviceEntitlementsExist");

    bool isRetail    = Utils::containsIgnoreCase(*productIds, L"Retail");
    bool isVolume    = Utils::containsIgnoreCase(*productIds, L"Volume") ||
                       Utils::containsIgnoreCase(*productIds, L"GVLK");
    bool isM365      = Utils::containsIgnoreCase(*productIds, L"O365") ||
                       Utils::containsIgnoreCase(*productIds, L"Microsoft365");
    bool hasDigitalLic = digitalLicIds && !digitalLicIds->empty();
    bool hasDeviceLic  = deviceEntitle && *deviceEntitle == 1;

    std::wstring channelDesc = L"Unknown";
    if (updateCh) {
        if (Utils::containsIgnoreCase(*updateCh, L"492350f6"))
            channelDesc = L"Current Channel (Monthly)";
        else if (Utils::containsIgnoreCase(*updateCh, L"7ffbc6bf"))
            channelDesc = L"Semi-Annual Enterprise Channel";
        else if (Utils::containsIgnoreCase(*updateCh, L"b8f9b850"))
            channelDesc = L"Current Channel Preview";
        else if (Utils::containsIgnoreCase(*updateCh, L"55336b82"))
            channelDesc = L"Monthly Enterprise Channel";
        else
            channelDesc = *updateCh;
    }

    std::wstring value =
        L"Product: "   + *productIds +
        L"  |  Ver: "  + (version  ? *version  : L"N/A") +
        L"  |  Arch: " + (platform ? *platform : L"N/A") +
        L"  |  Channel: " + channelDesc;

    if (isRetail && hasDigitalLic) {
        std::wstring detail =
            L"Digital License verified (linked to Microsoft Account). "
            L"Official licensing mechanism detected for Office " +
            *productIds + L".";
        results.push_back(FindingResult::clean(ID, CATEGORY, detail));
        results.back().value = value;
    }
    else if (isM365 && hasDigitalLic) {
        std::wstring detail =
            L"Microsoft 365 subscription verified. "
            L"License is active via Click-to-Run Digital Entitlement.";
        results.push_back(FindingResult::clean(ID, CATEGORY, detail));
        results.back().value = value;
    }
    else if (hasDeviceLic) {
        std::wstring detail =
            L"Device License verified (DeviceEntitlementsExist=1). "
            L"Standard enterprise shared-device activation model.";
        results.push_back(FindingResult(ID, CATEGORY, detail, value, Severity::INFO, false, true, FindingType::LICENSE_STATE, ForensicSource::LICENSE_STATE, EvidenceImpact::INFO_ONLY, EvidenceQuality::INFO_ONLY, EvidenceReliability::VERIFIED));
    }
    else if (isVolume) {
        std::wstring detail =
            L"Office Volume edition detected. "
            L"Requires KMS server or MAK activation.";
        results.push_back(FindingResult(ID, CATEGORY, detail, value, Severity::WARNING, true, true, FindingType::LICENSE_STATE, ForensicSource::LICENSE_STATE, EvidenceImpact::INFO_ONLY, EvidenceQuality::INFO_ONLY, EvidenceReliability::VERIFIED));
    }
    else if (isRetail && !hasDigitalLic) {
        std::wstring detail =
            L"Office Retail C2R installed, but Digital License token not found. "
            L"Please sign in with your Microsoft Account inside Office to activate.";
        results.push_back(FindingResult(ID, CATEGORY, detail, value, Severity::WARNING, true, true, FindingType::LICENSE_STATE, ForensicSource::LICENSE_STATE, EvidenceImpact::INFO_ONLY, EvidenceQuality::INFO_ONLY, EvidenceReliability::VERIFIED));
    }
    else {
        results.push_back(FindingResult(ID, CATEGORY,
            L"Click-to-Run classification: " + *productIds,
            value, Severity::INFO, false, true, FindingType::LICENSE_STATE, ForensicSource::LICENSE_STATE, EvidenceImpact::INFO_ONLY, EvidenceQuality::INFO_ONLY, EvidenceReliability::VERIFIED));
    }

    return results;
}


std::vector<FindingResult> runAll(WMI::WmiClient& wmi) {
    std::vector<FindingResult> all;

    auto pushAll = [&](std::vector<FindingResult> v) {
        for (auto& r : v) all.push_back(std::move(r));
    };

    pushAll(queryOfficeWmi(wmi));
    pushAll(parseOsppVbs());
    pushAll(checkOfficeDigitalLicense());  

    for (auto& f : all) {
        f.domain = EvidenceDomain::OFFICE;
        f.role = FindingRole::SUPPORTING;
        if (f.id == L"B1") f.evidenceCategory = EvidenceCategory::WMI;
        else if (f.id == L"B2") { f.evidenceCategory = EvidenceCategory::SERVICE | EvidenceCategory::FILESYSTEM; f.origin = EvidenceOrigin::DERIVED; }
        else if (f.id == L"B3") f.evidenceCategory = EvidenceCategory::REGISTRY | EvidenceCategory::FILESYSTEM;
    }

    return all;
}

} // namespace LicenseInspector::ModuleB
