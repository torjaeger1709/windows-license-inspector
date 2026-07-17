#include "module_a_windows.h"
#include "common/utils.h"
#include "core/registry_query.h"
#include "core/wmi_query.h"
#include "core/service_query.h"
#include "core/event_log_query.h"
#include "core/sys_path.h"
#include "core/firmware_provider.h"
#include "core/license_cache.h"

#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <chrono>

namespace LicenseInspector::ModuleA {

static std::wstring getWmiProp(const WMI::Row& row, const std::wstring& propName) {
    auto it = row.find(propName);
    if (it != row.end()) return it->second;
    return L"";
}

FindingResult checkKmsRogueServer(WMI::WmiClient& wmi) {
    std::wstring id = L"A1";
    std::wstring cat = L"Rogue KMS Server";

    std::wstring regServer = Registry::readString(
        HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Software Protection Platform",
        L"KeyManagementServiceServer"
    ).value_or(L"");

    std::wstring wmiServer = regServer;
    bool hasActiveGvlk = false;
    if (wmi.isConnected()) {
        auto products = wmi.query(L"SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL");
        for (const auto& p : products) {
            std::wstring statusStr = getWmiProp(p, L"LicenseStatus");
            std::wstring desc = getWmiProp(p, L"Description");
            std::wstring kmsMachine = getWmiProp(p, L"KeyManagementServiceMachine");
            if (statusStr == L"1" && (desc.find(L"VOLUME_KMSCLIENT") != std::wstring::npos || desc.find(L"GVLK") != std::wstring::npos)) {
                hasActiveGvlk = true;
                if (wmiServer.empty() && !kmsMachine.empty()) {
                    wmiServer = kmsMachine;
                }
            }
        }
    }

    if (wmiServer.empty()) {
        return FindingResult::clean(id, cat, L"No KeyManagementServiceServer configured in registry or WMI.");
    }

    std::wstring srvLower = wmiServer;
    std::transform(srvLower.begin(), srvLower.end(), srvLower.begin(), ::towlower);

    bool isLoopback = (srvLower == L"127.0.0.1" || srvLower == L"localhost" || srvLower == L"0.0.0.0" || srvLower == L"::1");
    
    std::vector<std::wstring> knownCrackDomains = {
        L"kms.lotro.cc", L"kms.digiboy.ir", L"kms8.msguides.com", L"kms.03k.org",
        L"kms.lueto.ru", L"kms.srv.cr", L"kms.massgrave.dev", L"kms.chinauos.com"
    };
    bool isKnownRogue = false;
    for (const auto& d : knownCrackDomains) {
        if (srvLower.find(d) != std::wstring::npos) {
            isKnownRogue = true;
            break;
        }
    }

    if (isLoopback || isKnownRogue) {
        std::wstring detail = isLoopback ? L"Rogue loopback KMS emulator (" + wmiServer + L") configured." : L"Known rogue activation domain (" + wmiServer + L") configured.";
        if (hasActiveGvlk) detail += L" Active GVLK channel confirmed.";
        return FindingResult(
            id, cat, detail, wmiServer, Severity::TAMPERING, true, true,
            FindingType::FORENSIC_EVIDENCE, ForensicSource::NETWORK_SERVER,
            EvidenceImpact::HIGH, EvidenceQuality::HIGH, EvidenceReliability::STRONG,
            VerificationStatus::FOUND, FindingState::VERIFIED, -1
        );
    }

    if (Utils::isPrivateOrLoopbackIP(wmiServer)) {
        return FindingResult(
            id, cat, L"Private LAN KMS server configured: " + wmiServer + L". Verify corporate volume licensing.",
            wmiServer, Severity::WARNING, true, true,
            FindingType::CONFIGURATION, ForensicSource::NETWORK_SERVER,
            EvidenceImpact::MEDIUM, EvidenceQuality::MEDIUM, EvidenceReliability::STRONG,
            VerificationStatus::FOUND, FindingState::VERIFIED, -1
        );
    }

    return FindingResult(
        id, cat, L"External KMS server configured: " + wmiServer, wmiServer, Severity::INFO, false, true,
        FindingType::CONFIGURATION, ForensicSource::NETWORK_SERVER,
        EvidenceImpact::INFO_ONLY, EvidenceQuality::INFO_ONLY, EvidenceReliability::STRONG,
        VerificationStatus::FOUND, FindingState::VERIFIED, -1
    );
}

FindingResult checkPowerShellHistory() {
    std::wstring id = L"A2";
    std::wstring cat = L"PowerShell / MAS History";

    wchar_t appData[MAX_PATH];
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appData))) {
        return FindingResult::unavailable(id, cat, L"Failed to resolve %APPDATA% directory.");
    }

    std::wstring historyPath = std::wstring(appData) + L"\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";
    int ageDays = Core::SysPath::getFileAgeDays(historyPath);
    if (ageDays < 0) {
        return FindingResult::clean(id, cat, L"PowerShell command history file not found.", FindingType::FORENSIC_EVIDENCE, ForensicSource::STATIC_ARTIFACT, EvidenceReliability::MODERATE);
    }

    std::ifstream file(historyPath.c_str());
    if (!file.is_open()) {
        return FindingResult::unavailable(id, cat, L"Unable to read PowerShell history file (Access Denied or Locked).", FindingType::FORENSIC_EVIDENCE, VerificationStatus::ACCESS_DENIED);
    }

    std::string line;
    bool exactMatchFound = false;
    std::wstring matchedLine;

    std::vector<std::string> exactKeywords = {
        "massgrave.dev", "get.activated.win", "kmsauto", "kmspico", "mas_aact", "slmgr /skms 127.0.0.1", "slmgr -skms 127.0.0.1"
    };

    while (std::getline(file, line)) {
        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        for (const auto& kw : exactKeywords) {
            if (lower.find(kw) != std::string::npos) {
                exactMatchFound = true;
                matchedLine = Utils::strToWstr(line);
                break;
            }
        }
        if (exactMatchFound) break;
    }
    file.close();

    if (exactMatchFound) {
        return FindingResult(
            id, cat, L"Exact activation crack command detected in PowerShell history (" + std::to_wstring(ageDays) + L" days old).",
            matchedLine, Severity::TAMPERING, true, true,
            FindingType::FORENSIC_EVIDENCE, ForensicSource::STATIC_ARTIFACT,
            EvidenceImpact::LOW, EvidenceQuality::MEDIUM, EvidenceReliability::MODERATE,
            VerificationStatus::FOUND, FindingState::DETECTED, ageDays
        );
    }

    return FindingResult::clean(id, cat, L"No activation script keywords found in PowerShell history.", FindingType::FORENSIC_EVIDENCE, ForensicSource::STATIC_ARTIFACT, EvidenceReliability::MODERATE);
}

FindingResult checkKms38Hook(WMI::WmiClient& wmi) {
    std::wstring id = L"A3";
    std::wstring cat = L"KMS38 Hook Detection";

    if (!wmi.isConnected()) {
        return FindingResult::unavailable(id, cat, L"WMI subsystem is unavailable.");
    }

    auto products = wmi.query(L"SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL");
    for (const auto& p : products) {
        std::wstring statusStr = getWmiProp(p, L"LicenseStatus");
        std::wstring desc = getWmiProp(p, L"Description");
        std::wstring evalEnd = getWmiProp(p, L"EvaluationEndDate");
        std::wstring graceStr = getWmiProp(p, L"GracePeriodRemaining");
        std::wstring name = getWmiProp(p, L"Name");

        if (statusStr == L"1" && (desc.find(L"VOLUME_KMSCLIENT") != std::wstring::npos || desc.find(L"GVLK") != std::wstring::npos)) {
            bool is2038 = (evalEnd.find(L"2038") != std::wstring::npos);
            if (is2038 || (graceStr == L"0" && evalEnd.length() > 4 && evalEnd.substr(0, 4) == L"2038")) {
                return FindingResult(
                    id, cat, L"KMS38 active activation hook detected. EvaluationEndDate extended to year 2038 on GVLK channel.",
                    name + L" (" + evalEnd + L")", Severity::TAMPERING, true, true,
                    FindingType::FORENSIC_EVIDENCE, ForensicSource::CORE_LICENSING_HOOK,
                    EvidenceImpact::HIGH, EvidenceQuality::HIGH, EvidenceReliability::STRONG,
                    VerificationStatus::FOUND, FindingState::VERIFIED, -1
                );
            }
        }
    }

    return FindingResult::clean(id, cat, L"No year-2038 evaluation extension hooks found in WMI licensing records.", FindingType::FORENSIC_EVIDENCE, ForensicSource::CORE_LICENSING_HOOK, EvidenceReliability::STRONG);
}

FindingResult checkLicenseStateChannel(WMI::WmiClient& wmi) {
    std::wstring id = L"A4";
    std::wstring cat = L"License State & Channel";

    if (!wmi.isConnected()) {
        return FindingResult::unavailable(id, cat, L"WMI subsystem is unavailable.");
    }

    const auto& consensus = Core::LicenseDataCache::getConsensus();

    if (!consensus.wmiProvenance.success) {
        return FindingResult::clean(id, cat, L"No active Windows license product records found via WMI.", FindingType::LICENSE_STATE, ForensicSource::LICENSE_STATE, EvidenceReliability::STRONG);
    }

    std::wstring name = consensus.wmiData.edition.raw;
    std::wstring channel = consensus.wmiData.channel.raw;
    if (channel.empty()) channel = consensus.wmiData.channel.normalized;
    std::wstring statusLabel = consensus.wmiData.status.raw;
    if (statusLabel == L"1" || consensus.wmiData.status.normalized == L"LICENSED") {
        statusLabel = L"Licensed";
    } else if (statusLabel == L"2" || statusLabel == L"3" || consensus.wmiData.status.normalized == L"GRACE") {
        statusLabel = L"Out-of-Box / Out-of-Tolerance Grace";
    } else if (statusLabel == L"5" || consensus.wmiData.status.normalized == L"NOTIFICATION") {
        statusLabel = L"Notification (Activation Required)";
    }

    Severity sev = Severity::CLEAN;
    if (consensus.wmiData.status.normalized != L"LICENSED" && !consensus.wmiData.status.normalized.empty()) {
        sev = Severity::WARNING;
    }

    EvidenceReliability reliability = EvidenceReliability::VERIFIED;
    FindingDisposition  disposition = FindingDisposition::NORMAL;
    std::wstring detailStr = L"Windows Product: " + name + L" | Channel: " + channel + L" | Status: " + statusLabel;

    if (consensus.secondaryAvailable) {
        if (consensus.conflictLevel == Core::ConflictSeverity::HIGH) {
            sev = Severity::WARNING;
            reliability = EvidenceReliability::MODERATE;
            disposition = FindingDisposition::SUSPICIOUS;
            detailStr += L" [CRITICAL MISMATCH with Software Licensing Manager]";
        } else if (consensus.conflictLevel == Core::ConflictSeverity::MEDIUM) {
            disposition = FindingDisposition::LEGITIMATE_UPGRADE;
            detailStr += L" [Channel Discrepancy: WMI=" + consensus.wmiData.channel.normalized + L" vs SLMGR=" + consensus.dlvData.channel.normalized + L" (Legitimate Upgrade)]";
        }
    } else {
        reliability = EvidenceReliability::VERIFIED;
    }

    FindingResult res(
        id, cat, detailStr,
        statusLabel + L" (" + consensus.wmiData.channel.normalized + L")", sev, (sev != Severity::CLEAN), true,
        FindingType::LICENSE_STATE, ForensicSource::LICENSE_STATE,
        EvidenceImpact::INFO_ONLY, EvidenceQuality::HIGH, reliability,
        VerificationStatus::FOUND, FindingState::VERIFIED, -1,
        EvidenceDomain::WINDOWS, EvidenceCategory::WMI, FindingRole::PRIMARY, disposition, EvidenceOrigin::OBSERVED
    );

    res.hasConsensusData = true;
    res.consensus = consensus;
    return res;
}

std::vector<FindingResult> checkCrackDirectories() {
    std::vector<FindingResult> results;
    std::wstring id = L"A5";
    std::wstring cat = L"Crack Tool Directories";

    std::vector<std::wstring> targetDirs = {
        L"C:\\KMSAuto",
        L"C:\\Program Files\\KMSpico",
        L"C:\\Program Files\\KMSAuto Net",
        L"C:\\Windows\\KMSAutoS",
        L"C:\\ProgramData\\KMSAutoS",
        L"C:\\ProgramData\\MAS_AAct"
    };

    for (const auto& dir : targetDirs) {
        DWORD attr = GetFileAttributesW(dir.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            int ageDays = Core::SysPath::getFileAgeDays(dir);
            results.push_back(FindingResult(
                id, cat, L"Known crack tool folder present on disk (" + (ageDays >= 0 ? std::to_wstring(ageDays) + L" days old" : L"unknown age") + L"): " + dir,
                dir, Severity::TAMPERING, true, true,
                FindingType::FORENSIC_EVIDENCE, ForensicSource::STATIC_ARTIFACT,
                EvidenceImpact::LOW, EvidenceQuality::LOW, EvidenceReliability::WEAK,
                VerificationStatus::FOUND, FindingState::DETECTED, ageDays
            ));
        }
    }

    if (results.empty()) {
        results.push_back(FindingResult::clean(id, cat, L"No known crack tool folders (KMSAuto, KMSpico, etc.) found on system drive.", FindingType::FORENSIC_EVIDENCE, ForensicSource::STATIC_ARTIFACT, EvidenceReliability::WEAK));
    }
    return results;
}

std::vector<FindingResult> checkHiddenScheduledTasks() {
    std::vector<FindingResult> results;
    std::wstring id = L"A6";
    std::wstring cat = L"Hidden Scheduled Tasks";

    std::wstring sysDir = Core::SysPath::getSystemDir();
    std::vector<std::wstring> taskPaths = {
        sysDir + L"\\Tasks\\AutoKMS",
        sysDir + L"\\Tasks\\MAS_AAct",
        sysDir + L"\\Tasks\\KMSAutoNet",
        sysDir + L"\\Tasks\\SvcRestartTask"
    };

    for (const auto& tp : taskPaths) {
        DWORD attr = GetFileAttributesW(tp.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            int ageDays = Core::SysPath::getFileAgeDays(tp);
            results.push_back(FindingResult(
                id, cat, L"Suspicious scheduled activator task found in Task Scheduler: " + tp,
                tp, Severity::TAMPERING, true, true,
                FindingType::FORENSIC_EVIDENCE, ForensicSource::SCHEDULING_EXECUTION,
                EvidenceImpact::MEDIUM, EvidenceQuality::MEDIUM, EvidenceReliability::MODERATE,
                VerificationStatus::FOUND, FindingState::VERIFIED, ageDays
            ));
        }
    }

    if (results.empty()) {
        results.push_back(FindingResult::clean(id, cat, L"No unauthorized scheduled activation tasks detected.", FindingType::FORENSIC_EVIDENCE, ForensicSource::SCHEDULING_EXECUTION, EvidenceReliability::MODERATE));
    }
    return results;
}

std::vector<FindingResult> checkTelemetryRegistryPolicy() {
    std::vector<FindingResult> results;
    std::wstring id = L"A7";
    std::wstring cat = L"Telemetry & Registry Policy";

    DWORD noGenTicket = Registry::readDWord(
        HKEY_LOCAL_MACHINE,
        L"Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Software Protection Platform",
        L"NoGenTicket"
    ).value_or(0);

    if (noGenTicket == 1) {
        results.push_back(FindingResult(
            id, cat, L"NoGenTicket registry policy set to 1. Suppresses genuine ticket validation telemetry.",
            L"NoGenTicket = 1", Severity::TAMPERING, true, true,
            FindingType::FORENSIC_EVIDENCE, ForensicSource::REGISTRY_COM_TAMPERING,
            EvidenceImpact::MEDIUM, EvidenceQuality::MEDIUM, EvidenceReliability::VERIFIED,
            VerificationStatus::FOUND, FindingState::VERIFIED, -1
        ));
    }

    DWORD skipRearm = Registry::readDWord(
        HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Software Protection Platform",
        L"SkipRearm"
    ).value_or(0);

    if (skipRearm == 1) {
        results.push_back(FindingResult(
            id, cat, L"SkipRearm registry policy set to 1. Bypasses activation rearm limits.",
            L"SkipRearm = 1", Severity::TAMPERING, true, true,
            FindingType::FORENSIC_EVIDENCE, ForensicSource::REGISTRY_COM_TAMPERING,
            EvidenceImpact::MEDIUM, EvidenceQuality::MEDIUM, EvidenceReliability::VERIFIED,
            VerificationStatus::FOUND, FindingState::VERIFIED, -1
        ));
    }

    if (results.empty()) {
        results.push_back(FindingResult::clean(id, cat, L"No licensing telemetry suppression policies (NoGenTicket / SkipRearm) configured.", FindingType::FORENSIC_EVIDENCE, ForensicSource::REGISTRY_COM_TAMPERING, EvidenceReliability::VERIFIED));
    }
    return results;
}

FindingResult checkSoftwareProtectionService() {
    std::wstring id = L"A8";
    std::wstring cat = L"Software Protection Service";

    auto res = Core::ServiceQuery::queryService(L"sppsvc");
    if (res.verificationStatus == VerificationStatus::ACCESS_DENIED) {
        return FindingResult::unavailable(id, cat, L"Access Denied when querying sppsvc service configuration.", FindingType::CONFIGURATION, VerificationStatus::ACCESS_DENIED);
    }
    if (res.verificationStatus == VerificationStatus::NOT_FOUND || !res.data.exists) {
        return FindingResult::unavailable(id, cat, L"Software Protection Service (sppsvc) not found on system.", FindingType::CONFIGURATION, VerificationStatus::NOT_FOUND);
    }

    if (res.data.startType == SERVICE_DISABLED) {
        return FindingResult(
            id, cat, L"Software Protection Service (sppsvc) startup is disabled, suppressing licensing checks.",
            L"sppsvc (Disabled)", Severity::TAMPERING, true, true,
            FindingType::FORENSIC_EVIDENCE, ForensicSource::REGISTRY_COM_TAMPERING,
            EvidenceImpact::MEDIUM, EvidenceQuality::MEDIUM, EvidenceReliability::VERIFIED,
            VerificationStatus::FOUND, FindingState::VERIFIED, -1
        );
    }

    return FindingResult::clean(id, cat, L"Software Protection Service (sppsvc) is properly configured and enabled.", FindingType::CONFIGURATION, ForensicSource::REGISTRY_COM_TAMPERING, EvidenceReliability::VERIFIED);
}

std::vector<FindingResult> checkKmsWindowsServices() {
    std::vector<FindingResult> results;
    std::wstring id = L"A9";
    std::wstring cat = L"KMS Windows Services";

    std::vector<std::wstring> suspiciousSvcNames = {
        L"AutoKMS", L"KMSELDI", L"KMS-RAdmin", L"Service_KMS", L"MAS_AActSvc"
    };

    auto checked = Core::ServiceQuery::checkSuspiciousServices(suspiciousSvcNames);
    for (const auto& res : checked) {
        if (res.verificationStatus == VerificationStatus::ACCESS_DENIED) {
            results.push_back(FindingResult::unavailable(id, cat, L"Access Denied querying service: " + res.data.serviceName, FindingType::FORENSIC_EVIDENCE, VerificationStatus::ACCESS_DENIED));
            continue;
        }
        if (res.verificationStatus == VerificationStatus::FOUND && res.data.exists) {
            bool active = (res.data.running || res.data.startType == SERVICE_AUTO_START);
            EvidenceQuality qual = active ? EvidenceQuality::HIGH : EvidenceQuality::MEDIUM;
            EvidenceImpact imp = active ? EvidenceImpact::HIGH : EvidenceImpact::MEDIUM;
            std::wstring detail = active ? L"Active unauthorized KMS emulator Windows Service running/scheduled: " + res.data.serviceName
                                         : L"Dormant unauthorized KMS emulator Windows Service present: " + res.data.serviceName;
            results.push_back(FindingResult(
                id, cat, detail, res.data.serviceName + (res.data.running ? L" (Running)" : L" (Stopped)"),
                Severity::TAMPERING, true, true,
                FindingType::FORENSIC_EVIDENCE, ForensicSource::SCHEDULING_EXECUTION,
                imp, qual, EvidenceReliability::VERIFIED,
                VerificationStatus::FOUND, FindingState::VERIFIED, -1
            ));
        }
    }

    if (results.empty()) {
        results.push_back(FindingResult::clean(id, cat, L"No unauthorized KMS emulator Windows Services (AutoKMS, KMSELDI, etc.) detected.", FindingType::FORENSIC_EVIDENCE, ForensicSource::SCHEDULING_EXECUTION, EvidenceReliability::VERIFIED));
    }
    return results;
}

FindingResult checkHostsFileTampering() {
    std::wstring id = L"A10";
    std::wstring cat = L"Hosts File Tampering";

    std::wstring hostsPath = Core::SysPath::getSystemDir() + L"\\drivers\\etc\\hosts";
    int ageDays = Core::SysPath::getFileAgeDays(hostsPath);
    if (ageDays < 0) {
        return FindingResult::clean(id, cat, L"System hosts file not found or inaccessible.", FindingType::FORENSIC_EVIDENCE, ForensicSource::NETWORK_SERVER, EvidenceReliability::STRONG);
    }

    std::wifstream file(hostsPath.c_str());
    if (!file.is_open()) {
        return FindingResult::unavailable(id, cat, L"Unable to open hosts file (Access Denied).", FindingType::FORENSIC_EVIDENCE, VerificationStatus::ACCESS_DENIED);
    }

    std::wstring line;
    std::vector<std::wstring> targetHosts = {
        L"sls.microsoft.com", L"activation.sls.microsoft.com", L"crl.microsoft.com"
    };
    bool redirected = false;
    std::wstring matchedLine;

    while (std::getline(file, line)) {
        std::wstring trimmed = line;
        trimmed.erase(0, trimmed.find_first_not_of(L" \t\r\n"));
        if (trimmed.empty() || trimmed[0] == L'#') continue;

        std::wstring lower = trimmed;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        for (const auto& th : targetHosts) {
            if (lower.find(th) != std::wstring::npos &&
                (lower.find(L"127.0.0.1") != std::wstring::npos || lower.find(L"0.0.0.0") != std::wstring::npos || lower.find(L"::1") != std::wstring::npos))
            {
                redirected = true;
                matchedLine = trimmed;
                break;
            }
        }
        if (redirected) break;
    }
    file.close();

    if (redirected) {
        return FindingResult(
            id, cat, L"Hosts file redirects Microsoft activation domain (" + matchedLine + L") to loopback (" + std::to_wstring(ageDays) + L" days old).",
            matchedLine, Severity::TAMPERING, true, true,
            FindingType::FORENSIC_EVIDENCE, ForensicSource::NETWORK_SERVER,
            EvidenceImpact::MEDIUM, EvidenceQuality::MEDIUM, EvidenceReliability::STRONG,
            VerificationStatus::FOUND, FindingState::VERIFIED, ageDays
        );
    }

    return FindingResult::clean(id, cat, L"No Microsoft licensing domain redirections found in hosts file.", FindingType::FORENSIC_EVIDENCE, ForensicSource::NETWORK_SERVER, EvidenceReliability::STRONG);
}

FindingResult checkLicensingStoreConsistency(WMI::WmiClient& wmi) {
    std::wstring id = L"A11";
    std::wstring cat = L"Licensing Store Consistency";

    if (!wmi.isConnected()) {
        return FindingResult::unavailable(id, cat, L"WMI subsystem is unavailable.");
    }

    auto products = wmi.query(L"SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL");
    bool logicalContradiction = false;
    std::wstring detailMsg;

    for (const auto& p : products) {
        std::wstring statusStr = getWmiProp(p, L"LicenseStatus");
        std::wstring desc = getWmiProp(p, L"Description");
        std::wstring graceStr = getWmiProp(p, L"GracePeriodRemaining");
        std::wstring name = getWmiProp(p, L"Name");

        if (statusStr == L"1" && desc.find(L"TIMEBASED_EVAL") != std::wstring::npos && graceStr == L"0") {
            logicalContradiction = true;
            detailMsg = L"WMI logical contradiction: Product " + name + L" is Licensed (Status 1) on TIMEBASED_EVAL channel with 0 grace remaining.";
            break;
        }
    }

    if (logicalContradiction) {
        return FindingResult(
            id, cat, detailMsg, L"Logical Contradiction Detected", Severity::WARNING, true, true,
            FindingType::FORENSIC_EVIDENCE, ForensicSource::CORE_LICENSING_HOOK,
            EvidenceImpact::MEDIUM, EvidenceQuality::MEDIUM, EvidenceReliability::VERIFIED,
            VerificationStatus::FOUND, FindingState::SUSPECTED, -1
        );
    }

    return FindingResult::clean(id, cat, L"Licensing store attributes consistent across checked WMI classes.", FindingType::FORENSIC_EVIDENCE, ForensicSource::CORE_LICENSING_HOOK, EvidenceReliability::VERIFIED);
}

std::vector<FindingResult> checkSoftwareProtectionEventLog(int eventLimit) {
    std::vector<FindingResult> results;
    std::wstring id = L"A12";
    std::wstring cat = L"Software Protection Event Log";

    auto res = Core::EventLogQuery::querySppEvents(eventLimit);
    if (res.verificationStatus == VerificationStatus::ACCESS_DENIED) {
        results.push_back(FindingResult::unavailable(id, cat, L"Access Denied reading Application event logs.", FindingType::INFORMATION, VerificationStatus::ACCESS_DENIED));
        return results;
    }
    if (res.verificationStatus == VerificationStatus::NOT_FOUND || res.data.empty()) {
        results.push_back(FindingResult::clean(id, cat, L"No recent SPP / Software Licensing events found in Application log.", FindingType::INFORMATION, ForensicSource::NONE, EvidenceReliability::MODERATE));
        return results;
    }

    int totalSpp = static_cast<int>(res.data.size());
    results.push_back(FindingResult(
        id, cat, L"Scanned " + std::to_wstring(totalSpp) + L" recent SPP events (in last " + std::to_wstring(eventLimit) + L" records).",
        std::to_wstring(totalSpp) + L" records scanned", Severity::INFO, false, true,
        FindingType::INFORMATION, ForensicSource::NONE,
        EvidenceImpact::INFO_ONLY, EvidenceQuality::INFO_ONLY, EvidenceReliability::MODERATE,
        VerificationStatus::FOUND, FindingState::DETECTED, -1
    ));

    return results;
}

std::vector<FindingResult> checkSppComIntegrity() {
    std::vector<FindingResult> results;
    std::wstring id = L"A13";
    std::wstring cat = L"SPP COM Integrity Check";

    std::wstring clsidPath = L"Software\\Classes\\CLSID\\{106E1BBE-D714-436C-ACEE-DCE60CD5743D}\\InProcServer32";
    std::wstring dllPath = Registry::readString(HKEY_LOCAL_MACHINE, clsidPath, L"").value_or(L"");
    if (dllPath.empty()) {
        dllPath = Registry::readString(HKEY_CLASSES_ROOT, L"CLSID\\{106E1BBE-D714-436C-ACEE-DCE60CD5743D}\\InProcServer32", L"").value_or(L"");
    }

    if (dllPath.empty()) {
        results.push_back(FindingResult::clean(id, cat, L"No custom InProcServer32 override found for SPP COM object (CLSID SppExtComObj).", FindingType::FORENSIC_EVIDENCE, ForensicSource::REGISTRY_COM_TAMPERING, EvidenceReliability::VERIFIED));
        return results;
    }

    std::wstring expanded = Utils::expandEnvVars(dllPath);
    bool insideSys32 = Core::SysPath::isInsideSystem32(expanded);

    std::wstring lowerPath = expanded;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
    bool isOfficialName = (lowerPath.find(L"sppextcomobj.dll") != std::wstring::npos) && (lowerPath.find(L"patcher") == std::wstring::npos);

    if (!insideSys32 || !isOfficialName) {
        results.push_back(FindingResult(
            id, cat, L"Active SPP COM DLL Hijack: InProcServer32 registration points outside System32 or to unauthorized binary: " + dllPath,
            dllPath, Severity::TAMPERING, true, true,
            FindingType::FORENSIC_EVIDENCE, ForensicSource::REGISTRY_COM_TAMPERING,
            EvidenceImpact::HIGH, EvidenceQuality::HIGH, EvidenceReliability::VERIFIED,
            VerificationStatus::FOUND, FindingState::VERIFIED, -1
        ));
    } else {
        results.push_back(FindingResult::clean(id, cat, L"SPP COM InProcServer32 points securely inside System32: " + dllPath, FindingType::FORENSIC_EVIDENCE, ForensicSource::REGISTRY_COM_TAMPERING, EvidenceReliability::VERIFIED));
    }

    return results;
}

FindingResult checkFirmwareLicenseConsistency(WMI::WmiClient& wmi) {
    std::wstring id = L"A14";
    std::wstring cat = L"Firmware License Consistency";

    if (!wmi.isConnected()) {
        return FindingResult::unavailable(id, cat, L"WMI not connected; cannot probe firmware license tables.", FindingType::CONFIGURATION, VerificationStatus::ACCESS_DENIED, EvidenceDomain::WINDOWS, EvidenceCategory::FIRMWARE | EvidenceCategory::WMI, FindingRole::SUPPORTING);
    }

    FirmwareLicenseInfo info;
    bool extracted = Core::FirmwareProviderFactory::extractConsolidatedInfo(wmi, info);

    if (!extracted || (!info.firmwarePresent && !info.virtualMachine)) {
        return FindingResult::notApplicable(id, cat, L"No ACPI MSDM/OA3 firmware table or hypervisor marker detected on this hardware.", FindingType::CONFIGURATION, EvidenceDomain::WINDOWS, EvidenceCategory::FIRMWARE | EvidenceCategory::WMI, FindingRole::SUPPORTING);
    }

    if (info.virtualMachine) {
        if (info.currentMechanism == ActivationMechanism::AVMA || info.currentChannel == LicenseChannel::VOLUME_GVLK || info.currentMechanism == ActivationMechanism::DIGITAL_ENTITLEMENT) {
            FindingResult res = FindingResult::clean(id, cat, L"Virtual Machine environment running legitimate AVMA/Volume/Digital licensing (" + info.currentNameRaw + L").", FindingType::FORENSIC_EVIDENCE, ForensicSource::LICENSE_STATE, EvidenceReliability::VERIFIED, EvidenceDomain::WINDOWS, EvidenceCategory::FIRMWARE | EvidenceCategory::WMI, FindingRole::SUPPORTING);
            res.disposition = FindingDisposition::NORMAL;
            res.origin = EvidenceOrigin::OBSERVED;
            return res;
        }
    }

    if (info.firmwarePresent) {
        EditionFamily fwFamily  = getEditionFamily(info.firmwareEdition);
        EditionFamily curFamily = getEditionFamily(info.currentEdition);

        if (fwFamily == curFamily && curFamily != EditionFamily::UNKNOWN) {
            std::wstring detail = L"Firmware License: " + info.firmwareDescRaw + L" | Current Windows: " + info.currentNameRaw +
                                  L" | Assessment: Firmware edition belongs to the same Windows Home/Pro family (" + editionFamilyToString(curFamily) + L"). No inconsistency detected.";
            FindingResult res = FindingResult::clean(id, cat, detail, FindingType::FORENSIC_EVIDENCE, ForensicSource::LICENSE_STATE, EvidenceReliability::VERIFIED, EvidenceDomain::WINDOWS, EvidenceCategory::FIRMWARE | EvidenceCategory::WMI, FindingRole::SUPPORTING);
            res.disposition = FindingDisposition::NORMAL;
            res.origin = EvidenceOrigin::OBSERVED;
            return res;
        }

        if (fwFamily == EditionFamily::HOME && (curFamily == EditionFamily::PROFESSIONAL || curFamily == EditionFamily::ENTERPRISE || curFamily == EditionFamily::EDUCATION)) {
            if (info.currentChannel == LicenseChannel::RETAIL || info.currentMechanism == ActivationMechanism::DIGITAL_ENTITLEMENT || info.currentMechanism == ActivationMechanism::RETAIL_KEY) {
                std::wstring detail = L"Firmware License: " + info.firmwareDescRaw + L" | Current Windows: " + info.currentNameRaw +
                                      L" | Assessment: Legitimate upgrade detected. Hardware originally shipped with Windows Home family and upgraded to " + info.currentNameRaw + L" via Retail/Digital Entitlement.";
                FindingResult res = FindingResult::clean(id, cat, detail, FindingType::FORENSIC_EVIDENCE, ForensicSource::LICENSE_STATE, EvidenceReliability::VERIFIED, EvidenceDomain::WINDOWS, EvidenceCategory::FIRMWARE | EvidenceCategory::WMI, FindingRole::SUPPORTING);
                res.disposition = FindingDisposition::LEGITIMATE_UPGRADE;
                res.origin = EvidenceOrigin::CORRELATED;
                return res;
            }
        }

        if (info.currentChannel == LicenseChannel::VOLUME_GVLK || info.currentMechanism == ActivationMechanism::GVLK_INSTALLED || info.currentMechanism == ActivationMechanism::KMS_ACTIVATED || info.currentMechanism == ActivationMechanism::KMS38_EVAL) {
            std::wstring detail = L"Firmware License: " + info.firmwareDescRaw + L" | Current Windows: " + info.currentNameRaw +
                                  L" | Assessment: Firmware license inconsistent with active activation mechanism. Hardware embedded with OEM key but active OS is running Volume KMS/GVLK activation.";
            FindingResult res(id, cat, detail, info.currentNameRaw, Severity::WARNING, true, true,
                              FindingType::FORENSIC_EVIDENCE, ForensicSource::LICENSE_STATE,
                              EvidenceImpact::MEDIUM, EvidenceQuality::HIGH, EvidenceReliability::STRONG,
                              VerificationStatus::FOUND, FindingState::SUSPECTED, -1,
                              EvidenceDomain::WINDOWS, EvidenceCategory::FIRMWARE | EvidenceCategory::WMI,
                              FindingRole::SUPPORTING, FindingDisposition::SUSPICIOUS, EvidenceOrigin::CORRELATED);
            if (!info.kmsMachine.empty()) {
                res.detail += L" (KMS Host: " + info.kmsMachine + L")";
            }
            return res;
        }

        std::wstring detail = L"Firmware License: " + info.firmwareDescRaw + L" | Current Windows: " + info.currentNameRaw +
                              L" | Assessment: Edition discrepancy. Firmware key belongs to a different edition family than active OS.";
        FindingResult res = FindingResult::clean(id, cat, detail, FindingType::FORENSIC_EVIDENCE, ForensicSource::LICENSE_STATE, EvidenceReliability::MODERATE, EvidenceDomain::WINDOWS, EvidenceCategory::FIRMWARE | EvidenceCategory::WMI, FindingRole::SUPPORTING);
        res.disposition = FindingDisposition::NORMAL;
        res.origin = EvidenceOrigin::OBSERVED;
        return res;
    }

    return FindingResult::notApplicable(id, cat, L"Firmware license state could not be conclusively evaluated.", FindingType::CONFIGURATION, EvidenceDomain::WINDOWS, EvidenceCategory::FIRMWARE | EvidenceCategory::WMI, FindingRole::SUPPORTING);
}

std::vector<FindingResult> runAll(WMI::WmiClient& wmi, int eventLimit) {
    std::vector<FindingResult> all;

    auto append = [&](FindingResult f) { all.push_back(std::move(f)); };
    auto appendVec = [&](std::vector<FindingResult> vec) {
        for (auto& f : vec) all.push_back(std::move(f));
    };

    append(checkKmsRogueServer(wmi));
    append(checkPowerShellHistory());
    append(checkKms38Hook(wmi));
    append(checkLicenseStateChannel(wmi));
    appendVec(checkCrackDirectories());
    appendVec(checkHiddenScheduledTasks());
    appendVec(checkTelemetryRegistryPolicy());
    append(checkSoftwareProtectionService());
    appendVec(checkKmsWindowsServices());
    append(checkHostsFileTampering());
    append(checkLicensingStoreConsistency(wmi));
    appendVec(checkSoftwareProtectionEventLog(eventLimit));
    appendVec(checkSppComIntegrity());
    append(checkFirmwareLicenseConsistency(wmi));

    for (auto& f : all) {
        f.domain = EvidenceDomain::WINDOWS;
        if (f.id == L"A1" || f.id == L"A3" || f.id == L"A6" || f.id == L"A9" || f.id == L"A13") {
            f.role = FindingRole::PRIMARY;
        } else {
            f.role = FindingRole::SUPPORTING;
        }
        if (f.id == L"A1") f.evidenceCategory = EvidenceCategory::REGISTRY | EvidenceCategory::WMI;
        else if (f.id == L"A2") f.evidenceCategory = EvidenceCategory::FILESYSTEM;
        else if (f.id == L"A3") f.evidenceCategory = EvidenceCategory::WMI;
        else if (f.id == L"A4") f.evidenceCategory = EvidenceCategory::WMI;
        else if (f.id == L"A5") f.evidenceCategory = EvidenceCategory::FILESYSTEM;
        else if (f.id == L"A6") f.evidenceCategory = EvidenceCategory::SERVICE | EvidenceCategory::COM;
        else if (f.id == L"A7") f.evidenceCategory = EvidenceCategory::REGISTRY;
        else if (f.id == L"A8") f.evidenceCategory = EvidenceCategory::SERVICE;
        else if (f.id == L"A9") f.evidenceCategory = EvidenceCategory::SERVICE;
        else if (f.id == L"A10") f.evidenceCategory = EvidenceCategory::NETWORK | EvidenceCategory::FILESYSTEM;
        else if (f.id == L"A11") { f.evidenceCategory = EvidenceCategory::FILESYSTEM | EvidenceCategory::WMI; f.origin = EvidenceOrigin::DERIVED; }
        else if (f.id == L"A12") f.evidenceCategory = EvidenceCategory::EVENTLOG;
        else if (f.id == L"A13") f.evidenceCategory = EvidenceCategory::COM | EvidenceCategory::FILESYSTEM;
        else if (f.id == L"A14") { f.evidenceCategory = EvidenceCategory::FIRMWARE | EvidenceCategory::WMI; }
    }

    return all;
}

} // namespace LicenseInspector::ModuleA
