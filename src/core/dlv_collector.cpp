#include "core/dlv_collector.h"
#include "common/utils.h"
#include <regex>
#include <chrono>
#include <algorithm>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace LicenseInspector::Core {

static const std::vector<EditionAlias> EDITION_ALIASES = {
    { L"CoreCountrySpecific",     EditionFamily::HOME },
    { L"CoreSingleLanguage",      EditionFamily::HOME },
    { L"Core",                    EditionFamily::HOME },
    { L"Home",                    EditionFamily::HOME },
    { L"ProfessionalEducation",   EditionFamily::PROFESSIONAL },
    { L"ProfessionalWorkstation", EditionFamily::PROFESSIONAL },
    { L"Professional",            EditionFamily::PROFESSIONAL },
    { L"Pro",                     EditionFamily::PROFESSIONAL },
    { L"Enterprise",              EditionFamily::ENTERPRISE },
    { L"Education",               EditionFamily::EDUCATION },
    { L"Server",                  EditionFamily::SERVER },
    { L"IoT",                     EditionFamily::IOT }
};

EditionFamily SemanticNormalizer::parseEditionFamilyByTokens(const std::wstring& raw) {
    if (raw.empty()) return EditionFamily::UNKNOWN;
    for (const auto& alias : EDITION_ALIASES) {
        if (raw.find(alias.token) != std::wstring::npos) {
            return alias.family;
        }
    }
    return EditionFamily::UNKNOWN;
}

std::wstring SemanticNormalizer::normalizeEdition(const std::wstring& rawName, const std::wstring& rawDesc) {
    EditionFamily fam = parseEditionFamilyByTokens(rawName);
    if (fam == EditionFamily::UNKNOWN) fam = parseEditionFamilyByTokens(rawDesc);

    switch (fam) {
        case EditionFamily::HOME:         return L"HOME";
        case EditionFamily::PROFESSIONAL: return L"PRO";
        case EditionFamily::ENTERPRISE:   return L"ENTERPRISE";
        case EditionFamily::EDUCATION:    return L"EDUCATION";
        case EditionFamily::SERVER:       return L"SERVER";
        case EditionFamily::IOT:          return L"IOT";
        default:                          return L"UNKNOWN";
    }
}

std::wstring SemanticNormalizer::normalizeChannel(const std::wstring& rawDesc, const std::wstring& rawChannel) {
    std::wstring combined = rawDesc + L" " + rawChannel;
    if (combined.find(L"VOLUME_KMSCLIENT") != std::wstring::npos || combined.find(L"KMSClient") != std::wstring::npos || combined.find(L"GVLK") != std::wstring::npos) {
        return L"VOLUME_KMS";
    }
    if (combined.find(L"VOLUME_MAK") != std::wstring::npos || combined.find(L"MAK") != std::wstring::npos) {
        return L"VOLUME_MAK";
    }
    if (combined.find(L"OEM_DM") != std::wstring::npos) return L"OEM_DM";
    if (combined.find(L"OEM_SLP") != std::wstring::npos) return L"OEM_SLP";
    if (combined.find(L"OEM_COA") != std::wstring::npos) return L"OEM_COA";
    if (combined.find(L"OEM") != std::wstring::npos) return L"OEM";
    if (combined.find(L"RETAIL") != std::wstring::npos || combined.find(L"Retail") != std::wstring::npos) {
        return L"RETAIL";
    }
    if (combined.find(L"DIGITAL") != std::wstring::npos) return L"DIGITAL_ENTITLEMENT";
    return L"UNKNOWN";
}

std::wstring SemanticNormalizer::normalizeStatus(const std::wstring& rawStatus) {
    if (rawStatus == L"1" || rawStatus.find(L"Licensed") != std::wstring::npos) return L"LICENSED";
    if (rawStatus == L"2" || rawStatus == L"3" || rawStatus.find(L"Grace") != std::wstring::npos) return L"GRACE";
    if (rawStatus == L"5" || rawStatus.find(L"Notification") != std::wstring::npos) return L"NOTIFICATION";
    if (rawStatus == L"0" || rawStatus.find(L"Unlicensed") != std::wstring::npos) return L"UNLICENSED";
    return L"UNKNOWN";
}

NormalizedLicenseData SemanticNormalizer::normalizeWmi(const std::wstring& name, const std::wstring& desc, 
                                                       const std::wstring& status, const std::wstring& pKey, 
                                                       const std::wstring& kmsHost) {
    NormalizedLicenseData data;
    data.success = true;
    data.rawOutputText = L"Name: " + name + L"\r\nDescription: " + desc + L"\r\nStatus: " + status + L"\r\nPartialKey: " + pKey + L"\r\nKmsHost: " + kmsHost;

    data.edition.raw        = name;
    data.edition.normalized = normalizeEdition(name, desc);
    data.edition.state      = CollectorState::MATCH;
    if (name.empty()) data.unparsedCount++;

    data.channel.raw        = desc;
    data.channel.normalized = normalizeChannel(desc, L"");
    data.channel.state      = CollectorState::MATCH;
    if (desc.empty()) data.unparsedCount++;

    data.status.raw         = status;
    data.status.normalized  = normalizeStatus(status);
    data.status.state       = CollectorState::MATCH;
    if (status.empty()) data.unparsedCount++;

    data.partialKey.raw        = pKey;
    data.partialKey.normalized = pKey;
    data.partialKey.state      = CollectorState::MATCH;
    if (pKey.empty()) data.unparsedCount++;

    data.kmsMachine.raw = kmsHost;
    if (kmsHost.empty() || data.channel.normalized == L"RETAIL" || data.channel.normalized.find(L"OEM") != std::wstring::npos) {
        data.kmsMachine.normalized = L"NOT_APPLICABLE";
        data.kmsMachine.state      = CollectorState::NOT_APPLICABLE;
    } else {
        data.kmsMachine.normalized = kmsHost;
        data.kmsMachine.state      = CollectorState::MATCH;
    }

    return data;
}

NormalizedLicenseData SemanticNormalizer::normalizeDlv(const std::wstring& rawText, bool success) {
    NormalizedLicenseData data;
    data.success = success;
    data.rawOutputText = rawText;
    if (!success || rawText.empty()) {
        data.edition.state    = CollectorState::UNAVAILABLE;
        data.channel.state    = CollectorState::UNAVAILABLE;
        data.status.state     = CollectorState::UNAVAILABLE;
        data.partialKey.state = CollectorState::UNAVAILABLE;
        data.kmsMachine.state = CollectorState::UNAVAILABLE;
        data.unparsedCount    = 4;
        return data;
    }

    std::wregex guidRegex(L"([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})");
    std::wsregex_iterator it(rawText.begin(), rawText.end(), guidRegex);
    std::wsregex_iterator end;
    if (it != end) {
        data.activationId = it->str(1);
        ++it;
        if (it != end) data.applicationId = it->str(1);
    }

    std::wregex pkeyRegex(L"Partial Product Key:[^A-Z0-9]*([A-Z0-9]{5})", std::regex_constants::icase);
    std::wsmatch match;
    if (std::regex_search(rawText, match, pkeyRegex)) {
        data.partialKey.raw        = match[1].str();
        data.partialKey.normalized = match[1].str();
    } else {
        // Fallback for localized: look for 5 char token near Key
        std::wregex pkeyLocal(L"(?:Key|Khóa)[^:\r\n]*:[^A-Z0-9]*([A-Z0-9]{5})", std::regex_constants::icase);
        if (std::regex_search(rawText, match, pkeyLocal)) {
            data.partialKey.raw        = match[1].str();
            data.partialKey.normalized = match[1].str();
        }
    }
    if (data.partialKey.raw.empty()) data.unparsedCount++;

    std::wregex kmsRegex(L"Key Management Service machine[^:\r\n]*:[ \t]*([^\r\n]+)", std::regex_constants::icase);
    if (std::regex_search(rawText, match, kmsRegex)) {
        std::wstring host = Utils::trim(match[1].str());
        data.kmsMachine.raw = host;
        data.kmsMachine.normalized = host;
    }

    std::wregex nameRegex(L"Name:[ \t]*([^\r\n]+)", std::regex_constants::icase);
    if (std::regex_search(rawText, match, nameRegex)) {
        data.edition.raw = Utils::trim(match[1].str());
    } else {
        data.unparsedCount++;
    }

    std::wregex descRegex(L"Description:[ \t]*([^\r\n]+)", std::regex_constants::icase);
    if (std::regex_search(rawText, match, descRegex)) {
        data.channel.raw = Utils::trim(match[1].str());
    } else {
        data.unparsedCount++;
    }

    std::wregex statusRegex(L"License Status:[ \t]*([^\r\n]+)", std::regex_constants::icase);
    if (std::regex_search(rawText, match, statusRegex)) {
        data.status.raw = Utils::trim(match[1].str());
    } else {
        data.unparsedCount++;
    }

    data.edition.normalized = normalizeEdition(data.edition.raw, data.channel.raw);
    data.channel.normalized = normalizeChannel(data.channel.raw, rawText);
    data.status.normalized  = normalizeStatus(data.status.raw);

    if (data.kmsMachine.normalized.empty() || data.channel.normalized == L"RETAIL" || data.channel.normalized.find(L"OEM") != std::wstring::npos) {
        if (data.kmsMachine.raw.empty()) {
            data.kmsMachine.normalized = L"NOT_APPLICABLE";
        }
    }

    return data;
}

std::pair<std::wstring, CollectorProvenance> DlvCollector::executeSafePipe() {
    CollectorProvenance prov;
    prov.collectorId   = L"SLMGR_DLV";
    prov.collectorType = L"VBScript Child Process (cscript.exe //NoLogo)";

    auto initStart = GetTickCount64();

    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE hReadPipe = NULL, hWritePipe = NULL;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
        prov.success   = false;
        prov.initMs    = static_cast<long long>(GetTickCount64() - initStart);
        prov.latencyMs = prov.initMs;
        return { L"", prov };
    }
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError  = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    wchar_t sysDir[MAX_PATH] = { 0 };
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring cmdLine = L"\"" + std::wstring(sysDir) + L"\\cscript.exe\" //NoLogo \"" + std::wstring(sysDir) + L"\\slmgr.vbs\" /dlv";

    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    BOOL created = CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(hWritePipe); // Close write end in parent so ReadFile returns EOF

    auto queryStart = GetTickCount64();
    prov.initMs = static_cast<long long>(queryStart - initStart);

    if (!created) {
        CloseHandle(hReadPipe);
        prov.success   = false;
        prov.exitCode  = -1;
        prov.latencyMs = prov.initMs;
        return { L"", prov };
    }

    DWORD waitRes = WaitForSingleObject(pi.hProcess, 7000);
    if (waitRes == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 258); // WAIT_TIMEOUT exit code
        prov.exitCode  = 258;
        prov.success   = false;
    } else {
        DWORD ec = 0;
        GetExitCodeProcess(pi.hProcess, &ec);
        prov.exitCode = static_cast<int>(ec);
        prov.success  = (ec == 0);
    }

    std::string narrowOut;
    char buffer[1024];
    DWORD bytesRead = 0;
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        narrowOut += buffer;
    }

    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    auto parseStart = GetTickCount64();
    prov.queryMs = static_cast<long long>(parseStart - queryStart);

    int wlen = MultiByteToWideChar(CP_UTF8, 0, narrowOut.data(), (int)narrowOut.size(), NULL, 0);
    std::wstring wOut;
    if (wlen <= 0) {
        wlen = MultiByteToWideChar(CP_ACP, 0, narrowOut.data(), (int)narrowOut.size(), NULL, 0);
        if (wlen > 0) {
            wOut.resize(wlen, 0);
            MultiByteToWideChar(CP_ACP, 0, narrowOut.data(), (int)narrowOut.size(), &wOut[0], wlen);
        }
    } else {
        wOut.resize(wlen, 0);
        MultiByteToWideChar(CP_UTF8, 0, narrowOut.data(), (int)narrowOut.size(), &wOut[0], wlen);
    }

    prov.parseMs   = static_cast<long long>(GetTickCount64() - parseStart);
    prov.latencyMs = prov.initMs + prov.queryMs + prov.parseMs;
    return { wOut, prov };
}

CollectorConsensus DlvCollector::crossValidate(const NormalizedLicenseData& wmi, const NormalizedLicenseData& dlv,
                                               const CollectorProvenance& wmiProv, const CollectorProvenance& dlvProv) {
    CollectorConsensus consensus;
    consensus.consensusVersion     = L"1.1";
    consensus.conflictReasonCode   = L"NONE";
    consensus.wmiProvenance        = wmiProv;
    consensus.dlvProvenance        = dlvProv;
    consensus.wmiData              = wmi;
    consensus.dlvData              = dlv;

    consensus.unavailable          = false;
    consensus.secondaryAvailable   = dlv.success && dlvProv.success;

    if (!consensus.secondaryAvailable) {
        consensus.confidence         = ConsensusConfidence::WMI_ONLY;
        consensus.conflictReasonCode = L"SECONDARY_COLLECTOR_UNAVAILABLE";
        return consensus;
    }

    int compared = 0;
    int matched  = 0;
    bool highConflict = false;
    bool medConflict  = false;
    bool lowConflict  = false;

    if (!wmi.status.normalized.empty() && wmi.status.normalized != L"UNKNOWN") {
        compared++;
        if (dlv.status.normalized == wmi.status.normalized || (wmi.status.normalized == L"LICENSED" && dlv.status.raw.find(L"Licensed") != std::wstring::npos)) {
            matched++;
            consensus.wmiData.status.state = CollectorState::MATCH;
            consensus.dlvData.status.state = CollectorState::MATCH;
        } else if (dlv.status.normalized == L"UNKNOWN" || dlv.status.raw.empty()) {
            consensus.dlvData.status.state = CollectorState::UNAVAILABLE;
            compared--; // Do not penalize if unparsed localized text
        } else {
            consensus.wmiData.status.state = CollectorState::MISMATCH;
            consensus.dlvData.status.state = CollectorState::MISMATCH;
            highConflict = true;
            consensus.conflictReasonCode = L"STATUS_MISMATCH";
        }
    }

    if (!wmi.edition.normalized.empty() && wmi.edition.normalized != L"UNKNOWN") {
        compared++;
        if (dlv.edition.normalized == wmi.edition.normalized) {
            matched++;
            consensus.wmiData.edition.state = CollectorState::MATCH;
            consensus.dlvData.edition.state = CollectorState::MATCH;
        } else if (dlv.edition.normalized == L"UNKNOWN" || dlv.edition.raw.empty()) {
            consensus.dlvData.edition.state = CollectorState::UNAVAILABLE;
            compared--;
        } else {
            consensus.wmiData.edition.state = CollectorState::MISMATCH;
            consensus.dlvData.edition.state = CollectorState::MISMATCH;
            lowConflict = true;
            if (consensus.conflictReasonCode == L"NONE") consensus.conflictReasonCode = L"EDITION_MISMATCH";
        }
    }

    if (!wmi.channel.normalized.empty() && wmi.channel.normalized != L"UNKNOWN") {
        compared++;
        if (dlv.channel.normalized == wmi.channel.normalized) {
            matched++;
            consensus.wmiData.channel.state = CollectorState::MATCH;
            consensus.dlvData.channel.state = CollectorState::MATCH;
        } else if (dlv.channel.normalized == L"UNKNOWN" || dlv.channel.raw.empty()) {
            consensus.dlvData.channel.state = CollectorState::UNAVAILABLE;
            compared--;
        } else {
            consensus.wmiData.channel.state = CollectorState::MISMATCH;
            consensus.dlvData.channel.state = CollectorState::MISMATCH;
            if (dlv.channel.normalized == L"VOLUME_KMS" || wmi.channel.normalized == L"VOLUME_KMS") {
                highConflict = true;
                consensus.conflictReasonCode = L"CHANNEL_KMS_CONFLICT";
            } else {
                medConflict = true; // e.g. OEM vs Retail
                if (consensus.conflictReasonCode == L"NONE" || consensus.conflictReasonCode == L"EDITION_MISMATCH") {
                    consensus.conflictReasonCode = L"CHANNEL_UPGRADE_MISMATCH";
                }
            }
        }
    }

    if (!wmi.partialKey.normalized.empty()) {
        compared++;
        if (dlv.partialKey.normalized == wmi.partialKey.normalized) {
            matched++;
            consensus.wmiData.partialKey.state = CollectorState::MATCH;
            consensus.dlvData.partialKey.state = CollectorState::MATCH;
        } else if (dlv.partialKey.normalized.empty()) {
            consensus.dlvData.partialKey.state = CollectorState::UNAVAILABLE;
            compared--;
        } else {
            consensus.wmiData.partialKey.state = CollectorState::MISMATCH;
            consensus.dlvData.partialKey.state = CollectorState::MISMATCH;
            highConflict = true;
            consensus.conflictReasonCode = L"PARTIAL_KEY_MISMATCH";
        }
    }

    if (wmi.kmsMachine.normalized == L"NOT_APPLICABLE" && dlv.kmsMachine.normalized == L"NOT_APPLICABLE") {
        consensus.wmiData.kmsMachine.state = CollectorState::NOT_APPLICABLE;
        consensus.dlvData.kmsMachine.state = CollectorState::NOT_APPLICABLE;
    } else {
        compared++;
        if (wmi.kmsMachine.normalized == dlv.kmsMachine.normalized) {
            matched++;
            consensus.wmiData.kmsMachine.state = CollectorState::MATCH;
            consensus.dlvData.kmsMachine.state = CollectorState::MATCH;
        } else if (dlv.kmsMachine.normalized == L"NOT_APPLICABLE" && wmi.kmsMachine.normalized.empty()) {
            matched++;
            consensus.wmiData.kmsMachine.state = CollectorState::MATCH;
            consensus.dlvData.kmsMachine.state = CollectorState::MATCH;
        } else {
            consensus.wmiData.kmsMachine.state = CollectorState::MISMATCH;
            consensus.dlvData.kmsMachine.state = CollectorState::MISMATCH;
            highConflict = true; // Rogue KMS host present in one but not the other
            consensus.conflictReasonCode = L"KMS_HOST_PRESENT";
        }
    }

    consensus.comparedFields = compared;
    consensus.matchedFields  = matched;

    if (highConflict) {
        consensus.conflictLevel = ConflictSeverity::HIGH;
        consensus.confidence    = ConsensusConfidence::CONFLICT;
    } else if (medConflict) {
        consensus.conflictLevel = ConflictSeverity::MEDIUM;
        consensus.confidence    = ConsensusConfidence::MODERATE;
    } else if (lowConflict || matched < compared) {
        consensus.conflictLevel = ConflictSeverity::LOW;
        consensus.confidence    = ConsensusConfidence::MODERATE;
    } else {
        consensus.conflictLevel = ConflictSeverity::NONE;
        if (dlv.unparsedCount >= 2 || wmi.unparsedCount >= 2) {
            consensus.confidence       = ConsensusConfidence::MODERATE;
            consensus.conflictReasonCode = L"UNPARSED_LOCALIZED_FIELDS";
        } else if (compared <= 1) {
            consensus.confidence       = ConsensusConfidence::MODERATE;
            consensus.conflictReasonCode = L"LIMITED_APPLICABLE_FIELDS";
        } else {
            consensus.confidence       = ConsensusConfidence::HIGH;
        }
    }

    return consensus;
}

} // namespace LicenseInspector::Core
