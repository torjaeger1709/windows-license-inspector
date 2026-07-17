#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shlobj.h>      

#include <algorithm>
#include <conio.h>       
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>        
#include <sstream>
#include <string>
#include <vector>

#include "common/types.h"
#include "common/utils.h"
#include "ui/console_ui.h"
#include "core/wmi_query.h"
#include "core/license_cache.h"
#include "modules/module_a_windows.h"
#include "modules/module_b_office.h"

using namespace LicenseInspector;

static bool checkAdminPrivilege() {
    return IsUserAnAdmin() != FALSE;
}

struct AppArgs {
    OutputFormat format       = OutputFormat::CONSOLE_ONLY;
    std::wstring fileBase     = L"";    // Empty = auto-generate from timestamp
    bool         noPause      = false;  // --no-pause : exit immediately
    bool         noAdminCheck = false;  // --no-admin-check : allow non-admin run
    int          eventLimit   = DEFAULT_EVENT_LIMIT; // --event-limit <N>
};

static AppArgs parseArgs(int argc, wchar_t* argv[]) {
    AppArgs args;
    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];

        if ((arg == L"--output" || arg == L"-o") && i + 1 < argc) {
            std::wstring val = argv[++i];
            std::transform(val.begin(), val.end(), val.begin(), ::towlower);
            if      (val == L"txt")  args.format = OutputFormat::CONSOLE_AND_TXT;
            else if (val == L"json") args.format = OutputFormat::CONSOLE_AND_JSON;
            else if (val == L"both") args.format = OutputFormat::CONSOLE_AND_BOTH;
        }
        else if ((arg == L"--file" || arg == L"-f") && i + 1 < argc) {
            args.fileBase = argv[++i];
        }
        else if (arg == L"--event-limit" && i + 1 < argc) {
            try {
                args.eventLimit = std::stoi(argv[++i]);
                if (args.eventLimit <= 0) args.eventLimit = DEFAULT_EVENT_LIMIT;
            } catch (...) {
                args.eventLimit = DEFAULT_EVENT_LIMIT;
            }
        }
        else if (arg == L"--no-pause" || arg == L"-n") {
            args.noPause = true;
        }
        else if (arg == L"--no-admin-check") {
            args.noAdminCheck = true;
        }
        else if (arg == L"--help" || arg == L"-h") {
            wprintf(L"Usage: license-inspector.exe [--output txt|json|both] [--file <basename>] [--event-limit <N>]\n");
            wprintf(L"  --output txt     : Save report as .txt file\n");
            wprintf(L"  --output json    : Save report as .json file\n");
            wprintf(L"  --output both    : Save both .txt and .json\n");
            wprintf(L"  --file <path>    : Basename for output files (default: auto timestamp)\n");
            wprintf(L"  --event-limit <N>: Limit number of Event Log records scanned (default: %d)\n", DEFAULT_EVENT_LIMIT);
            wprintf(L"  --no-pause       : Do not prompt for key press on exit\n");
            fflush(stdout);
            fflush(stderr);
            exit(0);
        }
    }
    return args;
}

static void writeTxtReport(const std::vector<FindingResult>& findings,
                           const std::wstring& scanTime,
                           const std::wstring& hostname,
                           const SystemInfo& sysInfo,
                           const std::wstring& filePath)
{
    std::ofstream out(std::filesystem::path(filePath), std::ios::binary);
    if (!out.is_open()) {
        wprintf(L"  [!] Could not write TXT report to: %ls\n", filePath.c_str());
        return;
    }

    const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
    out.write(reinterpret_cast<const char*>(bom), sizeof(bom));

    auto writeLine = [&out](const std::wstring& wline) {
        std::string s = Utils::wstrToStr(wline);
        out.write(s.data(), s.size());
        out << "\r\n";
    };

    writeLine(L"=============================================================");
    writeLine(L"  LICENSE INSPECTOR - Scan Report (7-Layer Forensics)");
    writeLine(L"  Scan Time : " + scanTime);
    writeLine(L"  Host      : " + hostname);
    writeLine(L"=============================================================");
    writeLine(L"");
    writeLine(L"-------------------------------------------------------------");
    writeLine(L"  SYSTEM INFORMATION");
    writeLine(L"-------------------------------------------------------------");
    writeLine(L"  Host / User       : " + sysInfo.hostname + L" (User: " + sysInfo.currentUser + L")");
    writeLine(L"  Operating System  : " + sysInfo.osName);
    writeLine(L"  OS Build / Version: " + sysInfo.osBuild);
    writeLine(L"  System Hardware   : " + sysInfo.biosModel);
    writeLine(L"  Office 16 Baseline: " + sysInfo.officeVersion);
    writeLine(L"  OEM Key (BIOS)    : " + sysInfo.oemKey);
    writeLine(L"  Current Windows Key: " + sysInfo.currentOsKey);
    writeLine(L"-------------------------------------------------------------");
    writeLine(L"");

    auto severityStr = [](Severity s, bool avail) -> std::wstring {
        if (!avail) return L"N/A";
        switch (s) {
            case Severity::CLEAN:     return L"CLEAN";
            case Severity::INFO:      return L"INFO";
            case Severity::WARNING:   return L"WARNING";
            case Severity::TAMPERING: return L"TAMPERING";
            default:                  return L"UNKNOWN";
        }
    };

    auto typeStr = [](FindingType t) -> std::wstring {
        switch (t) {
            case FindingType::LICENSE_STATE:     return L"LICENSE_STATE";
            case FindingType::FORENSIC_EVIDENCE: return L"FORENSIC_EVIDENCE";
            case FindingType::CONFIGURATION:     return L"CONFIGURATION";
            case FindingType::INFORMATION:       return L"INFORMATION";
            default:                             return L"UNKNOWN";
        }
    };

    auto roleStr = [](FindingRole r) -> std::wstring {
        switch (r) {
            case FindingRole::PRIMARY:       return L"PRIMARY";
            case FindingRole::SUPPORTING:    return L"SUPPORTING";
            case FindingRole::CORROBORATIVE: return L"CORROBORATIVE";
            default:                         return L"UNKNOWN";
        }
    };

    auto dispStr = [](FindingDisposition d) -> std::wstring {
        switch (d) {
            case FindingDisposition::NORMAL:             return L"NORMAL";
            case FindingDisposition::LEGITIMATE_UPGRADE: return L"LEGITIMATE_UPGRADE";
            case FindingDisposition::SUSPICIOUS:         return L"SUSPICIOUS";
            case FindingDisposition::TAMPERED:           return L"TAMPERED";
            default:                                     return L"UNKNOWN";
        }
    };

    for (const auto& f : findings) {
        writeLine(L"[" + f.id + L"] " + f.category);
        writeLine(L"  Type        : " + typeStr(f.type) + L" (Weight: " + std::to_wstring(f.getWeight()) + L")");
        writeLine(L"  Role        : " + roleStr(f.role) + L" | Disposition: " + dispStr(f.disposition));
        writeLine(L"  Severity    : " + severityStr(f.severity, f.available));
        writeLine(L"  Detail      : " + f.detail);
        if (!f.value.empty())
            writeLine(L"  Value       : " + f.value);
        if (f.hasConsensusData) {
            const auto& c = f.consensus;
            writeLine(L"  Consensus Engine     : v" + c.consensusVersion + L" (Conflict Reason: " + c.conflictReasonCode + L")");
            writeLine(L"  Consensus Confidence : " + c.getConfidenceString());
            if (c.secondaryAvailable) {
                writeLine(L"  Collector Agreement  : " + std::to_wstring(c.matchedFields) + L"/" + std::to_wstring(c.comparedFields) + L" (" + std::to_wstring(static_cast<int>(c.getAgreementPercentage())) + L"%)");
            } else {
                writeLine(L"  Collector Agreement  : N/A (Secondary Collector Unavailable)");
            }
            writeLine(L"  Collector Provenance :");
            writeLine(L"    - Primary (" + c.wmiProvenance.collectorId + L" - " + c.wmiProvenance.collectorType + L"): " + (c.wmiProvenance.success ? L"Success" : L"Failed") + L" | Init: " + std::to_wstring(c.wmiProvenance.initMs) + L" ms | Query: " + std::to_wstring(c.wmiProvenance.queryMs) + L" ms | Parse: " + std::to_wstring(c.wmiProvenance.parseMs) + L" ms (Total: " + std::to_wstring(c.wmiProvenance.latencyMs) + L" ms | ExitCode: " + std::to_wstring(c.wmiProvenance.exitCode) + L")");
            writeLine(L"    - Secondary (" + c.dlvProvenance.collectorId + L" - " + c.dlvProvenance.collectorType + L"): " + (c.dlvProvenance.success ? L"Success" : L"Failed/Timeout") + L" | Init: " + std::to_wstring(c.dlvProvenance.initMs) + L" ms | Query: " + std::to_wstring(c.dlvProvenance.queryMs) + L" ms | Parse: " + std::to_wstring(c.dlvProvenance.parseMs) + L" ms (Total: " + std::to_wstring(c.dlvProvenance.latencyMs) + L" ms | ExitCode: " + std::to_wstring(c.dlvProvenance.exitCode) + L")");
            if (c.secondaryAvailable) {
                writeLine(L"  Collector Consensus Details:");
                writeLine(L"    - Status      : " + std::wstring(Core::CollectorConsensus::collectorStateToString(c.wmiData.status.state)) + L" [WMI: " + c.wmiData.status.normalized + L" | SLMGR: " + c.dlvData.status.normalized + L"]");
                writeLine(L"    - Edition     : " + std::wstring(Core::CollectorConsensus::collectorStateToString(c.wmiData.edition.state)) + L" [WMI: " + c.wmiData.edition.normalized + L" | SLMGR: " + c.dlvData.edition.normalized + L"]");
                writeLine(L"    - Channel     : " + std::wstring(Core::CollectorConsensus::collectorStateToString(c.wmiData.channel.state)) + L" [WMI: " + c.wmiData.channel.normalized + L" | SLMGR: " + c.dlvData.channel.normalized + L"]");
                writeLine(L"    - Partial Key : " + std::wstring(Core::CollectorConsensus::collectorStateToString(c.wmiData.partialKey.state)) + L" [WMI: " + c.wmiData.partialKey.normalized + L" | SLMGR: " + c.dlvData.partialKey.normalized + L"]");
                writeLine(L"    - KMS Machine : " + std::wstring(Core::CollectorConsensus::collectorStateToString(c.wmiData.kmsMachine.state)) + L" [WMI: " + c.wmiData.kmsMachine.normalized + L" | SLMGR: " + c.dlvData.kmsMachine.normalized + L"]");
            }
        }
        writeLine(L"");
    }

    auto summary = ScanSummary::compute(findings);
    auto verdict = Verdict::compute(summary, findings);
    EvidenceGraph graph = EvidenceGraphBuilder::build(findings);

    writeLine(L"=============================================================");
    writeLine(L"  7-LAYER FORENSIC PIPELINE SUMMARY");
    writeLine(L"  Total Checks         : " + std::to_wstring(summary.total));
    writeLine(L"  Clean                : " + std::to_wstring(summary.clean));
    writeLine(L"  Warnings             : " + std::to_wstring(summary.warning));
    writeLine(L"  Tampering            : " + std::to_wstring(summary.tampering));
    writeLine(L"  Unavailable          : " + std::to_wstring(summary.unavailable));
    writeLine(L"  Information          : " + std::to_wstring(summary.information));
    writeLine(L"-------------------------------------------------------------");

    // Layer 1
    int verCount = 0, strongCount = 0, modCount = 0;
    for (const auto& f : findings) {
        if (f.verificationStatus != VerificationStatus::ACCESS_DENIED && f.verificationStatus != VerificationStatus::ERROR_OCCURRED && f.verificationStatus != VerificationStatus::NOT_APPLICABLE && f.verificationStatus != VerificationStatus::UNSUPPORTED) {
            if (f.reliability == EvidenceReliability::VERIFIED) verCount++;
            else if (f.reliability == EvidenceReliability::STRONG) strongCount++;
            else modCount++;
        }
    }
    writeLine(L"  LAYER 1 COLLECTORS   : Registry/WMI/COM: VERIFIED (" + std::to_wstring(verCount) +
              L") | Network/Hosts: STRONG (" + std::to_wstring(strongCount) +
              L") | Files/Tasks: MODERATE (" + std::to_wstring(modCount) + L")");
    writeLine(L"  Collector Breakdown  : FOUND: " + std::to_wstring(summary.foundCount) +
              L" | NOT_FOUND: " + std::to_wstring(summary.notFoundCount) +
              L" | NOT_APPLICABLE: " + std::to_wstring(summary.notApplicableCount) +
              L" | ACCESS_DENIED: " + std::to_wstring(summary.accessDeniedCount) +
              L" | ERROR: " + std::to_wstring(summary.errorCount));

    if (summary.accessDeniedCount > 0 || summary.errorCount > 0) {
        writeLine(L"  Collector Status     : [ WARNING ] - " + std::to_wstring(summary.accessDeniedCount) + L" Access Denied, " + std::to_wstring(summary.errorCount) + L" Errors encountered during collection");
    } else {
        writeLine(L"  Collector Status     : [ OK / 100% SUCCESS ] - All applicable collectors completed cleanly without errors");
    }

    // Layer 4
    writeLine(L"-------------------------------------------------------------");
    writeLine(L"  LAYER 4 EVIDENCE GRAPH: Graph Nodes: " + std::to_wstring((int)graph.nodes.size()) + L" | Graph Edges: " + std::to_wstring((int)graph.edges.size()) + L" | Confirmed Nodes: " + std::to_wstring(graph.uniqueSourceCount));
    if (graph.confirmedEdgeCount == 0 && !graph.hasActiveTampering) {
        writeLine(L"  Relationship Status  : No corroborating relationships established (Clean Graph)");
    } else {
        writeLine(L"  Relationship Status  : " + std::to_wstring(graph.confirmedEdgeCount) + L" corroborating relationship(s) established across " + std::to_wstring(graph.uniqueSourceCount) + L" independent source(s)");
        for (const auto& node : graph.nodes) {
            for (const auto* edge : node.outgoingEdges) {
                std::wstring relStr = L"USES";
                if (edge->relation == EdgeRelation::SUPPORTS) relStr = L"SUPPORTS";
                else if (edge->relation == EdgeRelation::CONTRADICTS) relStr = L"CONTRADICTS";
                else if (edge->relation == EdgeRelation::TRIGGERS) relStr = L"TRIGGERS";
                else if (edge->relation == EdgeRelation::CORROBORATES) relStr = L"CORROBORATES";
                writeLine(L"    * [" + edge->sourceId + L"] --(" + relStr + L")--> [" + edge->targetId + L"] : " + edge->detail);
            }
        }
    }

    writeLine(L"-------------------------------------------------------------");
    writeLine(L"  EVIDENCE SCORE (Risk)  : [ " + std::to_wstring(summary.evidenceScore) + L" pts ] -> " +
              (summary.evidenceScore >= 40 ? L"HIGH RISK (Active Tampering)" : (summary.evidenceScore >= 15 ? L"MODERATE RISK (Suspicious)" : L"LOW RISK (0 Tampering Artifacts)")));
    writeLine(L"  TRUST SCORE (Integrity): [ " + std::to_wstring(summary.trustScore) + L" / 100 ] -> " + summary.trustLevel);
    writeLine(L"  Integrity Gauge        : " + summary.trustGauge);
    writeLine(L"  CERTAINTY INDEX        : " + verdict.confidenceString);
    writeLine(L"  RISK RANKING           : " + verdict.riskRanking);
    writeLine(L"-------------------------------------------------------------");
    writeLine(L"  VERDICT                : " + verdict.title);
    writeLine(L"  EXPLANATION            : " + verdict.description);
    if (!verdict.reasons.empty()) {
        writeLine(L"-------------------------------------------------------------");
        writeLine(L"  REASONS FOR VERDICT:");
        for (const auto& r : verdict.reasons) {
            writeLine(L"    * " + r);
        }
    }
    if (!verdict.recommendations.empty()) {
        writeLine(L"-------------------------------------------------------------");
        writeLine(L"  RECOMMENDATIONS:");
        for (const auto& rec : verdict.recommendations) {
            writeLine(L"    -> " + rec);
        }
    }
    writeLine(L"=============================================================");

    wprintf(L"  [+] TXT report saved: %ls\n", filePath.c_str());
}

static std::wstring jsonEscape(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size() + 16);
    for (wchar_t c : s) {
        switch (c) {
            case L'"':  out += LR"(\")";  break;
            case L'\\': out += LR"(\\)";  break;
            case L'\n': out += LR"(\n)";  break;
            case L'\r': out += LR"(\r)";  break;
            case L'\t': out += LR"(\t)";  break;
            default:    out += c;         break;
        }
    }
    return out;
}

static void writeJsonReport(const std::vector<FindingResult>& findings,
                            const std::wstring& scanTime,
                            const std::wstring& hostname,
                            const SystemInfo& sysInfo,
                            const std::wstring& filePath)
{
    std::ofstream out(std::filesystem::path(filePath), std::ios::binary);
    if (!out.is_open()) {
        wprintf(L"  [!] Could not write JSON report to: %ls\n", filePath.c_str());
        return;
    }

    const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
    out.write(reinterpret_cast<const char*>(bom), sizeof(bom));

    auto writeStr = [&out](const std::wstring& wstr) {
        std::string s = Utils::wstrToStr(wstr);
        out.write(s.data(), s.size());
    };

    auto severityStr = [](Severity s, bool avail) -> std::wstring {
        if (!avail) return L"UNAVAILABLE";
        switch (s) {
            case Severity::CLEAN:     return L"CLEAN";
            case Severity::INFO:      return L"INFO";
            case Severity::WARNING:   return L"WARNING";
            case Severity::TAMPERING: return L"TAMPERING";
            default:                  return L"UNKNOWN";
        }
    };

    auto typeStr = [](FindingType t) -> std::wstring {
        switch (t) {
            case FindingType::LICENSE_STATE:     return L"LICENSE_STATE";
            case FindingType::FORENSIC_EVIDENCE: return L"FORENSIC_EVIDENCE";
            case FindingType::CONFIGURATION:     return L"CONFIGURATION";
            case FindingType::INFORMATION:       return L"INFORMATION";
            default:                             return L"UNKNOWN";
        }
    };

    auto roleStr = [](FindingRole r) -> std::wstring {
        switch (r) {
            case FindingRole::PRIMARY:       return L"PRIMARY";
            case FindingRole::SUPPORTING:    return L"SUPPORTING";
            case FindingRole::CORROBORATIVE: return L"CORROBORATIVE";
            default:                         return L"UNKNOWN";
        }
    };

    auto dispStr = [](FindingDisposition d) -> std::wstring {
        switch (d) {
            case FindingDisposition::NORMAL:             return L"NORMAL";
            case FindingDisposition::LEGITIMATE_UPGRADE: return L"LEGITIMATE_UPGRADE";
            case FindingDisposition::SUSPICIOUS:         return L"SUSPICIOUS";
            case FindingDisposition::TAMPERED:           return L"TAMPERED";
            default:                                     return L"UNKNOWN";
        }
    };

    auto originStr = [](EvidenceOrigin o) -> std::wstring {
        switch (o) {
            case EvidenceOrigin::OBSERVED:   return L"OBSERVED";
            case EvidenceOrigin::DERIVED:    return L"DERIVED";
            case EvidenceOrigin::CORRELATED: return L"CORRELATED";
            default:                         return L"UNKNOWN";
        }
    };

    auto summary = ScanSummary::compute(findings);
    auto verdict = Verdict::compute(summary, findings);

    writeStr(L"{\r\n");
    writeStr(L"  \"tool\": \"LicenseInspector\",\r\n");
    writeStr(L"  \"version\": \"1.1.0\",\r\n");
    writeStr(L"  \"scan_time\": \"" + jsonEscape(scanTime) + L"\",\r\n");
    writeStr(L"  \"hostname\": \"" + jsonEscape(hostname) + L"\",\r\n");
    writeStr(L"  \"system_info\": {\r\n");
    writeStr(L"    \"os_name\": \""        + jsonEscape(sysInfo.osName)        + L"\",\r\n");
    writeStr(L"    \"os_build\": \""       + jsonEscape(sysInfo.osBuild)       + L"\",\r\n");
    writeStr(L"    \"current_user\": \""   + jsonEscape(sysInfo.currentUser)   + L"\",\r\n");
    writeStr(L"    \"bios_model\": \""     + jsonEscape(sysInfo.biosModel)     + L"\",\r\n");
    writeStr(L"    \"office_version\": \"" + jsonEscape(sysInfo.officeVersion) + L"\",\r\n");
    writeStr(L"    \"oem_key\": \""        + jsonEscape(sysInfo.oemKey)        + L"\",\r\n");
    writeStr(L"    \"current_os_key\": \"" + jsonEscape(sysInfo.currentOsKey)  + L"\"\r\n");
    writeStr(L"  },\r\n");
    writeStr(L"  \"findings\": [\r\n");

    for (size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        writeStr(L"    {\r\n");
        writeStr(L"      \"id\": \""          + jsonEscape(f.id)       + L"\",\r\n");
        writeStr(L"      \"category\": \""    + jsonEscape(f.category) + L"\",\r\n");
        writeStr(L"      \"type\": \""        + typeStr(f.type)        + L"\",\r\n");
        writeStr(L"      \"role\": \""        + roleStr(f.role)        + L"\",\r\n");
        writeStr(L"      \"disposition\": \"" + dispStr(f.disposition) + L"\",\r\n");
        writeStr(L"      \"origin\": \""      + originStr(f.origin)    + L"\",\r\n");
        writeStr(L"      \"weight\": "        + std::to_wstring(f.getWeight()) + L",\r\n");
        writeStr(L"      \"severity\": \""    + severityStr(f.severity, f.available) + L"\",\r\n");
        writeStr(L"      \"flagged\": "       + std::wstring(f.flagged   ? L"true" : L"false") + L",\r\n");
        writeStr(L"      \"available\": "     + std::wstring(f.available ? L"true" : L"false") + L",\r\n");
        writeStr(L"      \"detail\": \""      + jsonEscape(f.detail)   + L"\",\r\n");
        writeStr(L"      \"value\": \""       + jsonEscape(f.value)    + L"\"");
        if (f.hasConsensusData) {
            const auto& c = f.consensus;
            writeStr(L",\r\n");
            writeStr(L"      \"collector_consensus\": {\r\n");
            writeStr(L"        \"consensus_version\": \""    + jsonEscape(c.consensusVersion)          + L"\",\r\n");
            writeStr(L"        \"conflict_reason_code\": \"" + jsonEscape(c.conflictReasonCode)        + L"\",\r\n");
            writeStr(L"        \"confidence\": \""           + jsonEscape(c.getConfidenceString())     + L"\",\r\n");
            writeStr(L"        \"agreement_percentage\": "   + std::to_wstring(c.getAgreementPercentage()) + L",\r\n");
            writeStr(L"        \"matched_fields\": "         + std::to_wstring(c.matchedFields)        + L",\r\n");
            writeStr(L"        \"compared_fields\": "        + std::to_wstring(c.comparedFields)       + L",\r\n");
            writeStr(L"        \"conflict_severity\": \""    + jsonEscape(c.getConflictLevelString())  + L"\",\r\n");
            writeStr(L"        \"secondary_available\": "    + std::wstring(c.secondaryAvailable ? L"true" : L"false") + L",\r\n");
            writeStr(L"        \"provenance\": {\r\n");
            writeStr(L"          \"wmi\": { \"collector_id\": \"" + jsonEscape(c.wmiProvenance.collectorId) + L"\", \"type\": \"" + jsonEscape(c.wmiProvenance.collectorType) + L"\", \"success\": " + (c.wmiProvenance.success ? L"true" : L"false") + L", \"latency_ms\": " + std::to_wstring(c.wmiProvenance.latencyMs) + L", \"breakdown_ms\": { \"init\": " + std::to_wstring(c.wmiProvenance.initMs) + L", \"query\": " + std::to_wstring(c.wmiProvenance.queryMs) + L", \"parse\": " + std::to_wstring(c.wmiProvenance.parseMs) + L" }, \"exit_code\": " + std::to_wstring(c.wmiProvenance.exitCode) + L" },\r\n");
            writeStr(L"          \"slmgr\": { \"collector_id\": \"" + jsonEscape(c.dlvProvenance.collectorId) + L"\", \"type\": \"" + jsonEscape(c.dlvProvenance.collectorType) + L"\", \"success\": " + (c.dlvProvenance.success ? L"true" : L"false") + L", \"latency_ms\": " + std::to_wstring(c.dlvProvenance.latencyMs) + L", \"breakdown_ms\": { \"init\": " + std::to_wstring(c.dlvProvenance.initMs) + L", \"query\": " + std::to_wstring(c.dlvProvenance.queryMs) + L", \"parse\": " + std::to_wstring(c.dlvProvenance.parseMs) + L" }, \"exit_code\": " + std::to_wstring(c.dlvProvenance.exitCode) + L" }\r\n");
            writeStr(L"        },\r\n");
            writeStr(L"        \"raw_slmgr_output\": \"" + jsonEscape(c.dlvData.rawOutputText) + L"\",\r\n");
            writeStr(L"        \"fields\": {\r\n");
            writeStr(L"          \"status\": { \"state\": \"" + std::wstring(Core::CollectorConsensus::collectorStateToString(c.wmiData.status.state)) + L"\", \"wmi\": \"" + jsonEscape(c.wmiData.status.normalized) + L"\", \"slmgr\": \"" + jsonEscape(c.dlvData.status.normalized) + L"\" },\r\n");
            writeStr(L"          \"edition\": { \"state\": \"" + std::wstring(Core::CollectorConsensus::collectorStateToString(c.wmiData.edition.state)) + L"\", \"wmi\": { \"raw\": \"" + jsonEscape(c.wmiData.edition.raw) + L"\", \"normalized\": \"" + jsonEscape(c.wmiData.edition.normalized) + L"\" }, \"slmgr\": { \"raw\": \"" + jsonEscape(c.dlvData.edition.raw) + L"\", \"normalized\": \"" + jsonEscape(c.dlvData.edition.normalized) + L"\" } },\r\n");
            writeStr(L"          \"channel\": { \"state\": \"" + std::wstring(Core::CollectorConsensus::collectorStateToString(c.wmiData.channel.state)) + L"\", \"wmi\": { \"raw\": \"" + jsonEscape(c.wmiData.channel.raw) + L"\", \"normalized\": \"" + jsonEscape(c.wmiData.channel.normalized) + L"\" }, \"slmgr\": { \"raw\": \"" + jsonEscape(c.dlvData.channel.raw) + L"\", \"normalized\": \"" + jsonEscape(c.dlvData.channel.normalized) + L"\" } },\r\n");
            writeStr(L"          \"partial_key\": { \"state\": \"" + std::wstring(Core::CollectorConsensus::collectorStateToString(c.wmiData.partialKey.state)) + L"\", \"wmi\": \"" + jsonEscape(c.wmiData.partialKey.normalized) + L"\", \"slmgr\": \"" + jsonEscape(c.dlvData.partialKey.normalized) + L"\" },\r\n");
            writeStr(L"          \"kms_machine\": { \"state\": \"" + std::wstring(Core::CollectorConsensus::collectorStateToString(c.wmiData.kmsMachine.state)) + L"\", \"wmi\": \"" + jsonEscape(c.wmiData.kmsMachine.normalized) + L"\", \"slmgr\": \"" + jsonEscape(c.dlvData.kmsMachine.normalized) + L"\" }\r\n");
            writeStr(L"        }\r\n");
            writeStr(L"      }\r\n");
        } else {
            writeStr(L"\r\n");
        }
        writeStr(L"    }" + std::wstring(i + 1 < findings.size() ? L"," : L"") + L"\r\n");
    }

    writeStr(L"  ],\r\n");
    writeStr(L"  \"summary\": {\r\n");
    writeStr(L"    \"total\": "                    + std::to_wstring(summary.total)             + L",\r\n");
    writeStr(L"    \"clean\": "                    + std::to_wstring(summary.clean)             + L",\r\n");
    writeStr(L"    \"warnings\": "                 + std::to_wstring(summary.warning)          + L",\r\n");
    writeStr(L"    \"tampering\": "                + std::to_wstring(summary.tampering)        + L",\r\n");
    writeStr(L"    \"unavailable\": "              + std::to_wstring(summary.unavailable)       + L",\r\n");
    writeStr(L"    \"information\": "              + std::to_wstring(summary.information)       + L",\r\n");
    writeStr(L"    \"evidence_score\": "           + std::to_wstring(summary.evidenceScore)     + L",\r\n");
    writeStr(L"    \"forensic_tampering_count\": " + std::to_wstring(summary.forensicTampering) + L",\r\n");
    writeStr(L"    \"license_attention_count\": "  + std::to_wstring(summary.licenseAttention)  + L",\r\n");
    writeStr(L"    \"trust_score\": "              + std::to_wstring(summary.trustScore)        + L",\r\n");
    writeStr(L"    \"trust_level\": \""            + jsonEscape(summary.trustLevel)             + L"\",\r\n");
    writeStr(L"    \"trust_gauge\": \""            + jsonEscape(summary.trustGauge)             + L"\"\r\n");
    writeStr(L"  },\r\n");
    writeStr(L"  \"verdict\": {\r\n");
    std::wstring levelStr = L"CLEAN";
    if (verdict.level == VerdictLevel::EVIDENCE_OF_TAMPERING) levelStr = L"EVIDENCE_OF_TAMPERING";
    else if (verdict.level == VerdictLevel::SUSPICIOUS_CONFIG) levelStr = L"SUSPICIOUS_CONFIG";
    else if (verdict.level == VerdictLevel::LICENSE_ATTENTION) levelStr = L"LICENSE_ATTENTION";
    writeStr(L"    \"level\": \""            + levelStr + L"\",\r\n");
    writeStr(L"    \"title\": \""            + jsonEscape(verdict.title)            + L"\",\r\n");
    writeStr(L"    \"description\": \""      + jsonEscape(verdict.description)      + L"\",\r\n");
    writeStr(L"    \"certainty_index\": "    + std::to_wstring(verdict.confidenceIndex) + L",\r\n");
    writeStr(L"    \"certainty_string\": \"" + jsonEscape(verdict.confidenceString) + L"\",\r\n");
    writeStr(L"    \"risk_ranking\": \""     + jsonEscape(verdict.riskRanking)      + L"\",\r\n");
    
    writeStr(L"    \"reasons\": [\r\n");
    for (size_t i = 0; i < verdict.reasons.size(); ++i) {
        writeStr(L"      \"" + jsonEscape(verdict.reasons[i]) + L"\"" + (i + 1 < verdict.reasons.size() ? L"," : L"") + L"\r\n");
    }
    writeStr(L"    ],\r\n");

    writeStr(L"    \"recommendations\": [\r\n");
    for (size_t i = 0; i < verdict.recommendations.size(); ++i) {
        writeStr(L"      \"" + jsonEscape(verdict.recommendations[i]) + L"\"" + (i + 1 < verdict.recommendations.size() ? L"," : L"") + L"\r\n");
    }
    writeStr(L"    ]\r\n");

    writeStr(L"  }\r\n");
    writeStr(L"}\r\n");

    wprintf(L"  [+] JSON report saved: %ls\n", filePath.c_str());
}


#include <locale.h>
#include <io.h>
#include <fcntl.h>

int wmain(int argc, wchar_t* argv[]) {
    setlocale(LC_ALL, ".UTF-8");
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    AppArgs args = parseArgs(argc, argv);

    UI::printBanner();

    if (!checkAdminPrivilege()) {
        if (!args.noAdminCheck) {
            UI::setColor(UI::COLOR_YELLOW);
            wprintf(L"  [WARN] Administrator privileges not detected.\n");
            wprintf(L"         Tip: Pass '--no-admin-check' to bypass exit and run best-effort scan.\n");
            UI::resetColor();
            if (_isatty(_fileno(stdout))) {
                wprintf(L"\n");
                fflush(stdout);
                fflush(stderr);
                return 1;
            } else {
                wprintf(L"  [INFO] Pipe environment detected: continuing best-effort scan without admin privileges.\n");
            }
        } else {
            UI::setColor(UI::COLOR_YELLOW);
            wprintf(L"  [WARN] Running without Administrator privileges (--no-admin-check).\n");
            wprintf(L"         Some checks may report Access Denied or incomplete forensic data.\n");
            UI::resetColor();
        }
    } else {
        UI::setColor(UI::COLOR_GREEN);
        wprintf(L"  [OK] Running with Administrator privileges.\n");
        UI::resetColor();
    }

    std::wstring scanTime = Utils::getCurrentTimestampISO();
    std::wstring hostname = Utils::getHostname();

    UI::setColor(UI::COLOR_GRAY);
    wprintf(L"  Scan started : %ls\n", scanTime.c_str());
    UI::resetColor();

    wprintf(L"\n");
    UI::setColor(UI::COLOR_CYAN);
    wprintf(L"  Initializing WMI connection (root\\CIMV2)...\n");
    UI::resetColor();

    std::unique_ptr<WMI::WmiClient> wmiClient;
    try {
        wmiClient = std::make_unique<WMI::WmiClient>(L"ROOT\\CIMV2");
        if (wmiClient->isConnected()) {
            UI::setColor(UI::COLOR_GREEN);
            wprintf(L"  [OK] WMI connected.\n");
            UI::resetColor();
        } else {
            UI::setColor(UI::COLOR_YELLOW);
            wprintf(L"  [WARN] WMI connection failed. Some checks will be skipped.\n");
            UI::resetColor();
        }
    } catch (const std::exception& e) {
        UI::setColor(UI::COLOR_YELLOW);
        wprintf(L"  [WARN] WMI init exception: %hs. Some checks will be skipped.\n", e.what());
        UI::resetColor();
        wmiClient = std::make_unique<WMI::WmiClient>(L"ROOT\\CIMV2");
    }

    UI::setColor(UI::COLOR_CYAN);
    wprintf(L"  Warming up License Consensus Cache (WMI + SLMGR via pipe)...\n");
    UI::resetColor();
    Core::LicenseDataCache::warmUp(wmiClient.get());
    UI::setColor(UI::COLOR_GREEN);
    wprintf(L"  [OK] License Consensus Cache ready.\n\n");
    UI::resetColor();

    SystemInfo sysInfo = Utils::querySystemInfo(wmiClient.get());
    UI::printSystemInfo(sysInfo);

    std::vector<FindingResult> allFindings;

    UI::printSectionHeader(L"MODULE A - Windows License Forensics (A1 - A14)",
                           UI::COLOR_CYAN);

    auto runAndPrint = [&](const std::wstring& label, auto fn) {
        UI::setColor(UI::COLOR_GRAY);
        wprintf(L"  >> Checking: %ls...\n", label.c_str());
        UI::resetColor();
        auto result = fn();
        if constexpr (std::is_same_v<decltype(result), FindingResult>) {
            UI::printResult(result);
            allFindings.push_back(std::move(result));
        } else {
            for (auto& r : result) {
                UI::printResult(r);
                allFindings.push_back(std::move(r));
            }
        }
    };

    runAndPrint(L"A1 - Rogue KMS Server (Registry / WMI)",
        [&]() { return ModuleA::checkKmsRogueServer(*wmiClient); });

    runAndPrint(L"A2 - PowerShell / MAS Command History",
        []() { return ModuleA::checkPowerShellHistory(); });

    runAndPrint(L"A3 - KMS38 Timestamp Activation Hook",
        [&]() { return ModuleA::checkKms38Hook(*wmiClient); });

    runAndPrint(L"A4 - License State & Channel Inspection",
        [&]() { return ModuleA::checkLicenseStateChannel(*wmiClient); });

    runAndPrint(L"A5 - Crack Tool Directory Scan",
        []() { return ModuleA::checkCrackDirectories(); });

    runAndPrint(L"A6 - Hidden Scheduled Activator Tasks",
        []() { return ModuleA::checkHiddenScheduledTasks(); });

    runAndPrint(L"A7 - Telemetry Suppression Policy (NoGenTicket)",
        []() { return ModuleA::checkTelemetryRegistryPolicy(); });

    runAndPrint(L"A8 - Software Protection Service Configuration",
        []() { return ModuleA::checkSoftwareProtectionService(); });

    runAndPrint(L"A9 - Unauthorized KMS Emulator Services",
        []() { return ModuleA::checkKmsWindowsServices(); });

    runAndPrint(L"A10 - Hosts File Domain Redirections",
        []() { return ModuleA::checkHostsFileTampering(); });

    runAndPrint(L"A11 - Licensing Store Logical Consistency",
        [&]() { return ModuleA::checkLicensingStoreConsistency(*wmiClient); });

    runAndPrint(L"A12 - Software Protection Event Logs",
        [&]() { return ModuleA::checkSoftwareProtectionEventLog(args.eventLimit); });

    runAndPrint(L"A13 - SPP COM Integrity & DLL Hijack Check",
        []() { return ModuleA::checkSppComIntegrity(); });

    runAndPrint(L"A14 - Firmware License Consistency Check",
        [&]() { return ModuleA::checkFirmwareLicenseConsistency(*wmiClient); });

    UI::printSectionHeader(L"MODULE B - Microsoft Office 16 License Inspection",
                           UI::COLOR_MAGENTA);

    runAndPrint(L"B1 - Office WMI License Status",
        [&]() { return ModuleB::queryOfficeWmi(*wmiClient); });

    runAndPrint(L"B2 - OSPP.VBS License Parser",
        []() { return ModuleB::parseOsppVbs(); });

    runAndPrint(L"B3 - Click-to-Run / Digital License Check",
        []() { return ModuleB::checkOfficeDigitalLicense(); });

    UI::printFinalSummary(allFindings, scanTime, hostname);

    if (args.format != OutputFormat::CONSOLE_ONLY) {
        std::wstring base = args.fileBase;
        if (base.empty()) {
            base = L"license_report_" + Utils::getCurrentTimestamp();
        }

        bool writeTxt  = (args.format == OutputFormat::CONSOLE_AND_TXT  ||
                          args.format == OutputFormat::CONSOLE_AND_BOTH);
        bool writeJson = (args.format == OutputFormat::CONSOLE_AND_JSON ||
                          args.format == OutputFormat::CONSOLE_AND_BOTH);

        UI::printSectionHeader(L"OUTPUT FILES", UI::COLOR_YELLOW);

        if (writeTxt)  writeTxtReport(allFindings,  scanTime, hostname, sysInfo, base + L".txt");
        if (writeJson) writeJsonReport(allFindings, scanTime, hostname, sysInfo, base + L".json");

        const auto& cons = Core::LicenseDataCache::getConsensus();
        if (cons.secondaryAvailable && !cons.dlvData.rawOutputText.empty()) {
            std::wstring slmgrPath = base + L"_slmgr.txt";
            std::ofstream outSlmgr(std::filesystem::path(slmgrPath), std::ios::binary);
            if (outSlmgr.is_open()) {
                const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
                outSlmgr.write(reinterpret_cast<const char*>(bom), sizeof(bom));
                std::string s = Utils::wstrToStr(cons.dlvData.rawOutputText);
                outSlmgr.write(s.data(), s.size());
                wprintf(L"  [OK] Saved Raw SLMGR Collector Output : %ls\n", slmgrPath.c_str());
            }
            std::error_code ec;
            std::filesystem::create_directory("collector_output", ec);
            if (!ec) {
                std::ofstream outDir(std::filesystem::path("collector_output/slmgr.txt"), std::ios::binary);
                if (outDir.is_open()) {
                    const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
                    outDir.write(reinterpret_cast<const char*>(bom), sizeof(bom));
                    std::string s = Utils::wstrToStr(cons.dlvData.rawOutputText);
                    outDir.write(s.data(), s.size());
                    wprintf(L"  [OK] Saved Audit Mirror Output        : collector_output/slmgr.txt\n");
                }
            }
        }

        wprintf(L"\n");
    }

    if (!args.noPause) {
        wprintf(L"  Press any key to exit...\n");
        fflush(stdout);
        _getch();
    }
    fflush(stdout);
    fflush(stderr);
    return 0;
}
