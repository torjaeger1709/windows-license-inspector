#include "ui/console_ui.h"
#include "common/types.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>

namespace LicenseInspector::UI {

static HANDLE hStdout() {
    static HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    return h;
}


void setColor(WORD color) {
    SetConsoleTextAttribute(hStdout(), color);
}

void resetColor() {
    SetConsoleTextAttribute(hStdout(), COLOR_DEFAULT);
}

void printColored(const std::wstring& text, WORD color) {
    setColor(color);
    wprintf(L"%ls", text.c_str());
    resetColor();
}


static WORD severityToColor(Severity s) {
    switch (s) {
        case Severity::CLEAN:     return COLOR_GREEN;
        case Severity::INFO:      return COLOR_CYAN;
        case Severity::WARNING:   return COLOR_YELLOW;
        case Severity::TAMPERING: return COLOR_RED;
        default:                  return COLOR_DEFAULT;
    }
}

static const wchar_t* severityToLabel(Severity s, bool available) {
    if (!available) return L"  N/A  ";
    switch (s) {
        case Severity::CLEAN:     return L" CLEAN ";
        case Severity::INFO:      return L" INFO  ";
        case Severity::WARNING:   return L"  WARN ";
        case Severity::TAMPERING: return L"TAMPER ";
        default:                  return L"  ???  ";
    }
}

static const wchar_t* severityToIcon(Severity s, bool available) {
    if (!available) return L"-";
    switch (s) {
        case Severity::CLEAN:     return L"+";
        case Severity::INFO:      return L"i";
        case Severity::WARNING:   return L"!";
        case Severity::TAMPERING: return L"X";
        default:                  return L"?";
    }
}


void printDivider(wchar_t ch, int width) {
    setColor(COLOR_GRAY);
    for (int i = 0; i < width; ++i) putwchar(ch);
    putwchar(L'\n');
    resetColor();
}

void printBanner() {
    SetConsoleOutputCP(CP_UTF8);

    printDivider(L'=');
    setColor(COLOR_CYAN);
    wprintf(L"\n");
    wprintf(L"  ██╗     ██╗ ██████╗███████╗███╗   ██╗███████╗███████╗\n");
    wprintf(L"  ██║     ██║██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝\n");
    wprintf(L"  ██║     ██║██║     █████╗  ██╔██╗ ██║███████╗█████╗  \n");
    wprintf(L"  ██║     ██║██║     ██╔══╝  ██║╚██╗██║╚════██║██╔══╝  \n");
    wprintf(L"  ███████╗██║╚██████╗███████╗██║ ╚████║███████║███████╗\n");
    wprintf(L"  ╚══════╝╚═╝ ╚═════╝╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝\n");
    resetColor();

    setColor(COLOR_WHITE);
    wprintf(L"\n  ██║███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗ ██████╗ ██████╗ \n");
    wprintf(L"  ██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗\n");
    wprintf(L"  ██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   ██║   ██║██████╔╝\n");
    wprintf(L"  ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗\n");
    wprintf(L"  ██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║\n");
    wprintf(L"  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝\n");
    resetColor();

    wprintf(L"\n");
    printDivider(L'=');
    setColor(COLOR_YELLOW);
    wprintf(L"  Windows/Office License Crack Detector \n");
    wprintf(L"  [!] Runs with Administrator privileges \n");
    resetColor();
    printDivider(L'=');
    wprintf(L"\n");
    fflush(stdout);
}

void printSectionHeader(const std::wstring& title, WORD color) {
    wprintf(L"\n");
    printDivider(L'-');
    setColor(color);
    wprintf(L"  %ls\n", title.c_str());
    resetColor();
    printDivider(L'-');
}

void printSystemInfo(const SystemInfo& info) {
    wprintf(L"\n");
    printDivider(L'-');
    setColor(COLOR_CYAN);
    wprintf(L"  SYSTEM INFORMATION & BASELINE\n");
    resetColor();
    printDivider(L'-');
    wprintf(L"  %-20ls : ", L"Host / User");
    setColor(COLOR_WHITE);
    wprintf(L"%ls (User: %ls)\n", info.hostname.c_str(), info.currentUser.c_str());
    resetColor();

    wprintf(L"  %-20ls : ", L"Operating System");
    setColor(COLOR_WHITE);
    wprintf(L"%ls\n", info.osName.c_str());
    resetColor();

    wprintf(L"  %-20ls : ", L"OS Build / Version");
    setColor(COLOR_WHITE);
    wprintf(L"%ls\n", info.osBuild.c_str());
    resetColor();

    wprintf(L"  %-20ls : ", L"System Hardware");
    setColor(COLOR_WHITE);
    wprintf(L"%ls\n", info.biosModel.c_str());
    resetColor();

    wprintf(L"  %-20ls : ", L"Office 16 Baseline");
    setColor(COLOR_WHITE);
    wprintf(L"%ls\n", info.officeVersion.c_str());
    resetColor();

    wprintf(L"  %-20ls : ", L"OEM Key (BIOS)");
    setColor(COLOR_WHITE);
    wprintf(L"%ls\n", info.oemKey.c_str());
    resetColor();

    wprintf(L"  %-20ls : ", L"Current Windows Key");
    setColor(COLOR_WHITE);
    wprintf(L"%ls\n", info.currentOsKey.c_str());
    resetColor();
    printDivider(L'-');
}

void printResult(const FindingResult& result) {
    WORD   col   = severityToColor(result.severity);
    const  wchar_t* icon  = severityToIcon(result.severity, result.available);
    const  wchar_t* label = severityToLabel(result.severity, result.available);

    if (!result.available) col = COLOR_GRAY;

    if (result.disposition == FindingDisposition::LEGITIMATE_UPGRADE) {
        label = L"UPGRADE";
        col = COLOR_CYAN;
        icon = L"*";
    } else if (result.disposition == FindingDisposition::SUSPICIOUS) {
        label = L"SUSPECT";
        col = COLOR_YELLOW;
        icon = L"!";
    } else if (result.disposition == FindingDisposition::TAMPERED) {
        label = L"TAMPER ";
        col = COLOR_RED;
        icon = L"X";
    }

    wprintf(L"  ");
    setColor(col);
    wprintf(L"[%ls]", label);
    resetColor();

    setColor(COLOR_WHITE);
    wprintf(L" %ls  ", icon);
    resetColor();

    setColor(col | FOREGROUND_INTENSITY);
    wprintf(L"%-40ls", result.category.c_str());
    resetColor();

    wprintf(L"\n");

    setColor(COLOR_GRAY);
    wprintf(L"         -> %ls\n", result.detail.c_str());

    if (!result.value.empty()) {
        wprintf(L"           Value: ");
        setColor(col);
        wprintf(L"%ls\n", result.value.c_str());
        resetColor();
    }

    if (result.hasConsensusData) {
        const auto& c = result.consensus;
        setColor(COLOR_WHITE);
        wprintf(L"           Consensus Engine     : v%ls (Conflict Reason: %ls)\n",
                c.consensusVersion.c_str(), c.conflictReasonCode.c_str());
        wprintf(L"           Consensus Confidence : ");
        if (c.confidence == Core::ConsensusConfidence::HIGH) setColor(COLOR_GREEN);
        else if (c.confidence == Core::ConsensusConfidence::WMI_ONLY) setColor(COLOR_CYAN);
        else setColor(COLOR_YELLOW);
        wprintf(L"%ls\n", c.getConfidenceString().c_str());
        resetColor();

        setColor(COLOR_GRAY);
        if (c.secondaryAvailable) {
            wprintf(L"           Collector Agreement  : %d/%d (%.0f%%)\n", c.matchedFields, c.comparedFields, c.getAgreementPercentage());
        } else {
            wprintf(L"           Collector Agreement  : N/A (Secondary Collector Unavailable)\n");
        }
        wprintf(L"           Collector Provenance :\n");
        wprintf(L"               [%-19ls] %-24ls: %ls | Init: %lld ms | Query: %lld ms | Parse: %lld ms (Total: %lld ms | Exit: %d)\n",
                c.wmiProvenance.collectorId.c_str(),
                L"COM API (IWbemServices)",
                c.wmiProvenance.success ? L"Success" : L"Failed",
                c.wmiProvenance.initMs, c.wmiProvenance.queryMs, c.wmiProvenance.parseMs, c.wmiProvenance.latencyMs, c.wmiProvenance.exitCode);
        wprintf(L"               [%-19ls] %-24ls: %ls | Init: %lld ms | Query: %lld ms | Parse: %lld ms (Total: %lld ms | Exit: %d)\n",
                c.dlvProvenance.collectorId.c_str(),
                L"VBScript (cscript.exe)",
                c.dlvProvenance.success ? L"Success" : L"Failed/Timeout",
                c.dlvProvenance.initMs, c.dlvProvenance.queryMs, c.dlvProvenance.parseMs, c.dlvProvenance.latencyMs, c.dlvProvenance.exitCode);

        if (c.secondaryAvailable) {
            wprintf(L"           Collector Consensus  :\n");
            wprintf(L"               %-12ls : %-14ls [WMI: %ls | SLMGR: %ls]\n",
                    L"Status", Core::CollectorConsensus::collectorStateToString(c.wmiData.status.state),
                    c.wmiData.status.normalized.c_str(), c.dlvData.status.normalized.c_str());
            wprintf(L"               %-12ls : %-14ls [WMI: %ls | SLMGR: %ls]\n",
                    L"Edition", Core::CollectorConsensus::collectorStateToString(c.wmiData.edition.state),
                    c.wmiData.edition.normalized.c_str(), c.dlvData.edition.normalized.c_str());
            wprintf(L"               %-12ls : %-14ls [WMI: %ls | SLMGR: %ls]\n",
                    L"Channel", Core::CollectorConsensus::collectorStateToString(c.wmiData.channel.state),
                    c.wmiData.channel.normalized.c_str(), c.dlvData.channel.normalized.c_str());
            wprintf(L"               %-12ls : %-14ls [WMI: %ls | SLMGR: %ls]\n",
                    L"Partial Key", Core::CollectorConsensus::collectorStateToString(c.wmiData.partialKey.state),
                    c.wmiData.partialKey.normalized.c_str(), c.dlvData.partialKey.normalized.c_str());
            wprintf(L"               %-12ls : %-14ls [WMI: %ls | SLMGR: %ls]\n",
                    L"KMS Machine", Core::CollectorConsensus::collectorStateToString(c.wmiData.kmsMachine.state),
                    c.wmiData.kmsMachine.normalized.c_str(), c.dlvData.kmsMachine.normalized.c_str());
        }
        resetColor();
    }

    resetColor();
}

void printFinalSummary(const std::vector<FindingResult>& findings,
                       const std::wstring& scanTime,
                       const std::wstring& hostname)
{
    auto summary = ScanSummary::compute(findings);

    wprintf(L"\n");
    printDivider(L'=');
    setColor(COLOR_WHITE);
    wprintf(L"  SCAN COMPLETE - %ls  |  Host: %ls\n",
            scanTime.c_str(), hostname.c_str());
    resetColor();
    printDivider(L'=');

    wprintf(L"\n  %-20ls  %ls\n", L"Total Checks:", std::to_wstring(summary.total).c_str());

    setColor(COLOR_GREEN);
    wprintf(L"  %-20ls  %ls\n", L"Clean:", std::to_wstring(summary.clean).c_str());
    resetColor();

    setColor(COLOR_YELLOW);
    wprintf(L"  %-20ls  %ls\n", L"Warnings:", std::to_wstring(summary.warning).c_str());
    resetColor();

    setColor(COLOR_RED);
    wprintf(L"  %-20ls  %ls\n", L"Tampering:", std::to_wstring(summary.tampering).c_str());
    resetColor();

    setColor(COLOR_GRAY);
    wprintf(L"  %-20ls  %ls\n", L"Unavailable:", std::to_wstring(summary.unavailable).c_str());
    resetColor();

    setColor(COLOR_CYAN);
    wprintf(L"  %-20ls  %ls\n", L"Information:", std::to_wstring(summary.information).c_str());
    resetColor();

    wprintf(L"\n");
    printDivider(L'-');

    wprintf(L"  %-25ls: ", L"LAYER 1 COLLECTORS");
    int verCount = 0, strongCount = 0, modCount = 0;
    for (const auto& f : findings) {
        if (f.verificationStatus != VerificationStatus::ACCESS_DENIED && f.verificationStatus != VerificationStatus::ERROR_OCCURRED && f.verificationStatus != VerificationStatus::NOT_APPLICABLE && f.verificationStatus != VerificationStatus::UNSUPPORTED) {
            if (f.reliability == EvidenceReliability::VERIFIED) verCount++;
            else if (f.reliability == EvidenceReliability::STRONG) strongCount++;
            else modCount++;
        }
    }
    wprintf(L"Registry/WMI/COM: VERIFIED (%d) | Network/Hosts: STRONG (%d) | Files/Tasks: MODERATE (%d)\n", verCount, strongCount, modCount);
    wprintf(L"  %-25ls: FOUND: %d | NOT_FOUND: %d | NOT_APPLICABLE: %d | ACCESS_DENIED: %d | ERROR: %d\n",
            L"Collector Breakdown", summary.foundCount, summary.notFoundCount, summary.notApplicableCount, summary.accessDeniedCount, summary.errorCount);

    if (summary.accessDeniedCount > 0 || summary.errorCount > 0) {
        setColor(COLOR_RED);
        wprintf(L"  %-25ls: [ WARNING ] - %d Access Denied, %d Errors encountered during collection\n", L"Collector Status", summary.accessDeniedCount, summary.errorCount);
        resetColor();
    } else {
        setColor(COLOR_GREEN);
        wprintf(L"  %-25ls: [ OK / 100%% SUCCESS ] - All applicable collectors completed cleanly without errors\n", L"Collector Status");
        resetColor();
    }

    EvidenceGraph graph = EvidenceGraphBuilder::build(findings);
    printDivider(L'-');
    wprintf(L"  %-25ls: Graph Nodes: %d | Graph Edges: %d | Confirmed Nodes: %d\n",
            L"LAYER 4 EVIDENCE GRAPH", (int)graph.nodes.size(), (int)graph.edges.size(), graph.uniqueSourceCount);
    wprintf(L"  %-25ls: ", L"Relationship Status");
    if (graph.confirmedEdgeCount == 0 && !graph.hasActiveTampering) {
        setColor(COLOR_GREEN);
        wprintf(L"No corroborating relationships established (Clean Graph)\n");
        resetColor();
    } else {
        setColor(COLOR_YELLOW);
        wprintf(L"%d corroborating relationship(s) established across %d independent source(s)\n", graph.confirmedEdgeCount, graph.uniqueSourceCount);
        resetColor();
        for (const auto& node : graph.nodes) {
            for (const auto* edge : node.outgoingEdges) {
                std::wstring relStr = L"USES";
                if (edge->relation == EdgeRelation::SUPPORTS) relStr = L"SUPPORTS";
                else if (edge->relation == EdgeRelation::CONTRADICTS) relStr = L"CONTRADICTS";
                else if (edge->relation == EdgeRelation::TRIGGERS) relStr = L"TRIGGERS";
                else if (edge->relation == EdgeRelation::CORROBORATES) relStr = L"CORROBORATES";
                wprintf(L"    * [%ls] --(%ls)--> [%ls] : %ls\n", edge->sourceId.c_str(), relStr.c_str(), edge->targetId.c_str(), edge->detail.c_str());
            }
        }
    }

    printDivider(L'-');

    wprintf(L"  %-25ls: [ %d pts ] -> ", L"EVIDENCE SCORE (Risk)", summary.evidenceScore);
    setColor(summary.evidenceScore >= 40 ? COLOR_RED : (summary.evidenceScore >= 15 ? COLOR_YELLOW : COLOR_GREEN));
    wprintf(L"%ls\n", summary.evidenceScore >= 40 ? L"HIGH RISK (Active Tampering)" : (summary.evidenceScore >= 15 ? L"MODERATE RISK (Suspicious)" : L"LOW RISK (0 Tampering Artifacts)"));
    resetColor();
    wprintf(L"  %-25ls  (Breakdown: Forensic Tampering: %d | License Warnings: %d)\n", L"", summary.forensicTampering, summary.licenseAttention);

    WORD scoreColor = COLOR_GREEN;
    if (summary.trustScore < 40)      scoreColor = COLOR_RED;
    else if (summary.trustScore < 90) scoreColor = COLOR_YELLOW;

    wprintf(L"  %-25ls: ", L"TRUST SCORE (Integrity)");
    setColor(scoreColor);
    wprintf(L"[ %d / 100 ] -> %ls\n", summary.trustScore, summary.trustLevel.c_str());
    resetColor();

    wprintf(L"  %-25ls: ", L"Integrity Gauge");
    setColor(scoreColor);
    wprintf(L"%ls\n", summary.trustGauge.c_str());
    resetColor();

    Verdict v = Verdict::compute(summary, findings);

    wprintf(L"  %-25ls: ", L"CERTAINTY INDEX");
    setColor(COLOR_CYAN);
    wprintf(L"%ls\n", v.confidenceString.c_str());
    resetColor();

    wprintf(L"  %-25ls: ", L"RISK RANKING");
    setColor(v.level == VerdictLevel::EVIDENCE_OF_TAMPERING ? COLOR_RED : (v.level == VerdictLevel::CLEAN ? COLOR_GREEN : COLOR_YELLOW));
    wprintf(L"%ls\n", v.riskRanking.c_str());
    resetColor();

    printDivider(L'-');

    WORD verdictColor = COLOR_GREEN;
    if (v.level == VerdictLevel::EVIDENCE_OF_TAMPERING) verdictColor = COLOR_RED;
    else if (v.level == VerdictLevel::SUSPICIOUS_CONFIG || v.level == VerdictLevel::LICENSE_ATTENTION) verdictColor = COLOR_YELLOW;

    setColor(verdictColor);
    wprintf(L"  VERDICT: %ls\n", v.title.c_str());
    wprintf(L"           %ls\n", v.description.c_str());
    resetColor();

    if (!v.reasons.empty()) {
        printDivider(L'-');
        setColor(COLOR_YELLOW);
        wprintf(L"  REASONS FOR VERDICT (ATTRIBUTE-BASED INFERENCE):\n");
        resetColor();
        for (const auto& r : v.reasons) {
            wprintf(L"    * %ls\n", r.c_str());
        }
    }

    if (!v.recommendations.empty()) {
        printDivider(L'-');
        setColor(COLOR_GREEN);
        wprintf(L"  RECOMMENDATIONS / REMEDIATION ACTIONS:\n");
        resetColor();
        for (const auto& rec : v.recommendations) {
            wprintf(L"    -> %ls\n", rec.c_str());
        }
    }

    printDivider(L'=');
    wprintf(L"\n");
    fflush(stdout);
}

} // namespace LicenseInspector::UI
