#pragma once

#include "common/types.h"
#include "core/wmi_query.h"
#include <vector>

namespace LicenseInspector::ModuleA {

/// A1: Check Rogue KMS Server (Loopback/Crack domain + GVLK channel -> HIGH impact/quality; private LAN -> MEDIUM)
FindingResult checkKmsRogueServer(WMI::WmiClient& wmi);

/// A2: Scan PowerShell history for unauthorized activation scripts (irm massgrave, iex, KMSAuto) with soft decay
FindingResult checkPowerShellHistory();

/// A3: Query WMI for KMS38 active hook (EvaluationEndDate near year 2038 + GVLK + Status 1)
FindingResult checkKms38Hook(WMI::WmiClient& wmi);

/// A4: Query WMI for official license state (Licensed, Grace, Notification) and channel (Retail, OEM, Volume)
FindingResult checkLicenseStateChannel(WMI::WmiClient& wmi);

/// A5: Check for known crack tool directories on disk (C:\KMSAuto, KMSpico, etc.) with soft decay
std::vector<FindingResult> checkCrackDirectories();

/// A6: Enumerate Scheduled Tasks (including hidden activators AutoKMS, MAS_AAct)
std::vector<FindingResult> checkHiddenScheduledTasks();

/// A7: Check registry licensing policies (NoGenTicket = 1, SkipRearm = 1)
std::vector<FindingResult> checkTelemetryRegistryPolicy();

/// A8: Query Software Protection Service (sppsvc) startup configuration (Disabled -> MEDIUM impact)
FindingResult checkSoftwareProtectionService();

/// A9: Query known KMS emulator Windows Services (AutoKMS, KMSELDI running/auto -> HIGH impact/quality)
std::vector<FindingResult> checkKmsWindowsServices();

/// A10: Scan hosts file for domain redirections (e.g. sls.microsoft.com -> 0.0.0.0/127.0.0.1)
FindingResult checkHostsFileTampering();

/// A11: Check Licensing Store Consistency (Extremely Conservative heuristic, marked SUSPECTED)
FindingResult checkLicensingStoreConsistency(WMI::WmiClient& wmi);

/// A12: Query recent Software Protection Event Logs up to eventLimit (marked INFO)
std::vector<FindingResult> checkSoftwareProtectionEventLog(int eventLimit = DEFAULT_EVENT_LIMIT);

/// A13: Check SPP COM Integrity using GetSystemDirectoryW() resolution (CLSID SppExtComObj DLL hijack)
std::vector<FindingResult> checkSppComIntegrity();

/// A14: Check Firmware License Consistency (Cross-validation between ACPI MSDM/OA3 BIOS OEM key and active OS license)
FindingResult checkFirmwareLicenseConsistency(WMI::WmiClient& wmi);

/// Run all 14 Module A checks and return a combined vector of findings.
std::vector<FindingResult> runAll(WMI::WmiClient& wmi, int eventLimit = DEFAULT_EVENT_LIMIT);

} // namespace LicenseInspector::ModuleA
