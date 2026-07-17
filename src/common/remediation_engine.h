#pragma once
#include <string>
#include <vector>

namespace LicenseInspector {

// Forward declarations to break circular header dependency
struct FindingResult;
struct Verdict;
enum class VerdictLevel;

namespace Remediation {

    struct RemediationEntry {
        const wchar_t* id;
        const wchar_t* actionTemplate;
    };

    constexpr RemediationEntry REMEDIATION_TABLE[] = {
        { L"A1",  L"[Remediation A1] Clear KeyManagementServiceServer registry value using 'slmgr /ckms' and verify official volume KMS domain" },
        { L"A2",  L"[Remediation A2] Review PowerShell history for activation scripts (irm/iex) and ensure no unauthorized tasks remain" },
        { L"A3",  L"[Remediation A3] Remove KMS38 hook, reset EvaluationEndDate, and reinstall legitimate Windows product key ('slmgr /ipk')" },
        { L"A5",  L"[Remediation A5] Quarantine and delete unauthorized crack tool directory: {value}" },
        { L"A6",  L"[Remediation A6] Delete suspicious hidden Scheduled Task: {value}" },
        { L"A7",  L"[Remediation A7] Reset NoGenTicket and SkipRearm registry policies under Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Software Protection Platform to 0" },
        { L"A8",  L"[Remediation A8] Re-enable and restore default Automatic/Demand startup permissions for Software Protection Service (sppsvc)" },
        { L"A9",  L"[Remediation A9] Stop, disable, and remove unauthorized KMS Windows Service: {value}" },
        { L"A10", L"[Remediation A10] Remove unauthorized domain redirections (e.g. sls.microsoft.com) from C:\\Windows\\System32\\drivers\\etc\\hosts" },
        { L"A11", L"[Remediation A11] Re-evaluate WMI SoftwareLicensingProduct consistency using 'slmgr /dlv' and repair SPP repository if corrupted" },
        { L"A13", L"[Remediation A13] Restore original InProcServer32 COM registration and system DLL path for CLSID {106E1BBE-D714-436C-ACEE-DCE60CD5743D}" },
        { L"A14", L"[Remediation A14] Firmware/OS licensing mismatch detected ({value}). If hardware originally shipped with Home/OEM, verify legitimate upgrade path or remove unauthorized KMS/GVLK activation." }
    };

    class StringFormatter {
    public:
        static std::wstring safeFormat(const std::wstring& tpl, const std::wstring& val) {
            std::wstring res = tpl;
            const std::wstring token = L"{value}";
            size_t pos = res.find(token);
            while (pos != std::wstring::npos) {
                res.replace(pos, token.length(), val.empty() ? L"(N/A)" : val);
                pos = res.find(token, pos + (val.empty() ? 5 : val.length()));
            }
            return res;
        }
    };

    class RemediationEngine {
    public:
        static std::vector<std::wstring> computeRemediations(const std::vector<FindingResult>& findings, const Verdict& verdict);
    };

} // namespace Remediation
} // namespace LicenseInspector
