// ─────────────────────────────────────────────────────────────────────────────
// utils.cpp  —  Utility / Helper Function Implementations
// ─────────────────────────────────────────────────────────────────────────────
// Windows Internals Notes:
//
//  WideCharToMultiByte / MultiByteToWideChar
//    The Win32 API family uses UTF-16LE (wchar_t) strings internally.
//    Console code pages (CP_UTF8 = 65001) handle conversion at I/O boundaries.
//
//  ExpandEnvironmentStringsW
//    Resolves tokens like %APPDATA% using the process's environment block.
//    The environment block is inherited from the parent process (usually Explorer
//    or cmd.exe) and includes per-user variables from the registry:
//      HKCU\Environment  and  HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
//
//  GetFileAttributesW
//    Returns INVALID_FILE_ATTRIBUTES if the path does not exist or is
//    inaccessible.  PathFileExistsW (shlwapi.h) is a thin wrapper around this.
// ─────────────────────────────────────────────────────────────────────────────

#include "common/utils.h"
#include "core/registry_query.h"
#include "core/wmi_query.h"
#include "common/license_parser.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>

namespace LicenseInspector::Utils {


std::string wstrToStr(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    // CP_UTF8 ensures correct handling of non-ASCII characters (Vietnamese, etc.)
    int size = WideCharToMultiByte(CP_UTF8, 0,
                                   wstr.data(), static_cast<int>(wstr.size()),
                                   nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0,
                        wstr.data(), static_cast<int>(wstr.size()),
                        result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring strToWstr(const std::string& str) {
    if (str.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, 0,
                                   str.data(), static_cast<int>(str.size()),
                                   nullptr, 0);
    if (size <= 0) return {};
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0,
                        str.data(), static_cast<int>(str.size()),
                        result.data(), size);
    return result;
}


std::wstring expandEnvVars(const std::wstring& pathTemplate) {
    // First call: get required buffer size (includes null terminator)
    DWORD size = ExpandEnvironmentStringsW(pathTemplate.c_str(), nullptr, 0);
    if (size == 0) return pathTemplate;

    std::wstring result(size, L'\0');
    DWORD written = ExpandEnvironmentStringsW(pathTemplate.c_str(),
                                              result.data(),
                                              static_cast<DWORD>(result.size()));
    // written includes the null terminator; resize to remove it
    if (written > 0 && written <= size)
        result.resize(written - 1);
    return result;
}

bool pathExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES);
}

std::wstring getHostname() {
    wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(buf, &size))
        return std::wstring(buf, size);
    return L"UNKNOWN";
}


static SYSTEMTIME getLocalTime() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    return st;
}

std::wstring getCurrentTimestamp() {
    SYSTEMTIME st = getLocalTime();
    wchar_t buf[32];
    swprintf_s(buf, L"%04d%02d%02d_%02d%02d%02d",
               st.wYear, st.wMonth, st.wDay,
               st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::wstring getCurrentTimestampISO() {
    SYSTEMTIME st = getLocalTime();
    wchar_t buf[32];
    swprintf_s(buf, L"%04d-%02d-%02dT%02d:%02d:%02d",
               st.wYear, st.wMonth, st.wDay,
               st.wHour, st.wMinute, st.wSecond);
    return buf;
}


std::optional<std::wstring> readFileAsWString(const std::wstring& path) {
    // Open as binary so we can handle both UTF-8 and UTF-16 files.
    // PowerShell ConsoleHost_history.txt is typically UTF-16LE on Windows.
    std::ifstream file(std::filesystem::path(path), std::ios::binary | std::ios::ate);
    if (!file.is_open()) return std::nullopt;

    std::streamsize size = file.tellg();
    if (size <= 0) return std::nullopt;
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(static_cast<size_t>(size));
    if (!file.read(buffer.data(), size)) return std::nullopt;

    // Detect UTF-16LE BOM: 0xFF 0xFE
    if (buffer.size() >= 2 &&
        static_cast<unsigned char>(buffer[0]) == 0xFF &&
        static_cast<unsigned char>(buffer[1]) == 0xFE)
    {
        // Skip BOM, interpret as UTF-16LE
        const wchar_t* wdata = reinterpret_cast<const wchar_t*>(buffer.data() + 2);
        size_t wlen = (buffer.size() - 2) / sizeof(wchar_t);
        return std::wstring(wdata, wlen);
    }

    // Assume UTF-8 / ANSI — convert to wide
    return strToWstr(std::string(buffer.begin(), buffer.end()));
}


bool containsIgnoreCase(const std::wstring& haystack, const std::wstring& needle) {
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(),   needle.end(),
        [](wchar_t a, wchar_t b) {
            return std::towlower(a) == std::towlower(b);
        });
    return it != haystack.end();
}

std::vector<std::wstring> splitString(const std::wstring& str, wchar_t delim) {
    std::vector<std::wstring> tokens;
    std::wstringstream ss(str);
    std::wstring token;
    while (std::getline(ss, token, delim))
        tokens.push_back(token);
    return tokens;
}

std::wstring trim(const std::wstring& str) {
    auto isSpace = [](wchar_t c) {
        return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n';
    };
    auto begin = std::find_if_not(str.begin(), str.end(), isSpace);
    auto end   = std::find_if_not(str.rbegin(), str.rend(), isSpace).base();
    return (begin < end) ? std::wstring(begin, end) : L"";
}


bool strEndsWith(const std::wstring& str, const std::wstring& suffix) {
    if (suffix.size() > str.size()) return false;
    return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool strStartsWith(const std::wstring& str, const std::wstring& prefix) {
    if (prefix.size() > str.size()) return false;
    return str.compare(0, prefix.size(), prefix) == 0;
}


bool isPrivateOrLoopbackIP(const std::wstring& ip) {
    // Use std::wregex to classify:
    //   Loopback  : 127.x.x.x
    //   Unspecified: 0.0.0.0
    //   RFC-1918 A : 10.x.x.x
    //   RFC-1918 B : 172.16-31.x.x
    //   RFC-1918 C : 192.168.x.x
    //   localhost  : (literal string)
    static const std::wregex privateRegex(
        LR"(^(127\.\d+\.\d+\.\d+|0\.0\.0\.0|10\.\d+\.\d+\.\d+|)"
        LR"(172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|localhost)$)",
        std::regex_constants::icase
    );
    return std::regex_match(ip, privateRegex);
}

bool isSuspiciousKmsHost(const std::wstring& host) {
    static const std::vector<std::wstring> knownBadHosts = {
        L"kms.digiboy.ir",
        L"kms8.msguides.com",
        L"kms9.msguides.com",
        L"kms.loli.beer",
        L"kms.chinancce.com",
        L"kms.03k.org",
        L"kms.xspace.in",
        L"kms.cangshui.net",
        L"k.msk8.com",
        L"s8.uk.to",
        L"s9.us.to",
    };
    std::wstring lower = host;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    for (const auto& bad : knownBadHosts) {
        if (lower == bad || strEndsWith(lower, L"." + bad))
            return true;
    }
    return false;
}

SystemInfo querySystemInfo(LicenseInspector::WMI::WmiClient* wmi) {
    SystemInfo info;
    info.hostname = getHostname();

    wchar_t userBuf[256];
    DWORD userLen = sizeof(userBuf) / sizeof(wchar_t);
    std::wstring username;
    if (GetUserNameW(userBuf, &userLen)) {
        username = userBuf;
    } else {
        wchar_t envUser[256] = {0};
        GetEnvironmentVariableW(L"USERNAME", envUser, 256);
        username = envUser[0] ? envUser : L"Unknown";
    }
    wchar_t envDomain[256] = {0};
    GetEnvironmentVariableW(L"USERDOMAIN", envDomain, 256);
    std::wstring domain = envDomain;
    if (!domain.empty() && domain != L"Unknown") {
        info.currentUser = domain + L"\\" + username;
    } else {
        info.currentUser = username;
    }

    auto prodName = Registry::readString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName");
    std::wstring osStr = prodName ? trim(*prodName) : L"Microsoft Windows";

    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);
    if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        osStr += L" (64-bit x64)";
    } else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        osStr += L" (64-bit ARM64)";
    } else {
        osStr += L" (32-bit x86)";
    }
    info.osName = osStr;

    auto buildNum = Registry::readString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuildNumber");
    auto ubr      = Registry::readDWord(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR");
    auto dispVer  = Registry::readString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"DisplayVersion");
    if (!dispVer) {
        dispVer = Registry::readString(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ReleaseId");
    }

    std::wstring buildStr = L"Build ";
    if (buildNum) buildStr += trim(*buildNum);
    else          buildStr += L"Unknown";
    if (ubr)      buildStr += L"." + std::to_wstring(*ubr);
    if (dispVer)  buildStr += L" (Version " + trim(*dispVer) + L")";
    info.osBuild = buildStr;

    auto sysVendor = Registry::readString(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer");
    auto sysModel  = Registry::readString(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName");
    std::wstring biosStr;
    if (sysVendor && sysModel) {
        biosStr = trim(*sysVendor) + L" - " + trim(*sysModel);
    } else if (sysModel) {
        biosStr = trim(*sysModel);
    } else {
        biosStr = L"Standard PC / Unknown Hardware";
    }
    info.biosModel = biosStr;

    auto c2rReleaseId = Registry::readString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration", L"ProductReleaseIds");
    auto c2rVer       = Registry::readString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration", L"VersionToReport");
    if (c2rReleaseId && !c2rReleaseId->empty()) {
        info.officeVersion = trim(*c2rReleaseId) + (c2rVer ? (L" (v" + trim(*c2rVer) + L")") : L" (Click-To-Run)");
    } else {
        auto msiPath = Registry::readString(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Office\\16.0\\Common\\InstallRoot", L"Path");
        if (msiPath && !msiPath->empty()) {
            info.officeVersion = L"Microsoft Office 16 (Traditional MSI Install)";
        } else {
            info.officeVersion = L"Not Installed / No ClickToRun Baseline Found";
        }
    }

    if (wmi && wmi->isConnected()) {
        auto oemRows = wmi->query(L"SELECT OA3xOriginalProductKey FROM SoftwareLicensingService");
        if (!oemRows.empty()) {
            auto it = oemRows[0].find(L"OA3xOriginalProductKey");
            if (it != oemRows[0].end() && !it->second.empty()) {
                info.oemKey = LicenseParser::maskKeyLast5(it->second);
            }
        }
        if (info.oemKey.empty()) {
            info.oemKey = L"Not Present / No OA3 Table in BIOS";
        }

        auto prodRows = wmi->query(L"SELECT PartialProductKey, Description, Name, LicenseStatus FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL");
        for (const auto& row : prodRows) {
            std::wstring name, desc, pKey, status;
            if (auto it = row.find(L"Name"); it != row.end()) name = it->second;
            if (auto it = row.find(L"Description"); it != row.end()) desc = it->second;
            if (auto it = row.find(L"PartialProductKey"); it != row.end()) pKey = it->second;
            if (auto it = row.find(L"LicenseStatus"); it != row.end()) status = it->second;

            if ((name.find(L"Windows") != std::wstring::npos || desc.find(L"Windows") != std::wstring::npos) && !pKey.empty()) {
                if (status == L"1" || info.currentOsKey.empty() || info.currentOsKey.find(L"Not Found") != std::wstring::npos) {
                    info.currentOsKey = L"XXXXX-XXXXX-XXXXX-XXXXX-" + pKey;
                }
            }
        }
        if (info.currentOsKey.empty()) {
            info.currentOsKey = L"Not Found / Unactivated";
        }
    } else {
        info.oemKey = L"WMI Not Available";
        info.currentOsKey = L"WMI Not Available";
    }

    return info;
}

} // namespace LicenseInspector::Utils
