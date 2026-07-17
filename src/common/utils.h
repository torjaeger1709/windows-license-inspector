#pragma once

#include <string>
#include <vector>
#include <optional>
#include "common/types.h"

namespace LicenseInspector::WMI { class WmiClient; }

namespace LicenseInspector::Utils {

std::string  wstrToStr(const std::wstring& wstr);

std::wstring strToWstr(const std::string&  str);

std::wstring expandEnvVars(const std::wstring& pathTemplate);

bool pathExists(const std::wstring& path);

std::wstring getHostname();

std::wstring getCurrentTimestamp();

std::wstring getCurrentTimestampISO();

std::optional<std::wstring> readFileAsWString(const std::wstring& path);

bool containsIgnoreCase(const std::wstring& haystack, const std::wstring& needle);

std::vector<std::wstring> splitString(const std::wstring& str, wchar_t delim);

std::wstring trim(const std::wstring& str);

bool strEndsWith(const std::wstring& str, const std::wstring& suffix);

bool strStartsWith(const std::wstring& str, const std::wstring& prefix);

// Returns true if the given string is a loopback (127.x.x.x), unspecified
// (0.0.0.0), or RFC-1918 private address (10.x, 172.16-31.x, 192.168.x).
// These are the typical values used by rogue local KMS servers.
bool isPrivateOrLoopbackIP(const std::wstring& ip);

// Returns true if the given domain/hostname looks like a known crack-related
// KMS activation server domain (e.g. kms.digiboy.ir, kms8.msguides.com).
bool isSuspiciousKmsHost(const std::wstring& host);

// Query baseline operating system, build, user, BIOS model, Office version, OEM Key, and Current Windows Key.
SystemInfo querySystemInfo(LicenseInspector::WMI::WmiClient* wmi = nullptr);

} // namespace LicenseInspector::Utils
