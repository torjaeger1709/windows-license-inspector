#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <optional>
#include <string>
#include <vector>

namespace LicenseInspector::Registry {

std::optional<std::wstring> readString(HKEY   root,
                                       const std::wstring& subKey,
                                       const std::wstring& valueName);

std::optional<DWORD> readDWord(HKEY   root,
                               const std::wstring& subKey,
                               const std::wstring& valueName);

std::vector<std::wstring> enumSubKeys(HKEY   root,
                                      const std::wstring& subKey);

bool keyExists(HKEY root, const std::wstring& subKey);

} // namespace LicenseInspector::Registry
