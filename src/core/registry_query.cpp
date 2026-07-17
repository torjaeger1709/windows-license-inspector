#include "core/registry_query.h"

#include <vector>

namespace LicenseInspector::Registry {
std::optional<std::wstring> readString(HKEY               root,
                                       const std::wstring& subKey,
                                       const std::wstring& valueName)
{
    HKEY hKey = nullptr;
    // KEY_READ = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | STANDARD_RIGHTS_READ
    LONG result = RegOpenKeyExW(root,
                                subKey.c_str(),
                                0,              // ulOptions (reserved, must be 0)
                                KEY_READ,
                                &hKey);
    if (result != ERROR_SUCCESS || hKey == nullptr)
        return std::nullopt;

    // First call: query the required buffer size (lpData = nullptr)
    DWORD type   = 0;
    DWORD cbData = 0;
    result = RegQueryValueExW(hKey, valueName.c_str(),
                              nullptr,   // lpReserved
                              &type,
                              nullptr,   // lpData — null to get size
                              &cbData);

    if (result != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ) ||
        cbData == 0)
    {
        RegCloseKey(hKey);
        return std::nullopt;
    }

    // Second call: read the actual data
    // cbData includes the null terminator (in bytes); allocate accordingly
    std::wstring value(cbData / sizeof(wchar_t), L'\0');
    result = RegQueryValueExW(hKey, valueName.c_str(),
                              nullptr, &type,
                              reinterpret_cast<LPBYTE>(value.data()),
                              &cbData);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS)
        return std::nullopt;

    while (!value.empty() && value.back() == L'\0')
        value.pop_back();

    return value;
}


std::optional<DWORD> readDWord(HKEY               root,
                               const std::wstring& subKey,
                               const std::wstring& valueName)
{
    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS || hKey == nullptr)
        return std::nullopt;

    DWORD type   = 0;
    DWORD value  = 0;
    DWORD cbData = sizeof(DWORD);
    result = RegQueryValueExW(hKey, valueName.c_str(),
                              nullptr, &type,
                              reinterpret_cast<LPBYTE>(&value),
                              &cbData);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS || type != REG_DWORD)
        return std::nullopt;

    return value;
}


std::vector<std::wstring> enumSubKeys(HKEY               root,
                                      const std::wstring& subKey)
{
    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS || hKey == nullptr)
        return {};

    std::vector<std::wstring> keys;
    wchar_t   name[256];
    DWORD     nameLen = 256;
    DWORD     index   = 0;

    while (RegEnumKeyExW(hKey, index, name, &nameLen,
                         nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
    {
        keys.emplace_back(name, nameLen);
        nameLen = 256;  // reset for next iteration
        ++index;
    }

    RegCloseKey(hKey);
    return keys;
}


bool keyExists(HKEY root, const std::wstring& subKey) {
    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS && hKey != nullptr) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

} // namespace LicenseInspector::Registry
