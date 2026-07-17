#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <wbemcli.h>      
#include <comdef.h>       

#include <map>
#include <string>
#include <vector>

namespace LicenseInspector::WMI {

using Row = std::map<std::wstring, std::wstring>;

class WmiClient {
public:
    /// Initialize COM subsystem and connect to the given WMI namespace.
    /// @param namespacePath  
    /// @throws std::runtime_error on fatal COM/WMI init failure.
    explicit WmiClient(const std::wstring& namespacePath);
    ~WmiClient();

    WmiClient(const WmiClient&)            = delete;
    WmiClient& operator=(const WmiClient&) = delete;

    /// @param wql  WQL query string, e.g. "SELECT Name FROM SoftwareLicensingProduct"
    std::vector<Row> query(const std::wstring& wql) const;

    bool isConnected() const { return pServices_ != nullptr; }

private:
    IWbemLocator*  pLocator_  = nullptr;
    IWbemServices* pServices_ = nullptr;
    bool           comInitialized_ = false;

    static std::wstring variantToWString(const VARIANT& vt);
};

} // namespace LicenseInspector::WMI
