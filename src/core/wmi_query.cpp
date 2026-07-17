#include "core/wmi_query.h"
#include "common/utils.h"
#include <combaseapi.h>   
#include <oleauto.h>      
#include <stdexcept>
#include <sstream>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace LicenseInspector::WMI {

WmiClient::WmiClient(const std::wstring& namespacePath) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        throw std::runtime_error("CoInitializeEx failed: COM cannot be initialized.");
    }
    comInitialized_ = (hr == S_OK);  
    hr = CoInitializeSecurity(
        nullptr,                         
        -1,                              
        nullptr,                         
        nullptr,                        
        RPC_C_AUTHN_LEVEL_DEFAULT,       
        RPC_C_IMP_LEVEL_IMPERSONATE,    
        nullptr,                         
        EOAC_NONE,                      
        nullptr                         
    );
    if (FAILED(hr) && hr != static_cast<HRESULT>(0x80010119L)) {
    }

    hr = CoCreateInstance(
        CLSID_WbemLocator,
        nullptr,
        CLSCTX_INPROC_SERVER,  
        IID_IWbemLocator,
        reinterpret_cast<void**>(&pLocator_)
    );
    if (FAILED(hr) || !pLocator_) {
        throw std::runtime_error("CoCreateInstance(IWbemLocator) failed.");
    }

    hr = pLocator_->ConnectServer(
        _bstr_t(namespacePath.c_str()),  
        nullptr,                          
        nullptr,                          
        nullptr,                          
        0,                               
        nullptr,                          
        nullptr,                          
        &pServices_                       
    );
    if (FAILED(hr) || !pServices_) {
        pServices_ = nullptr;
        return;
    }

    CoSetProxyBlanket(
        pServices_,                     
        RPC_C_AUTHN_WINNT,               
        RPC_C_AUTHZ_NONE,                
        nullptr,                          
        RPC_C_AUTHN_LEVEL_CALL,          
        RPC_C_IMP_LEVEL_IMPERSONATE,     
        nullptr,                          
        EOAC_NONE                         
    );
}


WmiClient::~WmiClient() {
    if (pServices_) { pServices_->Release(); pServices_ = nullptr; }
    if (pLocator_)  { pLocator_->Release();  pLocator_  = nullptr; }

    if (comInitialized_) {
        CoUninitialize();
        comInitialized_ = false;
    }
}


std::wstring WmiClient::variantToWString(const VARIANT& vt) {
    switch (vt.vt) {
        case VT_BSTR:
            return vt.bstrVal ? std::wstring(vt.bstrVal) : L"";

        case VT_I4:   return std::to_wstring(vt.lVal);
        case VT_UI4:  return std::to_wstring(vt.uintVal);
        case VT_I2:   return std::to_wstring(vt.iVal);
        case VT_UI2:  return std::to_wstring(vt.uiVal);
        case VT_I8:   return std::to_wstring(vt.llVal);
        case VT_UI8:  return std::to_wstring(vt.ullVal);
        case VT_BOOL: return (vt.boolVal != VARIANT_FALSE) ? L"true" : L"false";
        case VT_R4:   return std::to_wstring(vt.fltVal);
        case VT_R8:   return std::to_wstring(vt.dblVal);

        case VT_NULL:
        case VT_EMPTY:
        default:
            return L"";
    }
}


std::vector<Row> WmiClient::query(const std::wstring& wql) const {
    std::vector<Row> results;

    if (!isConnected()) return results;   

    IEnumWbemClassObject* pEnum = nullptr;

    HRESULT hr = pServices_->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(wql.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnum
    );

    if (FAILED(hr) || !pEnum) return results; 

    IWbemClassObject* pObj  = nullptr;
    ULONG             uRet  = 0;

    while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet) == S_OK) {
        Row row;

        SAFEARRAY* pNames = nullptr;
        pObj->GetNames(nullptr, WBEM_FLAG_ALWAYS, nullptr, &pNames);

        if (pNames) {
            LONG lLower = 0, lUpper = 0;
            SafeArrayGetLBound(pNames, 1, &lLower);
            SafeArrayGetUBound(pNames, 1, &lUpper);

            for (LONG i = lLower; i <= lUpper; ++i) {
                BSTR propName = nullptr;
                SafeArrayGetElement(pNames, &i, &propName);
                if (!propName) continue;

                std::wstring key(propName);
                SysFreeString(propName);

                VARIANT vt;
                VariantInit(&vt);
                HRESULT hrGet = pObj->Get(key.c_str(), 0, &vt, nullptr, nullptr);
                if (SUCCEEDED(hrGet)) {
                    row[key] = variantToWString(vt);
                }
                VariantClear(&vt);
            }

            SafeArrayDestroy(pNames);
        }

        results.push_back(std::move(row));
        pObj->Release();
    }

    pEnum->Release();
    return results;
}

} // namespace LicenseInspector::WMI
