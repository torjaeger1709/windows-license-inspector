#include "sys_path.h"
#include <windows.h>
#include <algorithm>
#include <vector>

namespace LicenseInspector {
namespace Core {

    std::wstring SysPath::getSystemDir() {
        wchar_t buf[MAX_PATH];
        UINT len = GetSystemDirectoryW(buf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) {
            return std::wstring(buf, len);
        }
        return L"C:\\Windows\\System32"; 
    }

    std::wstring SysPath::getWindowsDir() {
        wchar_t buf[MAX_PATH];
        UINT len = GetWindowsDirectoryW(buf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) {
            return std::wstring(buf, len);
        }
        return L"C:\\Windows"; 
    }

    int SysPath::getFileAgeDays(const std::wstring& absolutePath) {
        WIN32_FILE_ATTRIBUTE_DATA attrData;
        if (!GetFileAttributesExW(absolutePath.c_str(), GetFileExInfoStandard, &attrData)) {
            return -1;
        }

        FILETIME nowFt;
        GetSystemTimeAsFileTime(&nowFt);

        ULARGE_INTEGER nowUli, fileUli;
        nowUli.LowPart  = nowFt.dwLowDateTime;
        nowUli.HighPart = nowFt.dwHighDateTime;

        fileUli.LowPart  = attrData.ftLastWriteTime.dwLowDateTime;
        fileUli.HighPart = attrData.ftLastWriteTime.dwHighDateTime;

        if (fileUli.QuadPart == 0) {
            fileUli.LowPart  = attrData.ftCreationTime.dwLowDateTime;
            fileUli.HighPart = attrData.ftCreationTime.dwHighDateTime;
        }

        if (nowUli.QuadPart <= fileUli.QuadPart || fileUli.QuadPart == 0) {
            return 0; 
        }

        ULONGLONG diffTicks = nowUli.QuadPart - fileUli.QuadPart;
        ULONGLONG ticksPerDay = 864000000000ULL;
        return static_cast<int>(diffTicks / ticksPerDay);
    }

    bool SysPath::isInsideSystem32(const std::wstring& absolutePath) {
        if (absolutePath.empty()) return false;
        std::wstring sysDir = getSystemDir();
        std::wstring pathLower = absolutePath;
        std::wstring sysLower  = sysDir;

        std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);
        std::transform(sysLower.begin(), sysLower.end(), sysLower.begin(), ::towlower);

        if (sysLower.back() != L'\\') sysLower += L'\\';
        return pathLower.rfind(sysLower, 0) == 0;
    }

} // namespace Core
} // namespace LicenseInspector
