#pragma once
#include <string>

namespace LicenseInspector {
namespace Core {

    class SysPath {
    public:
        static std::wstring getSystemDir();
        static std::wstring getWindowsDir();
        static int getFileAgeDays(const std::wstring& absolutePath);
        static bool isInsideSystem32(const std::wstring& absolutePath);
    };

} // namespace Core
} // namespace LicenseInspector
