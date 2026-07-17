#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "common/types.h"
#include <string>
#include <vector>

namespace LicenseInspector::UI {

inline constexpr WORD COLOR_DEFAULT = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
inline constexpr WORD COLOR_GREEN   = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
inline constexpr WORD COLOR_RED     = FOREGROUND_RED   | FOREGROUND_INTENSITY;
inline constexpr WORD COLOR_YELLOW  = FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
inline constexpr WORD COLOR_CYAN    = FOREGROUND_GREEN | FOREGROUND_BLUE  | FOREGROUND_INTENSITY;
inline constexpr WORD COLOR_MAGENTA = FOREGROUND_RED   | FOREGROUND_BLUE  | FOREGROUND_INTENSITY;
inline constexpr WORD COLOR_WHITE   = FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
inline constexpr WORD COLOR_GRAY    = FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_BLUE;


void setColor(WORD color);

void resetColor();

void printColored(const std::wstring& text, WORD color);

void printBanner();

void printSectionHeader(const std::wstring& title, WORD color = COLOR_CYAN);

void printDivider(wchar_t ch = L'-', int width = 80);

void printSystemInfo(const SystemInfo& info);

void printResult(const FindingResult& result);

void printFinalSummary(const std::vector<FindingResult>& findings,
                       const std::wstring& scanTime,
                       const std::wstring& hostname);

} // namespace LicenseInspector::UI
