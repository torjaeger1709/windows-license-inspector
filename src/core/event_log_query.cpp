#include "event_log_query.h"
#include <windows.h>
#include <chrono>
#include <vector>

namespace LicenseInspector {
namespace Core {

    CollectorResult<std::vector<SppLogEvent>> EventLogQuery::querySppEvents(int maxRecords) {
        auto startTime = std::chrono::high_resolution_clock::now();
        std::wstring collectorName = L"EventLogCollector";
        std::vector<SppLogEvent> events;

        HANDLE hLog = OpenEventLogW(nullptr, L"Application");
        if (!hLog) {
            DWORD err = GetLastError();
            auto endTime = std::chrono::high_resolution_clock::now();
            double ms = std::chrono::duration<double, std::milli>(endTime - startTime).count();
            if (err == ERROR_ACCESS_DENIED) {
                return CollectorResult<std::vector<SppLogEvent>>::accessDenied(EvidenceReliability::MODERATE, collectorName, L"OpenEventLogW Application Access Denied");
            }
            return CollectorResult<std::vector<SppLogEvent>>::notFound(EvidenceReliability::MODERATE, collectorName, ms);
        }

        const DWORD BUFFER_SIZE = 65536;
        std::vector<BYTE> buffer(BUFFER_SIZE);
        DWORD bytesRead = 0, minBytesNeeded = 0;
        int scannedCount = 0;

        while (scannedCount < maxRecords * 5 && events.size() < static_cast<size_t>(maxRecords)) {
            if (!ReadEventLogW(hLog, EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ, 0,
                               buffer.data(), BUFFER_SIZE, &bytesRead, &minBytesNeeded))
            {
                DWORD err = GetLastError();
                if (err == ERROR_INSUFFICIENT_BUFFER) continue;
                break;
            }

            LPBYTE pRecord = buffer.data();
            LPBYTE pEnd = buffer.data() + bytesRead;

            while (pRecord < pEnd && events.size() < static_cast<size_t>(maxRecords)) {
                scannedCount++;
                PEVENTLOGRECORD pEvt = reinterpret_cast<PEVENTLOGRECORD>(pRecord);
                LPCWSTR pSourceName = reinterpret_cast<LPCWSTR>(pRecord + sizeof(EVENTLOGRECORD));

                std::wstring srcName = pSourceName ? pSourceName : L"";
                if (srcName == L"Microsoft-Windows-Security-SPP" ||
                    srcName == L"Software Licensing Service" ||
                    srcName == L"Security-SPP")
                {
                    SppLogEvent evt;
                    evt.eventId = (pEvt->EventID & 0xFFFF); // Low 16 bits
                    evt.sourceName = srcName;
                    
                    FILETIME ft;
                    LONGLONG ll = Int32x32To64(pEvt->TimeGenerated, 10000000) + 116444736000000000LL;
                    ft.dwLowDateTime = (DWORD)ll;
                    ft.dwHighDateTime = (DWORD)(ll >> 32);
                    SYSTEMTIME st;
                    if (FileTimeToSystemTime(&ft, &st)) {
                        wchar_t timeBuf[64];
                        wsprintfW(timeBuf, L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
                        evt.timeGenerated = timeBuf;
                    } else {
                        evt.timeGenerated = L"Unknown Time";
                    }

                    if (pEvt->NumStrings > 0) {
                        LPCWSTR pStr = reinterpret_cast<LPCWSTR>(pRecord + pEvt->StringOffset);
                        evt.messageSummary = pStr;
                    } else {
                        evt.messageSummary = L"Event ID: " + std::to_wstring(evt.eventId);
                    }

                    events.push_back(std::move(evt));
                }
                pRecord += pEvt->Length;
            }
        }

        CloseEventLog(hLog);

        auto endTime = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        if (events.empty()) {
            return CollectorResult<std::vector<SppLogEvent>>::notFound(EvidenceReliability::MODERATE, collectorName, ms);
        }
        return CollectorResult<std::vector<SppLogEvent>>::success(std::move(events), EvidenceReliability::MODERATE, collectorName, ms);
    }

} // namespace Core
} // namespace LicenseInspector
