#pragma once
#include <string>
#include <vector>
#include <windows.h>
#include "../common/types.h"

namespace LicenseInspector {
namespace Core {

    struct SppLogEvent {
        DWORD        eventId       = 0;
        std::wstring sourceName;
        std::wstring timeGenerated;
        std::wstring messageSummary;
    };

    class EventLogQuery {
    public:
        static CollectorResult<std::vector<SppLogEvent>> querySppEvents(int maxRecords = DEFAULT_EVENT_LIMIT);
    };

} // namespace Core
} // namespace LicenseInspector
